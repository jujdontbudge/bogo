use crate::{Error, Gate, Outcome, Scrubber, secrets::expose, wire};
use bogo_config::Upstream;
use futures::{StreamExt, stream::BoxStream};
use http::{HeaderName, HeaderValue};
use rmcp::{
    model::ClientJsonRpcMessage,
    transport::streamable_http_client::{
        SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
    },
};
use sse_stream::{Sse, SseStream};
use std::{collections::HashMap, sync::Arc, time::Duration};

type HttpError = StreamableHttpError<Error>;
#[derive(Clone)]
pub struct ExactHttpClient {
    client: reqwest::Client,
    gate: Arc<dyn Gate>,
    upstream: String,
    scrubber: Scrubber,
}
impl ExactHttpClient {
    pub fn new(
        upstream: String,
        config: &Upstream,
        gate: Arc<dyn Gate>,
        scrubber: Scrubber,
    ) -> Result<Self, Error> {
        let Upstream::Remote { headers, .. } = config else {
            return Err(Error::Configuration);
        };
        let mut defaults = http::HeaderMap::new();
        for (k, v) in headers {
            let key = HeaderName::from_bytes(k.as_bytes()).map_err(|_| Error::Configuration)?;
            let mut value = HeaderValue::from_str(&expose(v)).map_err(|_| Error::Configuration)?;
            value.set_sensitive(true);
            defaults.insert(key, value);
        }
        let client = reqwest::Client::builder()
            .default_headers(defaults)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            gate,
            upstream,
            scrubber,
        })
    }
    fn request(
        &self,
        method: reqwest::Method,
        uri: &str,
        session: Option<&str>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> reqwest::RequestBuilder {
        let mut r = self
            .client
            .request(method, uri)
            .header("accept", "application/json, text/event-stream");
        for (k, v) in headers {
            r = r.header(k, v);
        }
        if let Some(session) = session {
            r = r.header("mcp-session-id", session);
        }
        if let Some(auth) = auth {
            r = r.bearer_auth(auth);
        }
        r
    }
    fn stream(
        &self,
        response: reqwest::Response,
        max: usize,
    ) -> BoxStream<'static, Result<Sse, SseError>> {
        let scrubber = self.scrubber.clone();
        SseStream::from_bytes_stream(response.bytes_stream().scan(
            (0usize, 0u32),
            move |state, chunk| {
                let result = chunk
                    .map_err(|_| std::io::Error::other("upstream stream error"))
                    .and_then(|bytes| {
                        for b in &bytes {
                            state.0 += 1;
                            state.1 = (state.1 << 8) | u32::from(*b);
                            if state.0 > max {
                                return Err(std::io::Error::other("upstream SSE event too large"));
                            }
                            if state.1 & 0xffff == 0x0a0a || state.1 == 0x0d0a0d0a {
                                state.0 = 0;
                            }
                        }
                        Ok(bytes)
                    });
                std::future::ready(Some(result))
            },
        ))
        .map(move |event| {
            event
                .map(|mut e| {
                    e.id = e.id.map(|id| scrubber.text(&id));
                    e.event = e.event.map(|event| scrubber.text(&event));
                    if let Some(data) = &mut e.data {
                        // Decode escapes before scrubbing; never expose a raw event to rmcp logs.
                        *data = match serde_json::from_str::<serde_json::Value>(data) {
                            Ok(mut value) => {
                                scrubber.json(&mut value);
                                value.to_string()
                            }
                            Err(_) => String::new(),
                        };
                    }
                    e
                })
                .map_err(|_| SseError::Body(Box::new(std::io::Error::other("upstream SSE error"))))
        })
        .boxed()
    }
}
impl StreamableHttpClient for ExactHttpClient {
    type Error = Error;
    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session: Option<Arc<str>>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, HttpError> {
        self.post_message_with_max_sse_event_size(
            uri,
            message,
            session,
            auth,
            headers,
            16 * 1024 * 1024,
        )
        .await
    }
    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session: Option<Arc<str>>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
        max: usize,
    ) -> Result<StreamableHttpPostResponse, HttpError> {
        let call = wire::marker(&message).map_err(HttpError::Client)?;
        // Credentials, session headers, and request construction precede dispatch.
        let mut request = self
            .request(
                reqwest::Method::POST,
                &uri,
                session.as_deref(),
                auth,
                headers,
            )
            .header("content-type", "application/json")
            .build()
            .map_err(|_| HttpError::Client(Error::Configuration))?;
        let bytes = if let Some(id) = &call {
            let forward = self
                .gate
                .dispatch(id.clone())
                .await
                .map_err(HttpError::Client)?;
            wire::forward(&message, forward, &self.upstream).map_err(HttpError::Client)?
        } else {
            serde_json::to_vec(&message).map_err(|_| HttpError::Client(Error::Protocol))?
        };
        *request.body_mut() = Some(bytes.into());
        // Single attempt; no re-init, redirect, auth refresh, or retry after this point.
        let response = self.client.execute(request).await.map_err(|e| {
            let outcome = if e.is_connect() {
                Outcome::NotSent
            } else {
                Outcome::Unknown
            };
            if let Some(id) = &call {
                self.gate.outcome(id, outcome);
            }
            HttpError::Client(if outcome == Outcome::NotSent {
                Error::NotSent
            } else {
                Error::Unknown
            })
        })?;
        if response.status().as_u16() == 404 {
            return Err(HttpError::SessionExpired);
        }
        if response.status().as_u16() == 202 {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if !response.status().is_success() {
            return Err(HttpError::Client(Error::Protocol));
        }
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        if session
            .as_ref()
            .is_some_and(|id| self.scrubber.text(id) != *id)
        {
            return Err(HttpError::Client(Error::Protocol));
        }
        if response
            .headers()
            .get("content-type")
            .is_some_and(|h| h.as_bytes().starts_with(b"text/event-stream"))
        {
            return Ok(StreamableHttpPostResponse::Sse(
                self.stream(response, max),
                session,
            ));
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| HttpError::Client(Error::Unknown))?;
            if bytes.len() + chunk.len() > 16 * 1024 * 1024 {
                return Err(HttpError::Client(Error::Protocol));
            }
            bytes.extend_from_slice(&chunk);
        }
        let message = self.scrubber.message(&bytes).map_err(HttpError::Client)?;
        Ok(StreamableHttpPostResponse::Json(message, session))
    }
    async fn delete_session(
        &self,
        uri: Arc<str>,
        session: Arc<str>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), HttpError> {
        self.request(reqwest::Method::DELETE, &uri, Some(&session), auth, headers)
            .send()
            .await
            .map_err(|_| HttpError::Client(Error::Protocol))?;
        Ok(())
    }
    async fn get_stream(
        &self,
        uri: Arc<str>,
        session: Option<Arc<str>>,
        last: Option<String>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, HttpError> {
        self.get_stream_with_max_sse_event_size(uri, session, last, auth, headers, 16 * 1024 * 1024)
            .await
    }
    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session: Option<Arc<str>>,
        last: Option<String>,
        auth: Option<String>,
        headers: HashMap<HeaderName, HeaderValue>,
        max: usize,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, HttpError> {
        let mut request = self.request(
            reqwest::Method::GET,
            &uri,
            session.as_deref(),
            auth,
            headers,
        );
        if let Some(last) = last {
            request = request.header("last-event-id", last);
        }
        let response = request
            .send()
            .await
            .map_err(|_| HttpError::Client(Error::Protocol))?;
        if response.status().as_u16() == 405 {
            return Err(HttpError::ServerDoesNotSupportSse);
        }
        if !response.status().is_success() {
            return Err(HttpError::Client(Error::Protocol));
        }
        Ok(self.stream(response, max))
    }
}
