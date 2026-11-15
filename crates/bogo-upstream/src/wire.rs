use crate::{CALL_MARKER, CallId, Error, Forward};
use rmcp::model::{ClientJsonRpcMessage, ClientNotification, ClientRequest, GetMeta};

pub(crate) fn marker(message: &ClientJsonRpcMessage) -> Result<Option<CallId>, Error> {
    let disguised = match message {
        ClientJsonRpcMessage::Request(r) => {
            r.request.method() == "tools/call"
                && !matches!(&r.request, ClientRequest::CallToolRequest(_))
        }
        ClientJsonRpcMessage::Notification(n) => {
            matches!(&n.notification, ClientNotification::CustomNotification(c) if c.method == "tools/call")
        }
        _ => false,
    };
    if disguised {
        tracing::error!("internal_send_refused");
        return Err(Error::InternalSendRefused);
    }
    if let ClientJsonRpcMessage::Request(r) = message
        && let ClientRequest::CallToolRequest(call) = &r.request
    {
        return r
            .request
            .get_meta()
            .0
            .get(CALL_MARKER)
            .or_else(|| call.params.meta.as_ref().and_then(|m| m.0.get(CALL_MARKER)))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| Some(CallId(s.into())))
            .ok_or_else(|| {
                tracing::error!("internal_send_refused");
                Error::InternalSendRefused
            });
    }
    Ok(None)
}
/// Reconstruct the call exclusively from the core's destination and exact writer.
/// No SDK arguments or untrusted metadata can contribute to the outbound call.
pub(crate) fn forward(
    message: &ClientJsonRpcMessage,
    f: Forward,
    upstream: &str,
) -> Result<Vec<u8>, Error> {
    if f.upstream != upstream {
        return Err(Error::Rejected);
    }
    let ClientJsonRpcMessage::Request(r) = message else {
        return Err(Error::InternalSendRefused);
    };
    let ClientRequest::CallToolRequest(call) = &r.request else {
        return Err(Error::InternalSendRefused);
    };
    if call.params.name.as_ref() != f.tool {
        return Err(Error::Rejected);
    }
    let id = serde_json::to_string(&r.id).map_err(|_| Error::Protocol)?;
    let tool = serde_json::to_string(&f.tool).map_err(|_| Error::Protocol)?;
    Ok(format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":{tool},\"arguments\":{}}}}}", f.arguments.write()).into_bytes())
}
