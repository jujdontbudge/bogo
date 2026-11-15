use crate::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;

/// How often a request already accepted by the relay is re-sent until the
/// approver says `seen`. A resend is the same sealed bytes, so it is harmless.
const RESEND: Duration = Duration::from_secs(60);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Delivering,
    Seen,
    Over,
}

struct HubState {
    approvers: HashMap<ApproverId, ApproverRecord>,
    deliveries: HashMap<(ApproverId, ReqId), watch::Sender<Phase>>,
}

pub struct Hub {
    routes: HashMap<&'static str, Arc<dyn ApproverRoute>>,
    sink: Arc<dyn Sink>,
    state: Mutex<HubState>,
}

fn short(id: &[u8]) -> String {
    hex::encode(&id[..id.len().min(4)])
}

impl Hub {
    pub fn new(routes: Vec<Arc<dyn ApproverRoute>>, sink: Arc<dyn Sink>) -> Arc<Hub> {
        Arc::new(Hub {
            routes: routes.into_iter().map(|r| (r.kind(), r)).collect(),
            sink,
            state: Mutex::new(HubState {
                approvers: HashMap::new(),
                deliveries: HashMap::new(),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn route(&self, a: &ApproverRecord) -> Option<Arc<dyn ApproverRoute>> {
        self.routes.get(a.kind.as_str()).cloned()
    }

    pub fn approvers(&self) -> Vec<ApproverRecord> {
        self.lock().approvers.values().cloned().collect()
    }

    pub fn approver(&self, id: &ApproverId) -> Option<ApproverRecord> {
        self.lock().approvers.get(id).cloned()
    }

    /// On every boot, before any request: apply each route's registry
    /// (allowlist and channel keys), send `boot` and `registered` again to
    /// every active approver, and start taking in approver messages.
    pub async fn start(self: &Arc<Self>, approvers: Vec<ApproverRecord>, boot: BootNotice) {
        self.lock().approvers = approvers.iter().map(|a| (a.id, a.clone())).collect();
        self.apply_registry().await;
        for a in approvers.into_iter().filter(|a| a.active) {
            let hub = self.clone();
            tokio::spawn(async move {
                let Some(route) = hub.route(&a) else { return };
                retry("boot", &a, || route.boot(&a, &boot)).await;
                retry("registered", &a, || route.registered(&a)).await;
            });
        }
        for route in self.routes.values() {
            let (route, handler) = (route.clone(), self.clone() as Arc<dyn InboundHandler>);
            tokio::spawn(async move { route.run_inbound(handler).await });
        }
    }

    /// Give each route its whole registry, retrying until it takes it.
    async fn apply_registry(&self) {
        for route in self.routes.values() {
            let mine: Vec<ApproverRecord> = self
                .approvers()
                .into_iter()
                .filter(|a| a.kind == route.kind())
                .collect();
            let mut backoff = Duration::from_millis(500);
            while let Err(e) = route.set_approvers(&mine).await {
                tracing::warn!("{}: registry not applied yet: {e}", route.kind());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }

    /// Send a `boot` notice to every active approver (the stand-in's command).
    pub fn boot_notice(self: &Arc<Self>, boot: BootNotice) {
        for a in self.approvers().into_iter().filter(|a| a.active) {
            let hub = self.clone();
            tokio::spawn(async move {
                let Some(route) = hub.route(&a) else { return };
                retry("boot", &a, || route.boot(&a, &boot)).await;
            });
        }
    }

    /// Deliver a request to each listed active approver and keep retrying
    /// until it says `seen` or the request ends.
    pub fn ask(self: &Arc<Self>, out: Outbound, to: &[ApproverId]) {
        for id in to {
            let Some(a) = self.approver(id).filter(|a| a.active) else {
                continue;
            };
            let (tx, rx) = watch::channel(Phase::Delivering);
            {
                let mut st = self.lock();
                if st.deliveries.contains_key(&(a.id, out.req)) {
                    continue;
                }
                st.deliveries.insert((a.id, out.req), tx);
            }
            let (hub, out) = (self.clone(), out.clone());
            tokio::spawn(async move { hub.deliver_loop(a, out, rx).await });
        }
    }

    async fn deliver_loop(self: Arc<Self>, a: ApproverRecord, out: Outbound, mut rx: watch::Receiver<Phase>) {
        let Some(route) = self.route(&a) else { return };
        let mut backoff = Duration::from_millis(500);
        loop {
            if *rx.borrow() != Phase::Delivering {
                break;
            }
            let wait = match route.deliver(&a, &out).await {
                Ok(()) => {
                    backoff = Duration::from_millis(500);
                    RESEND
                }
                Err(e) => {
                    tracing::warn!("deliver {} to {}: {e}", short(&out.req), a.name);
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    wait
                }
            };
            tokio::select! {
                _ = rx.changed() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
        if *rx.borrow() == Phase::Over {
            let _ = route.retract(&a, &out.req).await;
        }
    }

    fn mark(&self, approver: &ApproverId, req: &ReqId, phase: Phase) {
        let mut st = self.lock();
        if let Some(tx) = st.deliveries.get(&(*approver, *req)) {
            let current = *tx.borrow();
            if current == Phase::Delivering {
                let _ = tx.send(phase);
            }
            if phase == Phase::Over {
                st.deliveries.remove(&(*approver, *req));
            }
        }
    }

    /// The request settled: stop delivering and tell its approvers.
    pub fn settled(self: &Arc<Self>, req: ReqId, to: &[ApproverId]) {
        self.finish(req, to, Notice::Settled);
    }

    /// The request ended: stop delivering, withdraw what is undelivered, and
    /// tell its approvers.
    pub fn ended(self: &Arc<Self>, req: ReqId, why: EndWhy, to: &[ApproverId]) {
        self.finish(req, to, Notice::Ended(why));
    }

    pub fn outcome(self: &Arc<Self>, req: ReqId, outcome: &str, to: &[ApproverId]) {
        self.finish(req, to, Notice::Outcome(outcome.into()));
    }

    fn finish(self: &Arc<Self>, req: ReqId, to: &[ApproverId], notice: Notice) {
        for id in to {
            self.mark(id, &req, Phase::Over);
            self.send_notice(*id, req, notice.clone());
        }
    }

    fn send_notice(self: &Arc<Self>, id: ApproverId, req: ReqId, notice: Notice) {
        let Some(a) = self.approver(&id) else { return };
        let hub = self.clone();
        tokio::spawn(async move {
            let Some(route) = hub.route(&a) else { return };
            retry("notice", &a, || route.notice(&a, &req, &notice)).await;
        });
    }

    pub fn apply(&self, effects: Vec<Effect>) {
        self.spawn_effects(effects);
    }

    /// The owner revoked an approver on the Mac (its entry is already
    /// durable). It stays known so a later `removed` gets `revokedAck` and its
    /// decisions are recorded as rejected.
    pub async fn revoked(self: &Arc<Self>, id: &ApproverId) {
        self.deactivate(id);
        self.apply_registry().await;
    }

    fn deactivate(&self, id: &ApproverId) {
        let mut st = self.lock();
        if let Some(a) = st.approvers.get_mut(id) {
            a.active = false;
        }
        let stale: Vec<_> = st.deliveries.keys().filter(|(a, _)| a == id).cloned().collect();
        for key in stale {
            if let Some(tx) = st.deliveries.remove(&key) {
                let _ = tx.send(Phase::Over);
            }
        }
    }

    /// The registration driver: the route runs its protocol up to the commit,
    /// the hub refuses keys or transcripts it has seen before, the sink makes
    /// the record durable, the route learns the new registry, and only then is
    /// the approver told it is registered.
    pub async fn register(
        self: &Arc<Self>,
        kind: &str,
        name: &str,
        owner: &dyn OwnerPrompt,
    ) -> Result<ApproverRecord, RegError> {
        let route = self
            .routes
            .get(kind)
            .cloned()
            .ok_or_else(|| RegError::Refused(format!("no approver route named {kind}")))?;
        let pending = route.register(name, owner).await?;
        let new = pending.approver().clone();
        let seen_before = self
            .approvers()
            .iter()
            .any(|a| a.id == new.id || a.tx_id == new.tx_id || a.sig_pk == new.sig_pk);
        if seen_before {
            pending.refuse("this key or transcript is already registered").await;
            return Err(RegError::Refused("this key or transcript is already registered".into()));
        }
        let committed = match self.sink.commit(name, kind, &new).await {
            Ok(c) => c,
            Err(e) => {
                pending.refuse("the Mac could not record the registration").await;
                return Err(RegError::Commit(e.0));
            }
        };
        if let Some(old) = committed.replaced {
            self.deactivate(&old);
        }
        self.lock()
            .approvers
            .insert(committed.record.id, committed.record.clone());
        self.apply_registry().await;
        pending.answer(&committed.record).await?;
        Ok(committed.record)
    }
}

#[async_trait]
impl InboundHandler for Hub {
    async fn handle(&self, msg: Inbound) -> Result<(), Retry> {
        let id = *msg.approver();
        let Some(a) = self.approver(&id) else {
            return Ok(());
        };
        let Some(route) = self.route(&a) else {
            return Ok(());
        };
        let hub = self;
        match msg {
            Inbound::Seen { req, .. } => {
                hub.mark(&id, &req, Phase::Seen);
                Ok(())
            }
            Inbound::Approval { req, alg, proof, .. } => {
                let effects = hub
                    .sink
                    .decision(Decision::Approval { approver: id, req, alg, proof })
                    .await
                    .map_err(|_| Retry)?;
                hub.spawn_effects(effects);
                Ok(())
            }
            Inbound::Denial { req, note, .. } => {
                let effects = hub
                    .sink
                    .decision(Decision::Denial { approver: id, req, note })
                    .await
                    .map_err(|_| Retry)?;
                hub.spawn_effects(effects);
                Ok(())
            }
            Inbound::Pause { agent, epoch, .. } => {
                let effects = hub
                    .sink
                    .decision(Decision::Pause { approver: id, agent, epoch })
                    .await
                    .map_err(|_| Retry)?;
                hub.spawn_effects(effects);
                Ok(())
            }
            Inbound::Removed { .. } => {
                let effects = hub.sink.removed(id).await.map_err(|_| Retry)?;
                hub.deactivate(&id);
                hub.spawn_effects(effects);
                let a = hub.approver(&id).unwrap_or(a);
                tokio::spawn(async move {
                    retry("revokedAck", &a, || route.revoked_ack(&a)).await;
                });
                Ok(())
            }
            Inbound::Sync { reqs, .. } => {
                for req in reqs {
                    let outcome = hub.sink.outcome(&req).await;
                    let (a, route) = (a.clone(), route.clone());
                    tokio::spawn(async move {
                        let notice = Notice::Outcome(outcome);
                        retry("outcome", &a, || route.notice(&a, &req, &notice)).await;
                    });
                }
                Ok(())
            }
            Inbound::RegResend { tx_id, .. } => {
                if a.active && a.tx_id == tx_id {
                    tokio::spawn(async move {
                        retry("registered", &a, || route.registered(&a)).await;
                    });
                }
                Ok(())
            }
            Inbound::RouteUpdate { seq, route: data, .. } => {
                let changed = hub
                    .sink
                    .route_update(id, seq, data.clone())
                    .await
                    .map_err(|_| Retry)?;
                if changed {
                    if let Some(rec) = hub.lock().approvers.get_mut(&id) {
                        rec.route = data;
                    }
                    hub.apply_registry().await;
                }
                Ok(())
            }
        }
    }
}

impl Hub {
    fn spawn_effects(&self, effects: Vec<Effect>) {
        for e in effects {
            let (req, to, notice) = match e {
                Effect::Settled { req, to } => (req, to, Notice::Settled),
                Effect::Ended { req, why, to } => (req, to, Notice::Ended(why)),
                Effect::Outcome { req, outcome, to } => (req, to, Notice::Outcome(outcome)),
            };
            for id in to {
                self.mark(&id, &req, Phase::Over);
                let Some(a) = self.approver(&id) else { continue };
                let Some(route) = self.route(&a) else { continue };
                let notice = notice.clone();
                tokio::spawn(async move {
                    retry("notice", &a, || route.notice(&a, &req, &notice)).await;
                });
            }
        }
    }
}

/// Retry with backoff until the route accepts, for up to a day.
async fn retry<'a, F, Fut>(what: &str, a: &'a ApproverRecord, mut f: F)
where
    F: FnMut() -> Fut + 'a,
    Fut: std::future::Future<Output = Result<(), DeliveryError>> + 'a,
{
    let mut backoff = Duration::from_millis(500);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(86_400);
    loop {
        match f().await {
            Ok(()) => return,
            Err(e) => {
                tracing::warn!("{what} to {}: {e}", a.name);
                if tokio::time::Instant::now() > deadline {
                    return;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}
