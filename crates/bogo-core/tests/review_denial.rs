use bogo_core::*;
use bogo_verify as _;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

#[test]
fn denied_approver_cannot_supply_the_second_approval() {
    let core = Core::start(b"review", &[9; 32]).unwrap();
    let step = |input| core.step(&input).unwrap().outputs;
    let mut policy = ToolPolicy::new(PolicyKind::Approve);
    policy.requirement = Requirement::KOfN(2);
    policy.deny_rule = DenyRule::WhenUnreachable;
    step(Input::Configure {
        seq: 1,
        cfg: PolicyConfig {
            default_policy: DefaultPolicy::Approve,
            max_pending: 10,
            tools: vec![("vault__open".into(), policy)],
            overrides: vec![],
        },
        catalog: vec![CatalogEntry {
            name: "vault__open".into(),
            upstream: "vault".into(),
            tool: "open".into(),
            just_key: "justification".into(),
        }],
    });
    let keys: Vec<_> = (1u8..=3)
        .map(|seed| SigningKey::from_bytes(&[seed; 32].into()).unwrap())
        .collect();
    for (i, key) in keys.iter().enumerate() {
        step(Input::ApproverSet {
            seq: 2 + i as u64,
            approver: Approver {
                id: vec![i as u8],
                name: format!("phone-{i}"),
                alg: 1,
                pk: key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            },
        });
    }
    step(Input::AgentSet {
        seq: 5,
        id: vec![7],
        name: "agent".into(),
    });
    step(Input::SessionOpened {
        session: vec![8],
        agent: vec![7],
        client: None,
    });
    let outputs = step(Input::Call {
        call: vec![9],
        session: vec![8],
        name: "vault__open".into(),
        args: None,
        now_ms: 100,
    });
    let (req, bytes) = outputs
        .into_iter()
        .find_map(|o| match o {
            Output::Ask { req, bytes, .. } => Some((req, bytes)),
            _ => None,
        })
        .unwrap();
    // Phone 0's earlier signed approval is delayed in the network.
    let mut message = b"BOGO-APPROVAL\x00v1".to_vec();
    message.extend_from_slice(&bytes);
    let delayed: Signature = keys[0].sign(&message);
    // Its denial arrives first. Phones 1 and 2 can still meet 2-of-3.
    let denied = step(Input::Denial {
        approver: vec![0],
        req: req.clone(),
        note: None,
    });
    assert!(!denied.iter().any(|o| matches!(o, Output::Ended { .. })));
    let late = step(Input::Approval {
        approver: vec![0],
        req: req.clone(),
        alg: 1,
        proof: delayed.to_bytes().to_vec(),
        now_ms: 101,
    });
    println!("delayed approval after denial: {late:?}");
    let sig: Signature = keys[1].sign(&message);
    step(Input::Approval {
        approver: vec![1],
        req,
        alg: 1,
        proof: sig.to_bytes().to_vec(),
        now_ms: 102,
    });
    let dispatch = step(Input::Dispatch {
        call: vec![9],
        now_ms: 103,
    });
    println!("dispatch: {dispatch:?}");
    assert!(
        !dispatch.iter().any(|o| matches!(o, Output::Forward { .. })),
        "2-of-3 must not forward with only one approval from a non-denying approver"
    );
}
