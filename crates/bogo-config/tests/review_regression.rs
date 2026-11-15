use bogo_config::{Config, Format, Policy, Secrets};

#[test]
fn approval_override_can_use_tool_display_hints() {
    // SPEC §3.4 permits a different policy per agent. Display hints belong to the tool.
    let text = r#"
version = 1
[server]
port = 8790
[defaults]
policy = "deny"
max_pending = 8
[upstreams.stripe]
command = "link-cli"
args = ["--mcp"]
[tools."stripe__create_payment_link"]
policy = "deny"
highlight = { amount = "usd_cents" }
[agents."Trip planner".tools."stripe__create_payment_link"]
policy = "approve"
"#;
    let config = Config::parse(text, &Secrets::default())
        .expect("a denied-by-default tool may require approval for one agent with currency hints");
    assert_eq!(
        config.agents["Trip planner"]["stripe__create_payment_link"].policy,
        Some(Policy::Approve)
    );
    assert_eq!(
        config.tools["stripe__create_payment_link"].hints[0].1,
        Format::MoneyMinor("USD".into())
    );
}
