use bogo_config::{Config, PathElem, Secrets};

#[test]
fn recommended_link_setup_highlights_selected_action_first() {
    let config = Config::parse(
        r#"
version = 1
[server]
port = 8790
[defaults]
policy = "approve"
max_pending = 8
[upstreams.stripe]
command = "link-cli"
args = ["--mcp"]
[tools.stripe__call_write_tool]
policy = "approve"
select = "name"
highlight = { name = "text", "arguments.amount" = "usd_cents" }
[tools."stripe__call_write_tool[name=spend-request_create]"]
policy = "approve"
"#,
        &Secrets::default(),
    )
    .unwrap();

    for tool in [
        "stripe__call_write_tool",
        "stripe__call_write_tool[name=spend-request_create]",
    ] {
        assert_eq!(
            config.tools[tool].hints[0].0,
            vec![PathElem::Key("name".into())],
            "the selected action must be highlighted first for {tool}"
        );
    }
}
