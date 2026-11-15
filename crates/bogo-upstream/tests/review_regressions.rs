use bogo_filter::{Rules, filter};
use rmcp::model::CallToolResult;
use serde_json::json;

#[test]
fn s1_filtering_resource_uri_preserves_a_deliverable_mcp_result() {
    // The documented daemon integration serializes, filters, then converts back.
    let upstream: CallToolResult = serde_json::from_value(json!({
        "content": [{
            "type": "resource_link",
            "name": "Shared file",
            "uri": "https://files.example/share/private-token"
        }]
    }))
    .unwrap();
    let rules = Rules {
        paths: vec!["uri".into()],
        ..Rules::default()
    };
    let (filtered, report) = filter(&rules, serde_json::to_value(upstream).unwrap());
    assert_eq!(report.fields, 1);
    assert!(!filtered.to_string().contains("private-token"));
    let delivered = serde_json::from_value::<CallToolResult>(filtered);
    assert!(
        delivered.is_ok(),
        "filtered result cannot be returned through MCP: {delivered:?}"
    );
}
