//! Run only when deliberately checking APNs credentials; sends one made-up token.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME")?;
    let mut client = bogo_apns::Client::from_file(
        std::path::Path::new(&format!(
            "{home}/.config/apple-bridge/apns/AuthKey_L2854KRF5Z.p8"
        )),
        "L2854KRF5Z",
        "AX3C2B78YD",
        "com.johansardar.applebridge.ios",
    )?;
    let response = client
        .wake(
            bogo_apns::Environment::Sandbox,
            &"0".repeat(64),
            "01234567",
            &"0".repeat(80),
        )
        .await?;
    println!(
        "HTTP/2 APNs status={} reason={} apns-id={}",
        response.status,
        response.reason.as_deref().unwrap_or("accepted"),
        response.apns_id.as_deref().unwrap_or("none")
    );
    if response.status != 400 || response.reason.as_deref() != Some("BadDeviceToken") {
        return Err("sandbox authentication proof not obtained".into());
    }
    Ok(())
}
