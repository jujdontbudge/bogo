use bogo_log::{Hex, LogEvent};
use bogo_state::Home;

#[tokio::test]
async fn lost_boot_cache_must_not_reuse_an_old_boot_sequence() {
    let root = std::env::temp_dir().join(format!(
        "bogo-review-boot-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    let home = Home::open(&root).unwrap();
    let lock = home.lock().unwrap();
    let (log, _, _, _) = home.open_log(&lock).unwrap();
    let mut last = 0;
    for n in 1..=3 {
        last = home.next_boot(&lock).unwrap();
        log.append(LogEvent::Boot {
            boot_seq: last,
            boot_id: Hex(vec![n; 32]),
        })
        .await
        .unwrap();
    }
    drop(log);
    drop(lock);
    // Simulate loss of the derived state while preserving keys and the log.
    std::fs::remove_file(root.join("state/boot")).unwrap();
    let home = Home::open(&root).unwrap();
    let lock = home.lock().unwrap();
    let (_log, _, _, _) = home.open_log(&lock).unwrap();
    let next = home.next_boot(&lock).unwrap();
    drop(lock);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(
        next > last,
        "boot sequence regressed from {last} to {next}; a phone retaining boot {last} treats new requests as belonging to an older boot"
    );
}
