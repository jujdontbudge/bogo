//! Standalone daemon entry; launchd normally runs `bogo serve`.
#[tokio::main]
async fn main() {
    let mut args = std::env::args_os().skip(1);
    let root = match args.next() {
        Some(flag) if flag == "--home" => args.next().map(std::path::PathBuf::from),
        None => std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".bogo")),
        _ => None,
    };
    let Some(root) = root.filter(|_| args.next().is_none()) else {
        eprintln!("usage: bogo-daemon [--home BOGO_DIRECTORY]");
        std::process::exit(2)
    };
    if let Err(e) = bogo_daemon::serve(&root).await {
        eprintln!("bogo-daemon: {e}");
        std::process::exit(1)
    }
}
