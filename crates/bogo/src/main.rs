use bogo_daemon::{Command, init, launch, request, serve};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(version, about = "BOGO owner commands")]
struct Args {
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Cli,
}
#[derive(Subcommand)]
enum Cli {
    Init,
    Start,
    Stop,
    Serve,
    Status,
    Tools,
    Agent {
        #[command(subcommand)]
        action: Agent,
    },
    Approver {
        #[command(subcommand)]
        action: Approver,
    },
    Request {
        #[command(subcommand)]
        action: Request,
    },
    Log {
        #[command(subcommand)]
        action: Option<Log>,
    },
    Export {
        #[arg(long, default_value = "jsonl")]
        format: String,
    },
    Upstream {
        #[command(subcommand)]
        action: Upstream,
    },
    #[cfg(feature = "test-approvers")]
    Soft {
        name: String,
        id: String,
        #[arg(long)]
        deny: bool,
        #[arg(long)]
        note: Option<String>,
    },
}
#[derive(Subcommand)]
enum Agent {
    Add { name: String },
    List,
    Revoke { name: String },
    Pause { name: String },
    Unpause { name: String },
}
#[derive(Subcommand)]
enum Approver {
    Add {
        name: String,
        #[arg(long, default_value = "iphone")]
        kind: String,
    },
    List,
    Revoke {
        name: String,
    },
}
#[derive(Subcommand)]
enum Request {
    List,
    Cancel { id: String },
}
#[derive(Subcommand)]
enum Log {
    Search {
        text: String,
    },
    Verify,
    Export {
        #[arg(long, default_value = "jsonl")]
        format: String,
    },
}
#[derive(Subcommand)]
enum Upstream {
    Add {
        name: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
}
#[tokio::main]
async fn main() {
    if let Err(e) = run(Args::parse()).await {
        eprintln!("bogo: {e}");
        std::process::exit(1)
    }
}
async fn run(args: Args) -> Result<(), String> {
    let root = args
        .home
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".bogo")))
        .ok_or("HOME is not set; use --home")?;
    let command = match args.command {
        Cli::Init => return init(&root),
        Cli::Start => return launch(&root, true),
        Cli::Stop => return launch(&root, false),
        Cli::Serve => return serve(&root).await,
        Cli::Status => Command::Status,
        Cli::Tools => Command::Tools,
        Cli::Agent { action } => match action {
            Agent::Add { name } => Command::AgentAdd { name },
            Agent::List => Command::AgentList,
            Agent::Revoke { name } => Command::AgentRevoke { name },
            Agent::Pause { name } => Command::Pause { name },
            Agent::Unpause { name } => Command::Unpause { name },
        },
        Cli::Approver { action } => match action {
            Approver::Add { name, kind } => Command::ApproverAdd { name, kind },
            Approver::List => Command::ApproverList,
            Approver::Revoke { name } => Command::ApproverRevoke { name },
        },
        Cli::Request { action } => match action {
            Request::List => Command::Requests,
            Request::Cancel { id } => Command::Cancel { id },
        },
        Cli::Log { action } => match action {
            None => Command::Log { search: None },
            Some(Log::Search { text }) => Command::Log { search: Some(text) },
            Some(Log::Verify) => Command::Verify,
            Some(Log::Export { format }) => Command::Export { format },
        },
        Cli::Export { format } => Command::Export { format },
        Cli::Upstream {
            action: Upstream::Add { name, url, command },
        } => return bogo_daemon::add_upstream(&root, &name, url, command),
        #[cfg(feature = "test-approvers")]
        Cli::Soft {
            name,
            id,
            deny,
            note,
        } => Command::Soft {
            name,
            id,
            deny,
            note,
        },
    };
    let v = request(&root, command).await?;
    if let Some(s) = v.as_str() {
        println!("{s}")
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        )
    }
    Ok(())
}
