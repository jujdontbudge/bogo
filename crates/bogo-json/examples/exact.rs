//! Read a JSON text on stdin; print the exact written text, or why it was refused.
//!
//! `printf '{"amount":4.7E3}' | cargo run -q -p bogo-json --example exact`

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("reading stdin: {e}");
        return ExitCode::from(2);
    }
    match bogo_json::parse(&input) {
        Ok(v) => {
            let written = v.write();
            let mut out = std::io::stdout();
            let _ = out.write_all(written.as_bytes());
            let _ = out.write_all(b"\n");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("refused: {} ({e})", e.kind.as_str());
            ExitCode::FAILURE
        }
    }
}
