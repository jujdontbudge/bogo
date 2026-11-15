//! The safe handle on BOGO's Lean decision core (ARCHITECTURE §3.4).
//!
//! One dedicated thread initializes the Lean runtime and holds the core's `State`; every
//! decision is serialized through it. [`Core::step`] sends one `Input` and gets back the
//! core's `Output`s and its next deadline. At startup the thread compares the linked library's
//! ABI with [`ABI`] and refuses to run if they differ.
//!
//! Nothing here decides anything. Rust encodes the input, Lean decodes it (rejecting anything
//! malformed), decides, and encodes the outputs.
//!
//! The Lean core calls `bogo_rs_verify` through its verify hook; a binary using this crate must
//! link `bogo-verify` as well.

#![forbid(unsafe_code)]

mod types;
pub mod wire;

pub use types::*;
pub use wire::{DecodeError, decode_outputs, encode_input};

use bogo_core_sys::LeanCore;
use std::sync::mpsc;
use std::thread;

/// The Rust↔Lean wire and C ABI version this crate speaks. Must equal `Bogo.Ffi.abi`.
pub const ABI: u32 = 1;

/// Why the core could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// The linked Lean library speaks another ABI. BOGO refuses to run.
    AbiMismatch { library: u32, expected: u32 },
    /// The core was already started in this process.
    AlreadyStarted,
    /// The Lean runtime failed to initialize.
    Runtime(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::AbiMismatch { library, expected } => write!(
                f,
                "the linked Lean core has ABI {library}, but this build expects {expected}; \
                 refusing to start"
            ),
            StartError::AlreadyStarted => {
                f.write_str("the core is already running in this process")
            }
            StartError::Runtime(m) => write!(f, "the Lean runtime failed: {m}"),
        }
    }
}

impl std::error::Error for StartError {}

/// The ABI check at startup.
pub fn check_abi(library: u32, expected: u32) -> Result<(), StartError> {
    if library == expected {
        Ok(())
    } else {
        Err(StartError::AbiMismatch { library, expected })
    }
}

/// The core thread stopped, or answered with bytes this build can't read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    Stopped,
    Ffi(String),
    Decode(DecodeError),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Stopped => f.write_str("the core thread has stopped"),
            CoreError::Ffi(m) => write!(f, "core FFI error: {m}"),
            CoreError::Decode(e) => write!(f, "unreadable core output: {}", e.0),
        }
    }
}

impl std::error::Error for CoreError {}

/// The result of one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub outputs: Vec<Output>,
    /// When the shell should next send `tick`.
    pub deadline_ms: Option<u64>,
}

enum Job {
    Step(Vec<u8>, mpsc::Sender<Result<Vec<u8>, CoreError>>),
    Restart(Vec<u8>, Vec<u8>, mpsc::Sender<Result<(), CoreError>>),
    DecodeRequest(Vec<u8>, mpsc::Sender<Result<Option<Vec<u8>>, CoreError>>),
    CheckApproval(
        u16,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        mpsc::Sender<Result<bool, CoreError>>,
    ),
}

/// A handle on the core thread. Cloning shares the same thread and state.
#[derive(Clone)]
pub struct Core {
    jobs: mpsc::Sender<Job>,
}

impl Core {
    /// Starts the core thread for this BOGO and boot, after the ABI check.
    pub fn start(bogo_id: &[u8], boot_id: &[u8]) -> Result<Core, StartError> {
        Core::start_expecting(bogo_id, boot_id, ABI)
    }

    /// As [`Core::start`], against an explicit expected ABI (how the check is exercised).
    pub fn start_expecting(
        bogo_id: &[u8],
        boot_id: &[u8],
        expected_abi: u32,
    ) -> Result<Core, StartError> {
        let (jobs, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), StartError>>();
        let (bogo_id, boot_id) = (bogo_id.to_vec(), boot_id.to_vec());
        thread::Builder::new()
            .name("bogo-core".into())
            .spawn(move || {
                let Some(mut lean) = LeanCore::take() else {
                    let _ = ready_tx.send(Err(StartError::AlreadyStarted));
                    return;
                };
                if let Err(e) = check_abi(lean.abi(), expected_abi) {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
                if let Err(e) = lean.start(&bogo_id, &boot_id) {
                    let _ = ready_tx.send(Err(StartError::Runtime(e.to_string())));
                    return;
                }
                let _ = ready_tx.send(Ok(()));
                serve(lean, rx);
            })
            .map_err(|e| StartError::Runtime(e.to_string()))?;
        ready_rx
            .recv()
            .map_err(|_| StartError::Runtime("core thread exited".into()))??;
        Ok(Core { jobs })
    }

    fn ask<T>(
        &self,
        job: impl FnOnce(mpsc::Sender<Result<T, CoreError>>) -> Job,
    ) -> Result<T, CoreError> {
        let (tx, rx) = mpsc::channel();
        self.jobs.send(job(tx)).map_err(|_| CoreError::Stopped)?;
        rx.recv().map_err(|_| CoreError::Stopped)?
    }

    /// One decision step.
    pub fn step(&self, input: &Input) -> Result<Step, CoreError> {
        self.step_bytes(&encode_input(input))
    }

    /// One step on raw input bytes, passed to Lean untouched. Lean decodes them itself, so
    /// anything malformed is rejected by the proved code, not here.
    pub fn step_bytes(&self, input: &[u8]) -> Result<Step, CoreError> {
        let out = self.ask(|tx| Job::Step(input.to_vec(), tx))?;
        let (outputs, deadline_ms) = decode_outputs(&out).map_err(CoreError::Decode)?;
        Ok(Step {
            outputs,
            deadline_ms,
        })
    }

    /// Replaces the state with a fresh one, as at a new boot.
    pub fn restart(&self, bogo_id: &[u8], boot_id: &[u8]) -> Result<(), CoreError> {
        self.ask(|tx| Job::Restart(bogo_id.to_vec(), boot_id.to_vec(), tx))
    }

    /// `Some(bytes)` if `req` is exactly a canonical request, decided by the Lean decoder.
    pub fn decode_request(&self, req: &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
        self.ask(|tx| Job::DecodeRequest(req.to_vec(), tx))
    }

    /// Whether `proof` is a valid approval of canonical request bytes `req` under `pk`.
    pub fn check_approval(
        &self,
        alg: u16,
        pk: &[u8],
        req: &[u8],
        proof: &[u8],
    ) -> Result<bool, CoreError> {
        self.ask(|tx| Job::CheckApproval(alg, pk.to_vec(), req.to_vec(), proof.to_vec(), tx))
    }
}

fn serve(mut lean: LeanCore, rx: mpsc::Receiver<Job>) {
    let ffi = |e: bogo_core_sys::FfiError| CoreError::Ffi(e.to_string());
    for job in rx {
        match job {
            Job::Step(b, tx) => {
                let _ = tx.send(lean.step(&b).map_err(ffi));
            }
            Job::Restart(a, b, tx) => {
                let _ = tx.send(lean.start(&a, &b).map_err(ffi));
            }
            Job::DecodeRequest(b, tx) => {
                let _ = tx.send(lean.decode_request(&b).map_err(ffi));
            }
            Job::CheckApproval(alg, pk, req, proof, tx) => {
                let _ = tx.send(lean.check_approval(alg, &pk, &req, &proof).map_err(ffi));
            }
        }
    }
}
