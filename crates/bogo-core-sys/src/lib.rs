//! The raw link to the compiled Lean decision core, and the one safe handle over it.
//!
//! This is the only BOGO crate with `unsafe` FFI (ARCHITECTURE §7). The C shim (`shim.c`) holds
//! the Lean `State`; this crate makes sure only one [`LeanCore`] ever exists in a process and
//! that it never leaves the thread that made it, so the shim's globals are never touched
//! concurrently and the rules around `lean_initialize_thread` never apply.
//!
//! The shim calls `bogo_rs_verify`, which `bogo-verify` defines. Any binary that links this
//! crate must link `bogo-verify` too.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};

mod raw {
    unsafe extern "C" {
        pub fn bogo_core_abi() -> u32;
        pub fn bogo_core_start(bogo_id: *const u8, n1: usize, boot_id: *const u8, n2: usize)
        -> i32;
        pub fn bogo_core_step(
            input: *const u8,
            n: usize,
            out: *mut *mut u8,
            out_n: *mut usize,
        ) -> i32;
        pub fn bogo_core_decode_request(
            input: *const u8,
            n: usize,
            out: *mut *mut u8,
            out_n: *mut usize,
        ) -> i32;
        pub fn bogo_core_check_approval(
            alg: u16,
            pk: *const u8,
            pk_n: usize,
            req: *const u8,
            req_n: usize,
            proof: *const u8,
            proof_n: usize,
        ) -> i32;
        pub fn bogo_core_free(p: *mut u8);
    }
}

/// Something went wrong below the Lean code: the runtime failed to start, or the shim could
/// not allocate. The core itself never fails; it answers every input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiError(pub &'static str);

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for FfiError {}

static TAKEN: AtomicBool = AtomicBool::new(false);

/// The process's one handle on the Lean core. Not `Send` or `Sync`: it stays on the thread
/// that created it.
pub struct LeanCore {
    _one_thread: PhantomData<*const ()>,
}

/// Takes a shim-owned buffer and gives back a Rust vector.
fn take(code: i32, out: *mut u8, out_n: usize) -> Result<Vec<u8>, FfiError> {
    if code != 0 || out.is_null() {
        return Err(FfiError("the core shim failed"));
    }
    // SAFETY: on success the shim returned a malloc'd buffer of exactly `out_n` bytes that
    // we now own; it is copied, then released through `bogo_core_free`.
    let v = unsafe { std::slice::from_raw_parts(out, out_n).to_vec() };
    // SAFETY: `out` came from the shim and is freed exactly once.
    unsafe { raw::bogo_core_free(out) };
    Ok(v)
}

impl LeanCore {
    /// Starts the Lean runtime (once per process) and makes this process's only handle.
    /// `None` if a handle was already made in this process.
    pub fn take() -> Option<LeanCore> {
        if TAKEN.swap(true, Ordering::SeqCst) {
            return None;
        }
        Some(LeanCore {
            _one_thread: PhantomData,
        })
    }

    /// The ABI version of the linked Lean library.
    pub fn abi(&self) -> u32 {
        // SAFETY: no arguments; only this thread calls into the shim.
        unsafe { raw::bogo_core_abi() }
    }

    /// Starts (or restarts) the core state for this BOGO and boot.
    pub fn start(&mut self, bogo_id: &[u8], boot_id: &[u8]) -> Result<(), FfiError> {
        // SAFETY: both slices are valid for the call; the shim copies them.
        let code = unsafe {
            raw::bogo_core_start(
                bogo_id.as_ptr(),
                bogo_id.len(),
                boot_id.as_ptr(),
                boot_id.len(),
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(FfiError("the Lean runtime failed to initialize"))
        }
    }

    /// One step: encoded input in, encoded outputs out.
    pub fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, FfiError> {
        let mut out = std::ptr::null_mut();
        let mut out_n = 0usize;
        // SAFETY: `input` is valid for the call; `out` and `out_n` are valid out-pointers.
        let code =
            unsafe { raw::bogo_core_step(input.as_ptr(), input.len(), &mut out, &mut out_n) };
        if code == -1 && out.is_null() {
            return Err(FfiError("the core was not started"));
        }
        take(code, out, out_n)
    }

    /// `Some(bytes)` if `req` is exactly a canonical request (the bytes come back unchanged).
    pub fn decode_request(&mut self, req: &[u8]) -> Result<Option<Vec<u8>>, FfiError> {
        let mut out = std::ptr::null_mut();
        let mut out_n = 0usize;
        // SAFETY: as in `step`.
        let code =
            unsafe { raw::bogo_core_decode_request(req.as_ptr(), req.len(), &mut out, &mut out_n) };
        match code {
            1 => Ok(None),
            _ => take(code, out, out_n).map(Some),
        }
    }

    /// Whether `proof` is a valid approval of the canonical request bytes `req` under `pk`.
    pub fn check_approval(
        &mut self,
        alg: u16,
        pk: &[u8],
        req: &[u8],
        proof: &[u8],
    ) -> Result<bool, FfiError> {
        // SAFETY: every slice is valid for the call; the shim copies them.
        let code = unsafe {
            raw::bogo_core_check_approval(
                alg,
                pk.as_ptr(),
                pk.len(),
                req.as_ptr(),
                req.len(),
                proof.as_ptr(),
                proof.len(),
            )
        };
        match code {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(FfiError("the Lean runtime failed to initialize")),
        }
    }
}
