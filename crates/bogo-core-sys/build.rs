//! Builds `BogoCore:static` with the toolchain pinned in `lean/lean-toolchain`, compiles the C
//! shim against that toolchain's `lean.h`, and links both with the Lean runtime
//! (ARCHITECTURE §3.4).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// elan's `lake`/`lean` wrappers pick the toolchain from `lean-toolchain`. Prefer them over
/// whatever else is called `lean` on PATH.
fn tool(name: &str) -> PathBuf {
    if let Ok(p) = env::var(format!("BOGO_{}", name.to_uppercase())) {
        return PathBuf::from(p);
    }
    let elan = env::var_os("ELAN_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| Path::new(&h).join(".elan")));
    if let Some(bin) = elan.map(|e| e.join("bin").join(name))
        && bin.exists()
    {
        return bin;
    }
    PathBuf::from(name)
}

fn run(cmd: &mut Command) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("could not run {cmd:?}: {e}"));
    if !out.status.success() {
        panic!(
            "{cmd:?} failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8(out.stdout).expect("tool output is UTF-8")
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lean_dir = manifest
        .join("../../lean")
        .canonicalize()
        .expect("lean/ exists");

    for f in ["lean-toolchain", "lakefile.toml", "BogoCore.lean"] {
        println!("cargo:rerun-if-changed={}", lean_dir.join(f).display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        lean_dir.join("BogoCore").display()
    );
    if let Ok(entries) = std::fs::read_dir(lean_dir.join("BogoCore")) {
        for e in entries.flatten() {
            println!("cargo:rerun-if-changed={}", e.path().display());
        }
    }
    println!("cargo:rerun-if-changed=shim.c");
    println!("cargo:rerun-if-env-changed=BOGO_LAKE");
    println!("cargo:rerun-if-env-changed=BOGO_LEAN");

    run(Command::new(tool("lake"))
        .current_dir(&lean_dir)
        .args(["build", "BogoCore:static"]));

    let prefix = PathBuf::from(
        run(Command::new(tool("lean"))
            .current_dir(&lean_dir)
            .arg("--print-prefix"))
        .trim(),
    );

    cc::Build::new()
        .file("shim.c")
        .include(prefix.join("include"))
        .flag_if_supported("-Wno-unused-parameter")
        .warnings(true)
        .compile("bogo_core_shim");

    println!(
        "cargo:rustc-link-search=native={}",
        lean_dir.join(".lake/build/lib").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib/lean").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=bogo_BogoCore");
    println!("cargo:rustc-link-lib=static=Init");
    println!("cargo:rustc-link-lib=static=leanrt");
    println!("cargo:rustc-link-lib=static=gmp");
    println!("cargo:rustc-link-lib=static=uv");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
