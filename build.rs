use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-env-changed=CLANG");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is set by cargo");
    let object = PathBuf::from(out_dir).join("kcart.bpf.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());

    let mut cmd = Command::new(&clang);
    cmd.args([
        "-O2", "-g", "-target", "bpf", "-Wall", "-Werror", "-I", "bpf",
    ]);
    if let Some(dir) = multiarch_include_dir() {
        cmd.arg("-I").arg(dir);
    }
    cmd.args(["-c", "bpf/kcart.bpf.c", "-o"]).arg(&object);

    let status = cmd
        .status()
        .unwrap_or_else(|err| panic!("failed to run {clang}: {err}"));
    if !status.success() {
        panic!("{clang} failed with {status} while compiling bpf/kcart.bpf.c");
    }
}

// Debian and Ubuntu keep asm/ under a multiarch directory that clang does not
// search when targeting bpf, and linux/types.h includes asm/types.h.
fn multiarch_include_dir() -> Option<PathBuf> {
    let dir = Path::new("/usr/include").join(format!("{}-linux-gnu", env::consts::ARCH));
    dir.join("asm/types.h").exists().then_some(dir)
}
