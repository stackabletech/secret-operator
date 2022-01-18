//! Compile Rust code from gRPC definition files stored in the vendor/csi directory.

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is required"));
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("file_descriptor_set.bin"))
        .compile(&["csi.proto"], &["vendor/csi"])
        .unwrap();
}
