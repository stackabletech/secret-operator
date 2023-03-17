use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    let krb5_cfg = pkg_config::probe_library("krb5").expect("Failed to probe pkg-config for krb5");
    let _kadm_cfg = pkg_config::probe_library("kadm-client")
        .expect("Failed to probe pkg-config for kadmin-client");
    let bindings = bindgen::builder()
        .header("wrapper.h")
        .clang_args(
            krb5_cfg
                .include_paths
                .iter()
                .map(|path| format!("-I{}", path.display())),
        )
        .allowlist_function("^krb5_.*")
        .allowlist_function("^kadm5_.*")
        .allowlist_function("error_message")
        .allowlist_function("^profile_.*")
        .allowlist_var("KRB5_.*")
        .allowlist_var("KADM5_.*")
        .allowlist_var("ENCTYPE_.*")
        .new_type_alias("krb5_error_code")
        .new_type_alias("kadm5_ret_t")
        .must_use_type("krb5_error_code")
        .must_use_type("kadm5_ret_t")
        // .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings");
}
