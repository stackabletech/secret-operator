#![allow(non_upper_case_globals, non_camel_case_types)]
// krb5 docs are not written following the Rust conventions,
// so some annotations are misinterpreted by rustdoc as links.
#![allow(rustdoc::broken_intra_doc_links)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
