// Exported because the olm-deployer needs access to the SecretClass
pub mod crd;

// This is a side-effect of exporting the crd module above (and introducing this lib.rs file)
// Without these, the operator binary doesn't compile anymore.
pub mod backend;
pub mod csi_server;
pub mod external_crd;
pub mod format;
pub mod grpc;
pub mod utils;
