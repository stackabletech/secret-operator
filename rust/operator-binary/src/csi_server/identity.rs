use std::collections::HashMap;

use clap::crate_version;
use tonic::{Request, Response, Status};

use crate::grpc::csi::v1::{
    identity_server::Identity, plugin_capability, GetPluginCapabilitiesRequest,
    GetPluginCapabilitiesResponse, GetPluginInfoRequest, GetPluginInfoResponse, PluginCapability,
    ProbeRequest, ProbeResponse,
};

pub struct SecretProvisionerIdentity;

// The identity services are mandatory to implement, we deliver some minimal responses here
// https://github.com/container-storage-interface/spec/blob/master/spec.md#rpc-interface
#[tonic::async_trait]
impl Identity for SecretProvisionerIdentity {
    async fn get_plugin_info(
        &self,
        _request: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        Ok(Response::new(GetPluginInfoResponse {
            name: "secrets.stackable.tech".to_string(),
            vendor_version: crate_version!().to_string(),
            manifest: HashMap::new(),
        }))
    }

    async fn get_plugin_capabilities(
        &self,
        _request: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
        // It is ok to return an empty vec here, as a minimal set of capabilities is
        // mandatory to implement. This list only refers to optional capabilities.
        Ok(Response::new(GetPluginCapabilitiesResponse {
            capabilities: vec![
                PluginCapability {
                    r#type: Some(plugin_capability::Type::Service(
                        plugin_capability::Service {
                            r#type:
                                plugin_capability::service::Type::VolumeAccessibilityConstraints
                                    .into(),
                        },
                    )),
                },
                PluginCapability {
                    r#type: Some(plugin_capability::Type::Service(
                        plugin_capability::Service {
                            r#type: plugin_capability::service::Type::ControllerService.into(),
                        },
                    )),
                },
            ],
        }))
    }

    async fn probe(
        &self,
        _request: Request<ProbeRequest>,
    ) -> Result<Response<ProbeResponse>, Status> {
        Ok(Response::new(ProbeResponse { ready: Some(true) }))
    }
}
