//! See [`SecretScope`]

use std::fmt::Display;

use serde::{Deserialize, Deserializer};
use snafu::{OptionExt, Snafu};

/// Defines what properties the secret identifies about a pod
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretScope {
    Node,
    Pod,
    Service { name: String },
    ListenerVolume { name: String },
}
impl From<&SecretScope> for SecretScope {
    fn from(value: &SecretScope) -> Self {
        value.clone()
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum DeserializeError {
    UnknownScopeType { tpe: String },
    ScopeRequiresParam { tpe: String },
    ScopeDoesNotAcceptParam { tpe: String, param: String },
}

impl SecretScope {
    fn deserialize(s: &str) -> Result<SecretScope, DeserializeError> {
        let (tpe, mut param) = match s.split_once('=') {
            Some((tpe, param)) => (tpe, Some(param)),
            // No param, whole string is tpe
            None => (s, None),
        };
        let scope = match tpe {
            "node" => Self::Node,
            "pod" => Self::Pod,
            "service" => Self::Service {
                name: param
                    .take()
                    .context(deserialize_error::ScopeRequiresParamSnafu { tpe })?
                    .to_string(),
            },
            "listener-volume" => Self::ListenerVolume {
                name: param
                    .take()
                    .context(deserialize_error::ScopeRequiresParamSnafu { tpe })?
                    .to_string(),
            },
            _ => return deserialize_error::UnknownScopeTypeSnafu { tpe }.fail(),
        };
        if let Some(param) = param {
            return deserialize_error::ScopeDoesNotAcceptParamSnafu { tpe, param }.fail();
        }
        Ok(scope)
    }

    pub(super) fn deserialize_vec<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Self>, D::Error> {
        let scopes_str = String::deserialize(de)?;
        scopes_str
            .split(',')
            .map(|s| Self::deserialize(s).map_err(<D::Error as serde::de::Error>::custom))
            .collect::<Result<Vec<_>, _>>()
    }
}
impl Display for SecretScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretScope::Node => write!(f, "node"),
            SecretScope::Pod => write!(f, "pod"),
            SecretScope::Service { name } => write!(f, "service={name}"),
            SecretScope::ListenerVolume { name } => write!(f, "listener-volume={name}"),
        }
    }
}
