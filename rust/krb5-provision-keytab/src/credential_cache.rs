use futures::{TryFuture, TryFutureExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{api::core::v1::Secret, ByteString},
    kube::runtime::reflector::ObjectRef,
};
use stackable_secret_operator_crd_utils::SecretReference;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to load initial cache from {cache_ref}"))]
    GetInitialCache {
        source: stackable_operator::error::Error,
        cache_ref: ObjectRef<Secret>,
    },

    #[snafu(display("failed to save credential {key} to {cache_ref}"))]
    SaveToCache {
        source: stackable_operator::error::Error,
        key: String,
        cache_ref: ObjectRef<Secret>,
    },

    #[snafu(display("newly saved credential {key} was not found in {cache_ref}"))]
    SavedKeyNotFound {
        key: String,
        cache_ref: ObjectRef<Secret>,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

pub struct CredentialCache {
    name: &'static str,
    kube: stackable_operator::client::Client,
    cache_ref: SecretReference,
    current_state: Secret,
}
impl CredentialCache {
    #[tracing::instrument(skip(kube))]
    pub async fn new(
        name: &'static str,
        kube: stackable_operator::client::Client,
        cache_ref: SecretReference,
    ) -> Result<Self> {
        Ok(Self {
            name,
            current_state: kube
                .get::<Secret>(&cache_ref.name, &cache_ref.namespace)
                .await
                .context(GetInitialCacheSnafu {
                    cache_ref: &cache_ref,
                })?,
            cache_ref,
            kube,
        })
    }

    fn get_if_present(&self, key: &str) -> Option<&[u8]> {
        Some(&self.current_state.data.as_ref()?.get(key)?.0)
    }

    /// Gets the credential named `key` from the cache, or calls `mk_value` if it cannot be found.
    ///
    /// # Concurrency
    /// There is no locking imposed by `CredentialCache`, in the face of a race condition
    /// `mk_value` must either fail or be idempotent (returning exactly the same value for all concurrent calls
    /// for the same key).
    ///
    /// # Errors
    /// There is no negative caching, the result of a failed call to `mk_value` will not be saved.
    #[tracing::instrument(skip(self, mk_value), fields(name = self.name, cache_ref = %self.cache_ref))]
    pub async fn get_or_insert<F: FnOnce(Ctx) -> Fut, Fut: TryFuture<Ok = Vec<u8>>>(
        &mut self,
        key: &str,
        mk_value: F,
    ) -> Result<Result<&[u8], Fut::Error>>
    where
        Fut::Error: std::error::Error + 'static,
    {
        // This should be an if let Some(...) but for some reason Rust considers that borrow to conflict with
        // us modifying self.current_state in the other branch
        if self.get_if_present(key).is_some() {
            tracing::info!("credential found in cache, reusing...");
            Ok(Ok(self
                .get_if_present(key)
                .expect("key was just confirmed to exist in cache")))
        } else {
            tracing::info!("credential not found in cache, generating...");
            match mk_value(Ctx {
                cache_ref: self.cache_ref.clone(),
            })
            .into_future()
            .await
            {
                Ok(value) => {
                    tracing::info!("generated credential successfully, saving...");
                    self.current_state = self
                        .kube
                        .merge_patch(
                            &self.current_state,
                            &Secret {
                                data: Some([(key.to_string(), ByteString(value))].into()),
                                ..Secret::default()
                            },
                        )
                        .await
                        .context(SaveToCacheSnafu {
                            key,
                            cache_ref: &self.cache_ref,
                        })?;
                    Ok(Ok(self.get_if_present(key).context(
                        SavedKeyNotFoundSnafu {
                            key,
                            cache_ref: &self.cache_ref,
                        },
                    )?))
                }
                Err(err) => {
                    tracing::warn!(
                        error = &err as &dyn std::error::Error,
                        "failed to generate credential, discarding..."
                    );
                    Ok(Err(err))
                }
            }
        }
    }
}

/// Information that may be useful for generating error messages in get_or_insert handlers
pub struct Ctx {
    pub cache_ref: SecretReference,
}
