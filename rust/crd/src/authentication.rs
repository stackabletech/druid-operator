use crate::tls::{
    add_cert_to_trust_store_cmd, add_key_pair_to_key_store_cmd, chown_and_chmod, create_tls_volume,
    CLIENT_HTTPS_CERT_ALIAS, CLIENT_HTTPS_CERT_ALIAS_NAME, CLIENT_HTTPS_KEY_STORE_PASSWORD,
    CLIENT_HTTPS_KEY_STORE_PATH, CLIENT_HTTPS_KEY_STORE_TYPE, SERVER_HTTPS_CERT_ALIAS,
    SERVER_HTTPS_CERT_ALIAS_NAME, SERVER_HTTPS_TRUST_STORE_PASSWORD, SERVER_HTTPS_TRUST_STORE_PATH,
    SERVER_HTTPS_TRUST_STORE_TYPE, STACKABLE_SERVER_TLS_DIR, TLS_STORE_PASSWORD,
};
use crate::DruidCluster;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::builder::{ContainerBuilder, PodBuilder};
use stackable_operator::{
    client::Client,
    commons::{
        authentication::{AuthenticationClass, AuthenticationClassProvider},
        tls::TlsAuthenticationProvider,
    },
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};
use std::collections::BTreeMap;
use strum::{EnumDiscriminants, IntoStaticStr};

pub const SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE: &str =
    "druid.server.https.requireClientCertificate";
pub const STACKABLE_MOUNT_SERVER_AUTHENTICATION_TLS_DIR: &str =
    "/stackable/mount_server_authentication_tls";
pub const SERVER_HTTPS_VALIDATE_HOST_NAMES: &str = "druid.server.https.validateHostnames";
pub const SERVER_HTTPS_KEY_MANAGER_PASSWORD: &str = "druid.server.https.keyManagerPassword";
pub const CLIENT_HTTPS_VALIDATE_HOST_NAMES: &str = "druid.client.https.validateHostnames";
pub const CLIENT_HTTPS_KEY_MANAGER_PASSWORD: &str = "druid.client.https.keyManagerPassword";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("Failed to retrieve AuthenticationClass {authentication_class}"))]
    AuthenticationClassRetrieval {
        source: stackable_operator::error::Error,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display("The Trino Operator doesn't support the AuthenticationClass provider {authentication_class_provider} from AuthenticationClass {authentication_class} yet"))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    #[snafu(display(
        "TLS encryption is deactivated. This is required for any authentication mechanism. Please set proper values in [spec.commonConfig.tls.server.secretClass]"
    ))]
    TlsNotActivated,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DruidAuthentication {
    #[serde(rename_all = "camelCase")]
    /// TLS based authentication (mutual TLS)
    Tls { authentication_class: String },
}

impl DruidAuthentication {
    pub async fn resolve(
        client: &Client,
        druid: &DruidCluster,
    ) -> Result<Vec<DruidAuthenticationConfig>, Error> {
        // Do not allow authentication without TLS activated
        if druid.spec.common_config.tls.server.is_none() {
            return Err(Error::TlsNotActivated);
        }

        let mut druid_authentication_config: Vec<DruidAuthenticationConfig> = vec![];

        for authentication_class_name in &druid.spec.common_config.authentication {
            let authentication_class =
                AuthenticationClass::resolve(client, authentication_class_name)
                    .await
                    .context(AuthenticationClassRetrievalSnafu {
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            authentication_class_name,
                        ),
                    })?;

            match &authentication_class.spec.provider {
                AuthenticationClassProvider::Tls(tls_provider) => {
                    druid_authentication_config
                        .push(DruidAuthenticationConfig::Tls(tls_provider.clone()));
                }
                _ => {
                    return Err(Error::AuthenticationClassProviderNotSupported {
                        authentication_class_provider: authentication_class
                            .spec
                            .provider
                            .to_string(),
                        authentication_class: ObjectRef::<AuthenticationClass>::new(
                            authentication_class_name,
                        ),
                    })
                }
            }
        }

        Ok(druid_authentication_config)
    }
}

#[derive(Clone, Debug)]
pub enum DruidAuthenticationConfig {
    Tls(TlsAuthenticationProvider),
}

impl DruidAuthenticationConfig {
    /// Adds required tls volume mounts to image and product container builders
    /// Adds required tls volumes to pod builder
    pub fn add_authentication_volume_and_volume_mounts(
        &self,
        prepare: &mut ContainerBuilder,
        druid: &mut ContainerBuilder,
        pod: &mut PodBuilder,
    ) {
        match &self {
            DruidAuthenticationConfig::Tls(tls_provider) => {
                prepare.add_volume_mount(
                    "authentication-tls-mount",
                    STACKABLE_MOUNT_SERVER_AUTHENTICATION_TLS_DIR,
                );
                druid.add_volume_mount(
                    "authentication-tls-mount",
                    STACKABLE_MOUNT_SERVER_AUTHENTICATION_TLS_DIR,
                );
                // TODO: remove unwrap
                pod.add_volume(create_tls_volume(
                    "authentication-tls-mount",
                    tls_provider.client_cert_secret_class.as_ref().unwrap(),
                ));
            }
        }
    }

    /// Add required authentication settings to the druid configuration
    pub fn add_common_config_properties(&self, config: &mut BTreeMap<String, Option<String>>) {
        match &self {
            DruidAuthenticationConfig::Tls(_) => {
                config.insert(
                    CLIENT_HTTPS_KEY_STORE_PATH.to_string(),
                    Some(format!("{}/keystore.p12", STACKABLE_SERVER_TLS_DIR)),
                );
                config.insert(
                    CLIENT_HTTPS_KEY_STORE_TYPE.to_string(),
                    Some("pkcs12".to_string()),
                );
                config.insert(
                    CLIENT_HTTPS_KEY_STORE_PASSWORD.to_string(),
                    Some(TLS_STORE_PASSWORD.to_string()),
                );
                // config.insert(
                //     CLIENT_HTTPS_CERT_ALIAS.to_string(),
                //     Some(CLIENT_HTTPS_CERT_ALIAS_NAME.to_string()),
                // );
                // This is required because the server will send its pod ip which is not in the SANs of the certificates
                config.insert(
                    CLIENT_HTTPS_VALIDATE_HOST_NAMES.to_string(),
                    Some("false".to_string()),
                );

                // This is required because PKCS12 does not use any key passwords but it will
                // be checked and would lead to an exception:
                // java.security.UnrecoverableKeyException: Get Key failed: null
                // Must be set to the store password or we get a bad padding exception:
                // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
                config.insert(
                    CLIENT_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
                    Some(TLS_STORE_PASSWORD.to_string()),
                );

                // This is required because PKCS12 does not use any key passwords but it will
                // be checked and would lead to an exception:
                // java.security.UnrecoverableKeyException: Get Key failed: null
                // Must be set to the store password or we get a bad padding exception:
                // javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
                config.insert(
                    SERVER_HTTPS_KEY_MANAGER_PASSWORD.to_string(),
                    Some(TLS_STORE_PASSWORD.to_string()),
                );

                // This will enforce the client to authenticate itself
                config.insert(
                    SERVER_HTTPS_REQUIRE_CLIENT_CERTIFICATE.to_string(),
                    Some("true".to_string()),
                );

                config.insert(
                    SERVER_HTTPS_TRUST_STORE_PATH.to_string(),
                    Some(format!("{}/truststore.p12", STACKABLE_SERVER_TLS_DIR)),
                );
                config.insert(
                    SERVER_HTTPS_TRUST_STORE_TYPE.to_string(),
                    Some("pkcs12".to_string()),
                );
                config.insert(
                    SERVER_HTTPS_TRUST_STORE_PASSWORD.to_string(),
                    Some(TLS_STORE_PASSWORD.to_string()),
                );
                // This is required because the client will send its pod ip which is not in the SANs of the certificates
                config.insert(
                    SERVER_HTTPS_VALIDATE_HOST_NAMES.to_string(),
                    Some("false".to_string()),
                );

                config.insert(
                    SERVER_HTTPS_CERT_ALIAS.to_string(),
                    Some(SERVER_HTTPS_CERT_ALIAS_NAME.to_string()),
                );
            }
        }
    }

    pub fn build_authentication_cmd(&self) -> Vec<String> {
        let mut command = vec![];
        match &self {
            DruidAuthenticationConfig::Tls(_) => {
                command.extend(add_cert_to_trust_store_cmd(
                    STACKABLE_MOUNT_SERVER_AUTHENTICATION_TLS_DIR,
                    STACKABLE_SERVER_TLS_DIR,
                    CLIENT_HTTPS_CERT_ALIAS_NAME,
                    TLS_STORE_PASSWORD,
                    false,
                ));
                command.extend(add_key_pair_to_key_store_cmd(
                    STACKABLE_MOUNT_SERVER_AUTHENTICATION_TLS_DIR,
                    STACKABLE_SERVER_TLS_DIR,
                    CLIENT_HTTPS_CERT_ALIAS_NAME,
                    TLS_STORE_PASSWORD,
                ));
                command.extend(chown_and_chmod(STACKABLE_SERVER_TLS_DIR));
            }
        }

        command
    }
}