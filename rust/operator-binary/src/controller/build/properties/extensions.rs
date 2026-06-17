//! Builder for the `druid.extensions.loadList` runtime.properties entry.
//!
//! The set of Druid extensions to load is derived from the metadata database, TLS, S3 and
//! authentication settings carried on the validated cluster. This is a build-step concern: it
//! computes a config output, so it lives here rather than in the validate step.

use std::collections::HashSet;

use tracing::debug;

use crate::{authentication::DruidAuthenticationConfig, crd::database::MetadataDatabaseConnection};

const EXT_S3: &str = "druid-s3-extensions";
const EXT_KAFKA_INDEXING: &str = "druid-kafka-indexing-service";
const EXT_DATASKETCHES: &str = "druid-datasketches";
const PROMETHEUS_EMITTER: &str = "prometheus-emitter";
const EXT_PSQL_MD_ST: &str = "postgresql-metadata-storage";
const EXT_MYSQL_MD_ST: &str = "mysql-metadata-storage";
const EXT_OPA_AUTHORIZER: &str = "druid-opa-authorizer";
const EXT_BASIC_SECURITY: &str = "druid-basic-security";
const EXT_HDFS: &str = "druid-hdfs-storage";
const EXT_SIMPLE_CLIENT_SSL_CONTEXT: &str = "simple-client-sslcontext";
const ENV_PAC4J: &str = "druid-pac4j";

/// Computes the `druid.extensions.loadList` entries from the validated cluster inputs.
///
/// Takes the resolved inputs (metadata database, whether TLS/S3 are in use, the user-supplied
/// additional extensions and the resolved authentication config) rather than the raw
/// `DruidCluster`, so it has no dependency on the validate step.
pub fn get_extension_list(
    metadata_database: &MetadataDatabaseConnection,
    tls_enabled: bool,
    uses_s3: bool,
    additional_extensions: &HashSet<String>,
    druid_auth_settings: &Option<DruidAuthenticationConfig>,
) -> Vec<String> {
    let mut extensions = HashSet::from([
        EXT_KAFKA_INDEXING.to_string(),
        EXT_DATASKETCHES.to_string(),
        PROMETHEUS_EMITTER.to_string(),
        EXT_BASIC_SECURITY.to_string(),
        EXT_OPA_AUTHORIZER.to_string(),
        EXT_HDFS.to_string(),
    ]);

    match metadata_database {
        MetadataDatabaseConnection::Derby(..) => {} // no additional extensions required
        MetadataDatabaseConnection::Postgresql(..) => {
            extensions.insert(EXT_PSQL_MD_ST.to_string());
        }
        MetadataDatabaseConnection::Mysql(..) => {
            extensions.insert(EXT_MYSQL_MD_ST.to_string());
        }
    };

    if tls_enabled {
        extensions.insert(EXT_SIMPLE_CLIENT_SSL_CONTEXT.to_string());
    }

    if uses_s3 {
        extensions.insert(EXT_S3.to_string());
    }

    if let Some(DruidAuthenticationConfig::Oidc { .. }) = druid_auth_settings {
        extensions.insert(ENV_PAC4J.to_string());
    }

    if !additional_extensions.is_empty() {
        debug!(
            enabled_extensions = ?extensions,
            ?additional_extensions,
            "Adding user specified additional extensions to list of enabled extensions"
        );
    }
    extensions.extend(additional_extensions.iter().cloned());

    let mut extensions = Vec::from_iter(extensions);
    extensions.sort();
    extensions
}

#[cfg(test)]
mod tests {
    use stackable_operator::{
        commons::tls_verification::TlsClientDetails, crd::authentication::oidc,
    };

    use super::*;
    use crate::crd::{
        authentication::{AuthenticationClassResolved, AuthenticationClassesResolved},
        security::DruidTlsSecurity,
        v1alpha1,
    };

    #[test]
    fn test_additional_extensions() {
        let cluster = deserialize_yaml_file::<v1alpha1::DruidCluster>(
            "test/resources/druid_controller/simple.yaml",
        );

        assert_eq!(
            cluster.spec.cluster_config.additional_extensions,
            HashSet::from([
                "druid-avro-extensions".to_owned(),
                "druid-azure-extensions".to_owned(),
                "druid-histogram".to_owned()
            ])
        );

        let druid_tls_security = DruidTlsSecurity::new_from_druid_cluster(
            &cluster,
            &AuthenticationClassesResolved {
                auth_classes: vec![],
            },
        );

        let druid_auth_config = Some(
            DruidAuthenticationConfig::try_from(AuthenticationClassesResolved {
                auth_classes: vec![AuthenticationClassResolved::Oidc {
                    auth_class_name: "oidc".to_string(),
                    provider: oidc::v1alpha1::AuthenticationProvider::new(
                        "my-oidc-provider".to_string().try_into().unwrap(),
                        None,
                        "".to_string(),
                        TlsClientDetails { tls: None },
                        "".to_string(),
                        vec![],
                        None,
                    ),
                    oidc: crate::authentication::oidc::DruidClientAuthenticationOptions {
                        client_credentials_secret_ref: "".to_string(),
                        extra_scopes: vec![],
                        product_specific_fields: oidc::v1alpha1::ClientAuthenticationMethodOption {
                            client_authentication_method:
                                oidc::v1alpha1::ClientAuthenticationMethod::default(),
                        },
                    },
                }],
            })
            .unwrap()
            .unwrap(),
        );

        assert_eq!(
            get_extension_list(
                &cluster.spec.cluster_config.metadata_database,
                druid_tls_security.tls_enabled(),
                // simple.yaml uses HDFS deep storage and no S3 ingestion.
                false,
                &cluster.spec.cluster_config.additional_extensions,
                &druid_auth_config,
            ),
            [
                "druid-avro-extensions".to_owned(),
                "druid-azure-extensions".to_owned(),
                "druid-basic-security".to_owned(),
                "druid-datasketches".to_owned(),
                "druid-hdfs-storage".to_owned(),
                "druid-histogram".to_owned(),
                "druid-kafka-indexing-service".to_owned(),
                "druid-opa-authorizer".to_owned(),
                "druid-pac4j".to_owned(),
                "postgresql-metadata-storage".to_owned(),
                "prometheus-emitter".to_owned(),
                "simple-client-sslcontext".to_owned(),
            ]
        )
    }

    pub fn deserialize_yaml_file<'a, T: serde::de::Deserialize<'a>>(path: &'a str) -> T {
        let file = std::fs::File::open(path).unwrap();
        let deserializer = serde_yaml::Deserializer::from_reader(file);
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap()
    }
}
