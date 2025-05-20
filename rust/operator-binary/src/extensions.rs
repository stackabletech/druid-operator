use std::collections::HashSet;

use tracing::debug;

use crate::{
    authentication::DruidAuthenticationConfig,
    crd::{DbType, security::DruidTlsSecurity, v1alpha1},
};

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

pub fn get_extension_list(
    druid: &v1alpha1::DruidCluster,
    druid_tls_security: &DruidTlsSecurity,
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

    match druid.spec.cluster_config.metadata_storage_database.db_type {
        DbType::Derby => {} // no additional extensions required
        DbType::Postgresql => {
            extensions.insert(EXT_PSQL_MD_ST.to_string());
        }
        DbType::Mysql => {
            extensions.insert(EXT_MYSQL_MD_ST.to_string());
        }
    };

    if druid_tls_security.tls_enabled() {
        extensions.insert(EXT_SIMPLE_CLIENT_SSL_CONTEXT.to_string());
    }

    if druid.uses_s3() {
        extensions.insert(EXT_S3.to_string());
    }

    if let Some(DruidAuthenticationConfig::Oidc { .. }) = druid_auth_settings {
        extensions.insert(ENV_PAC4J.to_string());
    }

    let additional_extensions = druid.spec.cluster_config.additional_extensions.clone();
    if !additional_extensions.is_empty() {
        debug!(
            enabled_extensions = ?extensions,
            ?additional_extensions,
            "Adding user specified additional extensions to list of enabled extensions"
        );
    }
    extensions.extend(additional_extensions);

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
    use crate::crd::authentication::{AuthenticationClassResolved, AuthenticationClassesResolved};

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

        assert_eq!(
            get_extension_list(
                &cluster,
                &DruidTlsSecurity::new_from_druid_cluster(
                    &cluster,
                    &AuthenticationClassesResolved {
                        auth_classes: vec![]
                    }
                ),
                &Some(
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
                                None
                            ),
                            oidc: oidc::v1alpha1::ClientAuthenticationOptions {
                                client_credentials_secret_ref: "".to_string(),
                                extra_scopes: vec![],
                                product_specific_fields: ()
                            }
                        }]
                    })
                    .unwrap()
                    .unwrap()
                )
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
