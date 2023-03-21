use serde::{Deserialize, Serialize};
use stackable_operator::schemars::{self, JsonSchema};

const TLS_DEFAULT_SECRET_CLASS: &str = "tls";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidTls {
    /// This setting controls client as well as internal tls usage:
    /// - If TLS encryption is used at all
    /// - Which cert the servers should use to authenticate themselves against the clients
    /// - Which cert the servers should use to authenticate themselves among each other
    // TODO: Separating internal and server TLS is currently not possible. Internal communication
    // happens via the HTTPS port. Even if both HTTPS and HTTP port are enabled, Druid clients
    // will default to using TLS.
    #[serde(default = "tls_default", skip_serializing_if = "Option::is_none")]
    pub server_and_internal_secret_class: Option<String>,
}

/// Default TLS settings. Internal and server communication default to "tls" secret class.
pub fn default_druid_tls() -> Option<DruidTls> {
    Some(DruidTls {
        server_and_internal_secret_class: tls_default(),
    })
}

/// Helper methods to provide defaults in the CRDs and tests
pub fn tls_default() -> Option<String> {
    Some(TLS_DEFAULT_SECRET_CLASS.to_string())
}

#[cfg(test)]
mod tests {
    use crate::{
        authentication::DruidAuthentication, tests::deserialize_yaml_str, tls::DruidTls,
        DruidClusterConfig,
    };
    use indoc::formatdoc;

    const BASE_DRUID_CONFIGURATION: &str = r#"
deepStorage:
  hdfs:
    configMapName: druid-hdfs
    directory: /druid
metadataStorageDatabase:
  dbType: derby
  connString: jdbc:derby://localhost:1527/var/druid/metadata.db;create=true
  host: localhost
  port: 1527
zookeeperConfigMapName: zk-config-map
    "#;

    #[test]
    fn test_tls_default() {
        let druid_cluster_config =
            deserialize_yaml_str::<DruidClusterConfig>(BASE_DRUID_CONFIGURATION);

        assert_eq!(
            druid_cluster_config.tls,
            Some(DruidTls {
                server_and_internal_secret_class: Some("tls".to_string())
            }),
        );
        assert_eq!(druid_cluster_config.authentication, vec![]);
    }

    #[test]
    fn test_tls_explicit_enabled() {
        let input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        tls:
          serverAndInternalSecretClass: druid-secret-class
        "};
        dbg!(&input);
        let druid_cluster_config = deserialize_yaml_str::<DruidClusterConfig>(&input);

        assert_eq!(
            druid_cluster_config.tls,
            Some(DruidTls {
                server_and_internal_secret_class: Some("druid-secret-class".to_string())
            }),
        );
        assert_eq!(druid_cluster_config.authentication, vec![]);
    }

    #[test]
    fn test_tls_explicit_disabled() {
        let input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        tls: null
        "};
        dbg!(&input);
        let druid_cluster_config = deserialize_yaml_str::<DruidClusterConfig>(&input);

        assert_eq!(druid_cluster_config.tls, None,);
        assert_eq!(druid_cluster_config.authentication, vec![]);
    }

    #[test]
    fn test_tls_explicit_disabled_secret_class() {
        let input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        tls:
          serverAndInternalSecretClass: null
        "};
        dbg!(&input);
        let druid_cluster_config = deserialize_yaml_str::<DruidClusterConfig>(&input);

        assert_eq!(
            druid_cluster_config.tls,
            Some(DruidTls {
                server_and_internal_secret_class: None,
            }),
        );
        assert_eq!(druid_cluster_config.authentication, vec![]);
    }

    #[test]
    fn test_tls_explicit_enabled_and_authentication_enabled() {
        let input = formatdoc! {"\
        {BASE_DRUID_CONFIGURATION}
        tls:
          serverAndInternalSecretClass: druid-secret-class
        authentication:
          - authenticationClass: druid-user-authentication-class
        "};
        dbg!(&input);
        let druid_cluster_config = deserialize_yaml_str::<DruidClusterConfig>(&input);

        assert_eq!(
            druid_cluster_config.tls,
            Some(DruidTls {
                server_and_internal_secret_class: Some("druid-secret-class".to_string())
            }),
        );
        assert_eq!(
            druid_cluster_config.authentication,
            vec![DruidAuthentication {
                authentication_class: "druid-user-authentication-class".to_string()
            }],
        );
    }
}
