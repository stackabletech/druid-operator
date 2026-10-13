use semver::Version;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    crd::s3::v1alpha1::ConnectionSpec, memory::MemoryQuantity,
    v2::jvm_argument_overrides::JvmArgumentOverrides,
};

use super::properties::ConfigFileName;
use crate::crd::{
    RW_CONFIG_DIRECTORY, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
    STACKABLE_TRUST_STORE_TYPE,
};

/// AWS Region JVM system property, passed to the AWS SDK v2 (used by Druid >= 37.0.0).
/// Rendered both into `jvm.config` and into the MiddleManager Peon JVM opts.
/// See: <https://druid.apache.org/docs/latest/development/extensions-core/s3/#aws-region>
pub(crate) const AWS_REGION: &str = "aws.region";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to format memory quantity {value:?} for Java"))]
    FormatMemoryStringForJava {
        value: MemoryQuantity,
        source: stackable_operator::memory::Error,
    },
}

/// Please note that this function is slightly different than all other operators, because memory
/// management is far more advanced in this operator.
///
/// `role_jvm_args` are the arguments only the role has (the Coordinator's Derby log file); they
/// follow the arguments every role has.
pub fn construct_jvm_args(
    jvm_argument_overrides: &JvmArgumentOverrides,
    heap: MemoryQuantity,
    direct_memory: Option<MemoryQuantity>,
    role_jvm_args: &[String],
    s3_conn: Option<&ConnectionSpec>,
    // TODO (@NickLarsenNZ): Remove this once we don't support Druid less than 37.0.0
    druid_version: Result<Version, semver::Error>,
) -> Result<String, Error> {
    let heap_str = heap
        .format_for_java()
        .with_context(|_| FormatMemoryStringForJavaSnafu { value: heap })?;
    let direct_memory_str = if let Some(m) = direct_memory {
        Some(
            m.format_for_java()
                .with_context(|_| FormatMemoryStringForJavaSnafu { value: m })?,
        )
    } else {
        None
    };

    let mut jvm_args = vec![
        "-server".to_owned(),
        format!("-Xmx{heap_str}"),
        format!("-Xms{heap_str}"),
    ];
    if let Some(direct_memory) = direct_memory_str {
        jvm_args.push(format!("-XX:MaxDirectMemorySize={direct_memory}"));
    }
    let security_properties_file = ConfigFileName::SecurityProperties;
    let log4j2_config_file = ConfigFileName::Log4j2Properties;
    jvm_args.extend([
        "-XX:+ExitOnOutOfMemoryError".to_owned(),
        "-XX:+UseG1GC".to_owned(),
        format!("-Djava.security.properties={RW_CONFIG_DIRECTORY}/{security_properties_file}"),
        "-Duser.timezone=UTC".to_owned(),
        "-Dfile.encoding=UTF-8".to_owned(),
        "-Djava.io.tmpdir=/tmp".to_owned(),
        "-Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager".to_owned(),
        format!("-Dlog4j.configurationFile={RW_CONFIG_DIRECTORY}/{log4j2_config_file}"),
        format!("-Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}"),
        format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}"),
        format!("-Djavax.net.ssl.trustStoreType={STACKABLE_TRUST_STORE_TYPE}"),
    ]);
    jvm_args.extend(role_jvm_args.iter().cloned());
    // TODO (@NickLarsenNZ): Remove the condition (keep the body) once we no longer support Druid
    // less than 37.0.0
    // Druid >= 37.0.0 uses the AWS SDK v2, which requires a region to be set via the JVM system
    // property `aws.region`.
    if matches!(&druid_version, Ok(v) if *v >= Version::new(37, 0, 0))
        && let Some(s3) = s3_conn
    {
        jvm_args.push(format!(
            "-D{AWS_REGION}={region_name}",
            region_name = s3.region.name
        ));
    }

    Ok(jvm_argument_overrides.apply_to(jvm_args).join("\n"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use indoc::indoc;
    use stackable_operator::v2::types::operator::RoleGroupName;

    use super::*;
    use crate::crd::DruidRole;

    #[test]
    fn test_construct_jvm_arguments_defaults() {
        use crate::controller::validate::test_support::MINIMAL_DRUID_YAML;

        let coordinator_jvm_config =
            construct_jvm_config_for_test(MINIMAL_DRUID_YAML, &DruidRole::Coordinator);
        let historical_jvm_config =
            construct_jvm_config_for_test(MINIMAL_DRUID_YAML, &DruidRole::Historical);

        assert_eq!(
            coordinator_jvm_config,
            indoc! {"
              -server
              -Xmx468m
              -Xms468m
              -XX:+ExitOnOutOfMemoryError
              -XX:+UseG1GC
              -Djava.security.properties=/stackable/rwconfig/security.properties
              -Duser.timezone=UTC
              -Dfile.encoding=UTF-8
              -Djava.io.tmpdir=/tmp
              -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
              -Dlog4j.configurationFile=/stackable/rwconfig/log4j2.properties
              -Djavax.net.ssl.trustStore=/stackable/truststore.p12
              -Djavax.net.ssl.trustStorePassword=changeit
              -Djavax.net.ssl.trustStoreType=pkcs12
              -Dderby.stream.error.file=/stackable/var/druid/derby.log"}
        );
        assert_eq!(
            historical_jvm_config,
            indoc! {"
              -server
              -Xmx900m
              -Xms900m
              -XX:MaxDirectMemorySize=300m
              -XX:+ExitOnOutOfMemoryError
              -XX:+UseG1GC
              -Djava.security.properties=/stackable/rwconfig/security.properties
              -Duser.timezone=UTC
              -Dfile.encoding=UTF-8
              -Djava.io.tmpdir=/tmp
              -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
              -Dlog4j.configurationFile=/stackable/rwconfig/log4j2.properties
              -Djavax.net.ssl.trustStore=/stackable/truststore.p12
              -Djavax.net.ssl.trustStorePassword=changeit
              -Djavax.net.ssl.trustStoreType=pkcs12"}
        );
    }

    #[test]
    fn test_construct_jvm_argument_overrides() {
        let input = r#"
        apiVersion: druid.stackable.tech/v1alpha1
        kind: DruidCluster
        metadata:
          name: simple-druid
          namespace: default
          uid: c27b3971-ca72-42c1-80a4-abdfc1db0ddd
        spec:
          image:
            productVersion: 30.0.0
          clusterConfig:
            deepStorage:
              hdfs:
                configMapName: simple-hdfs
                directory: /druid
            metadataDatabase:
              postgresql:
                host: druid-postgresql
                database: druid
                credentialsSecretName: mySecret
            zookeeperConfigMapName: simple-druid-znode
          brokers:
            roleGroups:
              default:
                replicas: 1
          coordinators:
            config:
              resources:
                memory:
                  limit: 42Gi
            jvmArgumentOverrides:
              add:
                - -Dhttps.proxyHost=proxy.my.corp
                - -Dhttps.proxyPort=8080
                - -Djava.net.preferIPv4Stack=true
            roleGroups:
              default:
                replicas: 1
                jvmArgumentOverrides:
                  # We need more memory!
                  removeRegex:
                    - -Xmx.*
                    - -Dhttps.proxyPort=.*
                  add:
                    - -Xmx40000m
                    - -Dhttps.proxyPort=1234
          historicals:
            config:
              resources:
                memory:
                  limit: 13Gi
            jvmArgumentOverrides:
              add:
                - -Dfoo=bar
            roleGroups:
              default:
                replicas: 1
          middleManagers:
            roleGroups:
              default:
                replicas: 1
          routers:
            roleGroups:
              default:
                replicas: 1
        "#;

        let coordinator_jvm_config = construct_jvm_config_for_test(input, &DruidRole::Coordinator);
        let historical_jvm_config = construct_jvm_config_for_test(input, &DruidRole::Historical);

        assert_eq!(
            coordinator_jvm_config,
            indoc! {"
              -server
              -Xms42708m
              -XX:+ExitOnOutOfMemoryError
              -XX:+UseG1GC
              -Djava.security.properties=/stackable/rwconfig/security.properties
              -Duser.timezone=UTC
              -Dfile.encoding=UTF-8
              -Djava.io.tmpdir=/tmp
              -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
              -Dlog4j.configurationFile=/stackable/rwconfig/log4j2.properties
              -Djavax.net.ssl.trustStore=/stackable/truststore.p12
              -Djavax.net.ssl.trustStorePassword=changeit
              -Djavax.net.ssl.trustStoreType=pkcs12
              -Dderby.stream.error.file=/stackable/var/druid/derby.log
              -Dhttps.proxyHost=proxy.my.corp
              -Djava.net.preferIPv4Stack=true
              -Xmx40000m
              -Dhttps.proxyPort=1234"}
        );
        assert_eq!(
            historical_jvm_config,
            indoc! {"
              -server
              -Xmx9759m
              -Xms9759m
              -XX:MaxDirectMemorySize=3253m
              -XX:+ExitOnOutOfMemoryError
              -XX:+UseG1GC
              -Djava.security.properties=/stackable/rwconfig/security.properties
              -Duser.timezone=UTC
              -Dfile.encoding=UTF-8
              -Djava.io.tmpdir=/tmp
              -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
              -Dlog4j.configurationFile=/stackable/rwconfig/log4j2.properties
              -Djavax.net.ssl.trustStore=/stackable/truststore.p12
              -Djavax.net.ssl.trustStorePassword=changeit
              -Djavax.net.ssl.trustStoreType=pkcs12
              -Dfoo=bar"}
        );
    }

    /// The rendered `jvm.config` of the role's `default` role group: the heap and direct memory
    /// sizes come from the role module, the arguments from [`construct_jvm_args`]. No S3
    /// connection is configured, so the region (and the version gating it) is never rendered.
    fn construct_jvm_config_for_test(druid_cluster: &str, druid_role: &DruidRole) -> String {
        use crate::controller::{
            build::{build, test_support::role_group_config_map},
            validate::test_support::{druid_from_yaml, validated_cluster},
        };

        let druid = druid_from_yaml(druid_cluster);
        let cluster = validated_cluster(&druid);
        let resources = build(&cluster).expect("build succeeds");
        role_group_config_map(
            &resources,
            &cluster,
            druid_role,
            &RoleGroupName::from_str("default").expect("valid role group name"),
        )
        .data
        .as_ref()
        .expect("the ConfigMap has data")[&ConfigFileName::JvmConfig.to_string()]
            .clone()
    }
}
