use snafu::{ResultExt, Snafu};
use stackable_operator::{
    memory::MemoryQuantity,
    role_utils,
    role_utils::{GenericRoleConfig, JavaCommonConfig, JvmArgumentOverrides, Role},
};

use crate::crd::{
    DruidRole, JVM_SECURITY_PROPERTIES_FILE, LOG4J2_CONFIG, RW_CONFIG_DIRECTORY,
    STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to format memory quantity {value:?} for Java"))]
    FormatMemoryStringForJava {
        value: MemoryQuantity,
        source: stackable_operator::memory::Error,
    },

    #[snafu(display("failed to merge jvm argument overrides"))]
    MergeJvmArgumentOverrides { source: role_utils::Error },
}

/// Please note that this function is slightly different than all other operators, because memory
/// management is far more advanced in this operator.
pub fn construct_jvm_args<T>(
    druid_role: &DruidRole,
    role: &Role<T, GenericRoleConfig, JavaCommonConfig>,
    role_group: &str,
    heap: MemoryQuantity,
    direct_memory: Option<MemoryQuantity>,
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
    jvm_args.extend([
        "-XX:+ExitOnOutOfMemoryError".to_owned(),
        "-XX:+UseG1GC".to_owned(),
        format!("-Djava.security.properties={RW_CONFIG_DIRECTORY}/{JVM_SECURITY_PROPERTIES_FILE}"),
        "-Duser.timezone=UTC".to_owned(),
        "-Dfile.encoding=UTF-8".to_owned(),
        "-Djava.io.tmpdir=/tmp".to_owned(),
        "-Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager".to_owned(),
        format!("-Dlog4j.configurationFile={RW_CONFIG_DIRECTORY}/{LOG4J2_CONFIG}"),
        format!("-Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}"),
        format!("-Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}"),
        "-Djavax.net.ssl.trustStoreType=pkcs12".to_owned(),
    ]);
    if druid_role == &DruidRole::Coordinator {
        jvm_args.push("-Dderby.stream.error.file=/stackable/var/druid/derby.log".to_owned());
    }

    let operator_generated = JvmArgumentOverrides::new_with_only_additions(jvm_args);
    let merged_jvm_argument_overrides = role
        .get_merged_jvm_argument_overrides(role_group, &operator_generated)
        .context(MergeJvmArgumentOverridesSnafu)?;

    Ok(merged_jvm_argument_overrides
        .effective_jvm_config_after_merging()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;
    use crate::crd::v1alpha1::DruidCluster;

    #[test]
    fn test_construct_jvm_arguments_defaults() {
        let input = r#"
        apiVersion: druid.stackable.tech/v1alpha1
        kind: DruidCluster
        metadata:
          name: simple-druid
        spec:
          image:
            productVersion: 30.0.0
          clusterConfig:
            deepStorage:
              hdfs:
                configMapName: simple-hdfs
                directory: /druid
            metadataStorageDatabase:
              dbType: postgresql
              connString: jdbc:postgresql://druid-postgresql/druid
              host: druid-postgresql
              port: 5432
              credentialsSecret: mySecret
            zookeeperConfigMapName: simple-druid-znode
          brokers:
            roleGroups:
              default:
                replicas: 1
          coordinators:
            roleGroups:
              default:
                replicas: 1
          historicals:
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
        spec:
          image:
            productVersion: 30.0.0
          clusterConfig:
            deepStorage:
              hdfs:
                configMapName: simple-hdfs
                directory: /druid
            metadataStorageDatabase:
              dbType: postgresql
              connString: jdbc:postgresql://druid-postgresql/druid
              host: druid-postgresql
              port: 5432
              credentialsSecret: mySecret
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

    fn construct_jvm_config_for_test(druid_cluster: &str, druid_role: &DruidRole) -> String {
        let deserializer = serde_yaml::Deserializer::from_str(druid_cluster);
        let druid: DruidCluster =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();

        let role = druid.get_role(druid_role);
        let merged_config = druid.merged_config().unwrap();
        let (heap, direct) = merged_config
            .common_config(druid_role, "default")
            .unwrap()
            .resources
            .get_memory_sizes(druid_role)
            .unwrap();

        construct_jvm_args(druid_role, &role, "default", heap, direct).unwrap()
    }
}
