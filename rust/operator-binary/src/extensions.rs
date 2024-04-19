use stackable_druid_crd::{security::DruidTlsSecurity, DbType, DruidCluster};

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

pub fn get_extension_list(
    druid: &DruidCluster,
    druid_tls_security: &DruidTlsSecurity,
) -> Vec<String> {
    let mut extensions = vec![
        EXT_KAFKA_INDEXING.to_string(),
        EXT_DATASKETCHES.to_string(),
        PROMETHEUS_EMITTER.to_string(),
        EXT_BASIC_SECURITY.to_string(),
        EXT_OPA_AUTHORIZER.to_string(),
        EXT_HDFS.to_string(),
    ];

    match druid.spec.cluster_config.metadata_storage_database.db_type {
        DbType::Derby => {} // no additional extensions required
        DbType::Postgresql => extensions.push(EXT_PSQL_MD_ST.to_string()),
        DbType::Mysql => extensions.push(EXT_MYSQL_MD_ST.to_string()),
    }

    if druid_tls_security.tls_enabled() {
        extensions.push(EXT_SIMPLE_CLIENT_SSL_CONTEXT.to_string());
    }

    if druid.uses_s3() {
        extensions.push(EXT_S3.to_string());
    }

    if let Some(additional_extensions) = &druid.spec.cluster_config.additional_extensions {
        if let Some(custom_extensions) = &additional_extensions.custom_extensions {
            for extension in custom_extensions {
                if extensions.contains(extension) {
                    continue;
                }
                extensions.push(extension.to_owned())
            }
        }
    }

    extensions
}
