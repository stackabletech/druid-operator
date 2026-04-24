use serde::{Deserialize, Serialize};
use stackable_operator::{
    database_connections::{
        self, TemplatingMechanism,
        databases::{
            derby::DerbyConnection, mysql::MysqlConnection, postgresql::PostgresqlConnection,
        },
        drivers::jdbc::{JdbcDatabaseConnection, JdbcDatabaseConnectionDetails},
    },
    schemars::{self, JsonSchema},
};

// metadata storage config properties
pub const METADATA_STORAGE_TYPE: &str = "druid.metadata.storage.type";
pub const METADATA_STORAGE_CONNECTOR_CONNECT_URI: &str =
    "druid.metadata.storage.connector.connectURI";
pub const METADATA_STORAGE_USER: &str = "druid.metadata.storage.connector.user";
pub const METADATA_STORAGE_PASSWORD: &str = "druid.metadata.storage.connector.password";

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MetadataDatabaseConnection {
    // Docs are on the struct
    Postgresql(PostgresqlConnection),

    /// Connection settings for a [MySQL](https://www.mysql.com/) database.
    ///
    /// Please note that - due to license issues - we don't ship the mysql driver, you need to add
    /// it it yourself.
    Mysql(MysqlConnection),

    // Docs are on the struct
    Derby(DerbyConnection),
    // We don't support generic as druid only offers the types mentioned above for metadata storage
    // See <https://druid.apache.org/docs/latest/design/metadata-storage/>
}

impl MetadataDatabaseConnection {
    /// Name of the database as it should be passed using `METADATA_STORAGE_TYPE` ("druid.metadata.storage.type") property.
    pub fn as_metadata_storage_type(&self) -> &str {
        match self {
            Self::Postgresql(_) => "postgresql",
            Self::Mysql(_) => "mysql",
            Self::Derby(_) => "derby",
        }
    }
}

impl JdbcDatabaseConnection for MetadataDatabaseConnection {
    /// We do *not* implement [`std::ops::Deref`]` for [`MetadataDatabaseConnection`], as we need
    /// some special handling for Derby.
    fn jdbc_connection_details_with_templating(
        &self,
        unique_database_name: &str,
        templating_mechanism: &TemplatingMechanism,
    ) -> Result<JdbcDatabaseConnectionDetails, database_connections::Error> {
        match self {
            Self::Postgresql(p) => p.jdbc_connection_details_with_templating(
                unique_database_name,
                templating_mechanism,
            ),
            Self::Mysql(m) => m.jdbc_connection_details_with_templating(
                unique_database_name,
                templating_mechanism,
            ),
            Self::Derby(d) => {
                // According to the [Druid docs](https://druid.apache.org/docs/latest/design/metadata-storage/#derby)
                // we should configure something like
                // `jdbc:derby://localhost:1527//opt/var/druid_state/derby;create=true`
                // instead of the usual `jdbc:derby:/opt/var/druid_state/derby;create=true`.
                //
                // It looks like Druid always starts Derby at `localhost:1527`, regardless of what we configure here,
                // so we can hardcode it here.
                d.jdbc_connection_details_with_host_part(unique_database_name, "localhost:1527")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use stackable_operator::utils::yaml_from_str_singleton_map;

    use super::*;

    #[rstest]
    #[case::postgres(
        "postgresql:
  host: druid-postgresql
  database: druid
  credentialsSecretName: druid-credentials",
        "jdbc:postgresql://druid-postgresql:5432/druid"
    )]
    #[case::derby(
        "derby: {}",
        "jdbc:derby://localhost:1527//tmp/derby/METADATA/derby.db;create=true"
    )]
    #[case::derby_custom_location(
        "derby:
  location: /user/provided.db",
        "jdbc:derby://localhost:1527//user/provided.db;create=true"
    )]
    fn test_connection_url(
        #[case] database_connection_yaml: &str,
        #[case] expected_connection_url: &str,
    ) {
        let database_connection: MetadataDatabaseConnection =
            yaml_from_str_singleton_map(database_connection_yaml).expect("invalid YAML");

        let jdbc_connection_details = database_connection
            .jdbc_connection_details("METADATA")
            .expect("failed to get JDBC connection details");
        assert_eq!(
            jdbc_connection_details.connection_url.as_str(),
            expected_connection_url
        );
    }
}
