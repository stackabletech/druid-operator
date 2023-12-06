use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::opa::OpaConfig,
    schemars::{self, JsonSchema},
};

#[derive(Clone, Deserialize, Debug, Default, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidAuthorization {
    /// Configure the OPA stacklet [discovery ConfigMap](DOCS_BASE_URL_PLACEHOLDER/concepts/service_discovery)
    /// and the name of the Rego package containing your Druid authorization rules.
    /// Consult the [OPA authorization documentation](DOCS_BASE_URL_PLACEHOLDER/concepts/opa)
    /// to learn how to deploy Rego authorization rules with OPA.
    /// Read the [Druid operator security documentation](DOCS_BASE_URL_PLACEHOLDER/druid/usage-guide/security)
    /// for more information on how to write rules specifically for Druid.
    pub opa: OpaConfig,
}
