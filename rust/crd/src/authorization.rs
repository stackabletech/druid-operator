use serde::{Deserialize, Serialize};
use stackable_operator::{
    commons::opa::OpaConfig,
    schemars::{self, JsonSchema},
};

#[derive(Clone, Deserialize, Debug, Default, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidAuthorization {
    /// Configure the OPA stacklet [discovery ConfigMap](https://docs.stackable.tech/home/nightly/concepts/service_discovery)
    /// and the name of the Rego package containing your Druid authorization rules.
    /// Consult the [OPA authorization documentation](https://docs.stackable.tech/home/nightly/concepts/opa)
    /// to learn how to deploy Rego authorization rules with OPA.
    /// Read the [Druid operator security documentation](https://docs.stackable.tech/home/nightly/druid/usage-guide/security)
    /// for more information on how to write rules specifically for Druid.
    pub opa: OpaConfig,
}
