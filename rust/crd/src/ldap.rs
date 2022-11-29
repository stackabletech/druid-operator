
use serde::{Deserialize, Serialize};
use stackable_operator::commons::authentication::AuthenticationClassProvider;
use stackable_operator::{
    schemars::{self, JsonSchema},
};

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DruidLdapSettings {
}

impl DruidLdapSettings {
    pub fn new_from(_resolved_authentication_config: &Vec<AuthenticationClassProvider>) -> Option<DruidLdapSettings> {
        None
    }
}