//! Builder for `security.properties` (Druid's JVM security properties file).

use std::collections::BTreeMap;

const NETWORKADDRESS_CACHE_TTL: &str = "networkaddress.cache.ttl";
const NETWORKADDRESS_CACHE_NEGATIVE_TTL: &str = "networkaddress.cache.negative.ttl";

const DEFAULT_NETWORKADDRESS_CACHE_TTL: &str = "30";
const DEFAULT_NETWORKADDRESS_CACHE_NEGATIVE_TTL: &str = "0";

/// Build the `security.properties` key/value pairs (same defaults for all roles).
///
/// `overrides` are the user's merged (role <- rolegroup) `security.properties`
/// config overrides, as returned by `DruidConfigOverrides::get_key_value_overrides`.
/// Override values win.
pub fn build(overrides: &BTreeMap<String, Option<String>>) -> BTreeMap<String, Option<String>> {
    let mut props: BTreeMap<String, Option<String>> = BTreeMap::new();
    props.insert(
        NETWORKADDRESS_CACHE_TTL.to_string(),
        Some(DEFAULT_NETWORKADDRESS_CACHE_TTL.to_string()),
    );
    props.insert(
        NETWORKADDRESS_CACHE_NEGATIVE_TTL.to_string(),
        Some(DEFAULT_NETWORKADDRESS_CACHE_NEGATIVE_TTL.to_string()),
    );
    props.extend(overrides.iter().map(|(k, v)| (k.clone(), v.clone())));
    props
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values copied verbatim from tests/templates/kuttl/smoke/53-assert.yaml.j2
    // (security.properties block, identical for every role):
    //   networkaddress.cache.negative.ttl=0
    //   networkaddress.cache.ttl=30
    #[test]
    fn defaults_match_snapshot() {
        let props = build(&BTreeMap::new());
        assert_eq!(props["networkaddress.cache.ttl"], Some("30".to_string()));
        assert_eq!(
            props["networkaddress.cache.negative.ttl"],
            Some("0".to_string())
        );
        assert_eq!(props.len(), 2);
    }

    #[test]
    fn override_wins() {
        let ov = BTreeMap::from([(
            "networkaddress.cache.ttl".to_string(),
            Some("60".to_string()),
        )]);
        let props = build(&ov);
        assert_eq!(props["networkaddress.cache.ttl"], Some("60".to_string()));
    }
}
