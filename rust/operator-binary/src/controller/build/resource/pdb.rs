use stackable_operator::{
    commons::pdb::PdbConfig, k8s_openapi::api::policy::v1::PodDisruptionBudget,
    v2::builder::pdb::pod_disruption_budget_builder_with_role,
};

use crate::{
    controller::{controller_name, operator_name, product_name, validate::ValidatedCluster},
    crd::DruidRole,
};

/// Builds the [`PodDisruptionBudget`] for the given `role`, or `None` if PDBs are disabled.
pub fn build_pdb(
    pdb: &PdbConfig,
    cluster: &ValidatedCluster,
    role: &DruidRole,
) -> Option<PodDisruptionBudget> {
    if !pdb.enabled {
        return None;
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        DruidRole::Broker => max_unavailable_brokers(),
        DruidRole::Coordinator => max_unavailable_coordinators(),
        DruidRole::Historical => max_unavailable_historicals(),
        DruidRole::MiddleManager => max_unavailable_middle_managers(),
        DruidRole::Router => max_unavailable_routers(),
    });
    let pdb = pod_disruption_budget_builder_with_role(
        cluster,
        &product_name(),
        &role.to_role_name(),
        &operator_name(),
        &controller_name(),
    )
    .with_max_unavailable(max_unavailable)
    .build();

    Some(pdb)
}

fn max_unavailable_brokers() -> u16 {
    1
}

fn max_unavailable_coordinators() -> u16 {
    1
}

fn max_unavailable_historicals() -> u16 {
    1
}

fn max_unavailable_middle_managers() -> u16 {
    1
}

fn max_unavailable_routers() -> u16 {
    1
}

#[cfg(test)]
mod tests {
    use stackable_operator::{
        commons::pdb::PdbConfig, k8s_openapi::apimachinery::pkg::util::intstr::IntOrString,
    };

    use super::*;
    use crate::controller::validate::test_support::{
        MINIMAL_DRUID_YAML, druid_from_yaml, validated_cluster,
    };

    fn cluster() -> ValidatedCluster {
        validated_cluster(&druid_from_yaml(MINIMAL_DRUID_YAML))
    }

    #[test]
    fn disabled_pdb_returns_none() {
        let pdb = PdbConfig {
            enabled: false,
            max_unavailable: None,
        };
        assert!(build_pdb(&pdb, &cluster(), &DruidRole::Broker).is_none());
    }

    #[test]
    fn enabled_pdb_uses_role_default() {
        let pdb = PdbConfig {
            enabled: true,
            max_unavailable: None,
        };
        let built = build_pdb(&pdb, &cluster(), &DruidRole::Broker).expect("a PDB is built");
        assert_eq!(
            built.spec.and_then(|spec| spec.max_unavailable),
            Some(IntOrString::Int(1))
        );
    }

    #[test]
    fn enabled_pdb_respects_explicit_max_unavailable() {
        let pdb = PdbConfig {
            enabled: true,
            max_unavailable: Some(3),
        };
        let built = build_pdb(&pdb, &cluster(), &DruidRole::Broker).expect("a PDB is built");
        assert_eq!(
            built.spec.and_then(|spec| spec.max_unavailable),
            Some(IntOrString::Int(3))
        );
    }
}
