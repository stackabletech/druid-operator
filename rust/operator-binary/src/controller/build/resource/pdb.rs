use std::str::FromStr;

use stackable_operator::{
    commons::pdb::PdbConfig,
    k8s_openapi::api::policy::v1::PodDisruptionBudget,
    v2::{builder::pdb::pod_disruption_budget_builder_with_role, types::operator::RoleName},
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
        &RoleName::from_str(&role.to_string()).expect("a DruidRole is a valid role name"),
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
