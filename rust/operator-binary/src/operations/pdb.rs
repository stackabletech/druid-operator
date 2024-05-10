use snafu::{ResultExt, Snafu};
use stackable_druid_crd::{DruidCluster, DruidRole, APP_NAME, OPERATOR_NAME};
use stackable_operator::{
    builder::pdb::PodDisruptionBudgetBuilder, client::Client, cluster_resources::ClusterResources,
    commons::pdb::PdbConfig, kube::ResourceExt,
};

use crate::druid_controller::DRUID_CONTROLLER_NAME;

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Cannot create PodDisruptionBudget for role [{role}]"))]
    CreatePdb {
        source: stackable_operator::builder::pdb::Error,
        role: String,
    },
    #[snafu(display("Cannot apply PodDisruptionBudget [{name}]"))]
    ApplyPdb {
        source: stackable_operator::cluster_resources::Error,
        name: String,
    },
}

pub async fn add_pdbs(
    pdb: &PdbConfig,
    druid: &DruidCluster,
    role: &DruidRole,
    client: &Client,
    cluster_resources: &mut ClusterResources,
) -> Result<(), Error> {
    if !pdb.enabled {
        return Ok(());
    }
    let max_unavailable = pdb.max_unavailable.unwrap_or(match role {
        DruidRole::Broker => max_unavailable_brokers(),
        DruidRole::Coordinator => max_unavailable_coordinators(),
        DruidRole::Historical => max_unavailable_historicals(),
        DruidRole::MiddleManager => max_unavailable_middle_managers(),
        DruidRole::Router => max_unavailable_routers(),
    });
    let pdb = PodDisruptionBudgetBuilder::new_with_role(
        druid,
        APP_NAME,
        &role.to_string(),
        OPERATOR_NAME,
        DRUID_CONTROLLER_NAME,
    )
    .with_context(|_| CreatePdbSnafu {
        role: role.to_string(),
    })?
    .with_max_unavailable(max_unavailable)
    .build();
    let pdb_name = pdb.name_any();
    cluster_resources
        .add(client, pdb)
        .await
        .with_context(|_| ApplyPdbSnafu { name: pdb_name })?;

    Ok(())
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
