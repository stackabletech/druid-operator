mod apply;
mod build;
mod fetch;
mod types;

use crate::controller::{
    apply::handle_cluster_resources, build::create_appliable_cluster_resources,
    fetch::fetch_additional_data,
};

use snafu::{ResultExt, Snafu};
use stackable_druid_crd::DruidCluster;

use stackable_operator::{
    kube::runtime::controller::Action, logging::controller::ReconcilerError,
    product_config::ProductConfigManager,
};
use std::{sync::Arc, time::Duration};
use strum::{EnumDiscriminants, IntoStaticStr};

pub const CONTROLLER_NAME: &str = "druidcluster";

const DOCKER_IMAGE_BASE_NAME: &str = "druid";

pub struct Ctx {
    pub client: stackable_operator::client::Client,
    pub product_config: ProductConfigManager,
}

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to fetch additional information"))]
    Fetch { source: fetch::Error },
    #[snafu(display("failed to build cluster resources"))]
    Build { source: build::Error },
    #[snafu(display("failed to apply cluster resources"))]
    Apply { source: apply::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }
}

pub async fn reconcile_druid(druid: Arc<DruidCluster>, ctx: Arc<Ctx>) -> Result<Action> {
    tracing::info!("Starting reconcile");

    let fetched_additional_data = fetch_additional_data(&druid, &ctx.client)
        .await
        .context(FetchSnafu)?;
    let built_cluster_resources =
        build_cluster_resources(druid.clone(), fetched_additional_data, &ctx.product_config)
            .context(BuildSnafu)?;

    apply_cluster_resources(&ctx.client, &druid, built_cluster_resources)
        .await
        .context(ApplySnafu)
}

pub fn error_policy(_obj: Arc<DruidCluster>, _error: &Error, _ctx: Arc<Ctx>) -> Action {
    Action::requeue(Duration::from_secs(5))
}
