mod authentication;
mod config;
mod discovery;
mod druid_controller;
mod extensions;
mod internal_secret;
mod operations;
mod product_logging;

use std::sync::Arc;

use crate::druid_controller::DRUID_CONTROLLER_NAME;
use clap::{crate_description, crate_version, Parser};
use futures::StreamExt;
use stackable_druid_crd::{DruidCluster, APP_NAME, OPERATOR_NAME};
use stackable_operator::CustomResourceExt;
use stackable_operator::{
    cli::Command,
    cli::ProductOperatorRun,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::core::DeserializeGuard,
    kube::runtime::{watcher, Controller},
    logging::controller::report_controller_reconciled,
};

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser)]
#[clap(about, author)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => DruidCluster::print_yaml_schema(built_info::PKG_VERSION)?,
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            tracing_target,
        }) => {
            stackable_operator::logging::initialize_logging(
                "DRUID_OPERATOR_LOG",
                APP_NAME,
                tracing_target,
            );
            stackable_operator::utils::print_startup_string(
                crate_description!(),
                crate_version!(),
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let product_config = product_config.load(&[
                "deploy/config-spec/properties.yaml",
                "/etc/stackable/druid-operator/config-spec/properties.yaml",
            ])?;
            let client =
                stackable_operator::client::create_client(Some(OPERATOR_NAME.to_string())).await?;

            Controller::new(
                watch_namespace.get_api::<DeserializeGuard<DruidCluster>>(&client),
                watcher::Config::default(),
            )
            .owns(
                watch_namespace.get_api::<Service>(&client),
                watcher::Config::default(),
            )
            .owns(
                watch_namespace.get_api::<StatefulSet>(&client),
                watcher::Config::default(),
            )
            .owns(
                watch_namespace.get_api::<ConfigMap>(&client),
                watcher::Config::default(),
            )
            .shutdown_on_signal()
            .run(
                druid_controller::reconcile_druid,
                druid_controller::error_policy,
                Arc::new(druid_controller::Ctx {
                    client: client.clone(),
                    product_config,
                }),
            )
            .map(|res| {
                report_controller_reconciled(
                    &client,
                    &format!("{DRUID_CONTROLLER_NAME}.{OPERATOR_NAME}"),
                    &res,
                )
            })
            .collect::<()>()
            .await;
        }
    }

    Ok(())
}
