use std::sync::Arc;

use clap::{crate_description, crate_version, Parser};
use druid_controller::{DRUID_CONTROLLER_NAME, FULL_CONTROLLER_NAME};
use futures::StreamExt;
use stackable_operator::{
    cli::{Command, ProductOperatorRun},
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        core::DeserializeGuard,
        runtime::{
            events::{Recorder, Reporter},
            watcher, Controller,
        },
    },
    logging::controller::report_controller_reconciled,
    shared::yaml::SerializeOptions,
    YamlSchema,
};

use crate::crd::{v1alpha1, DruidCluster, APP_NAME, OPERATOR_NAME};

mod authentication;
mod config;
mod crd;
mod discovery;
mod druid_controller;
mod extensions;
mod internal_secret;
mod operations;
mod product_logging;

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
        Command::Crd => DruidCluster::merged_crd(DruidCluster::V1Alpha1)?
            .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?,
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            tracing_target,
            cluster_info_opts,
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
            let client = stackable_operator::client::initialize_operator(
                Some(OPERATOR_NAME.to_string()),
                &cluster_info_opts,
            )
            .await?;

            let event_recorder = Arc::new(Recorder::new(
                client.as_kube_client(),
                Reporter {
                    controller: FULL_CONTROLLER_NAME.to_string(),
                    instance: None,
                },
            ));

            Controller::new(
                watch_namespace.get_api::<DeserializeGuard<v1alpha1::DruidCluster>>(&client),
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
            // We can let the reporting happen in the background
            .for_each_concurrent(
                16, // concurrency limit
                |result| {
                    // The event_recorder needs to be shared across all invocations, so that
                    // events are correctly aggregated
                    let event_recorder = event_recorder.clone();
                    async move {
                        report_controller_reconciled(
                            &event_recorder,
                            FULL_CONTROLLER_NAME,
                            &result,
                        )
                        .await;
                    }
                },
            )
            .await;
        }
    }

    Ok(())
}
