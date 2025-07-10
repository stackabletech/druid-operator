// TODO: Look into how to properly resolve `clippy::large_enum_variant`.
// This will need changes in our and upstream error types.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use clap::Parser;
use druid_controller::{DRUID_CONTROLLER_NAME, FULL_CONTROLLER_NAME};
use futures::StreamExt;
use stackable_operator::{
    YamlSchema,
    cli::{Command, ProductOperatorRun},
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        ResourceExt,
        core::DeserializeGuard,
        runtime::{
            Controller,
            events::{Recorder, Reporter},
            reflector::ObjectRef,
            watcher,
        },
    },
    logging::controller::report_controller_reconciled,
    shared::yaml::SerializeOptions,
    telemetry::Tracing,
};

use crate::crd::{DruidCluster, DruidClusterVersion, OPERATOR_NAME, v1alpha1};

mod authentication;
mod config;
mod crd;
mod discovery;
mod druid_controller;
mod extensions;
mod internal_secret;
mod listener;
mod operations;
mod product_logging;
mod service;

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
        Command::Crd => DruidCluster::merged_crd(DruidClusterVersion::V1Alpha1)?
            .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?,
        Command::Run(ProductOperatorRun {
            product_config,
            watch_namespace,
            telemetry_arguments,
            cluster_info_opts,
        }) => {
            // NOTE (@NickLarsenNZ): Before stackable-telemetry was used:
            // - The console log level was set by `DRUID_OPERATOR_LOG`, and is now `CONSOLE_LOG` (when using Tracing::pre_configured).
            // - The file log level was set by `DRUID_OPERATOR_LOG`, and is now set via `FILE_LOG` (when using Tracing::pre_configured).
            // - The file log directory was set by `DRUID_OPERATOR_LOG_DIRECTORY`, and is now set by `ROLLING_LOGS_DIR` (or via `--rolling-logs <DIRECTORY>`).
            let _tracing_guard =
                Tracing::pre_configured(built_info::PKG_NAME, telemetry_arguments).init()?;

            tracing::info!(
                built_info.pkg_version = built_info::PKG_VERSION,
                built_info.git_version = built_info::GIT_VERSION,
                built_info.target = built_info::TARGET,
                built_info.built_time_utc = built_info::BUILT_TIME_UTC,
                built_info.rustc_version = built_info::RUSTC_VERSION,
                "Starting {description}",
                description = built_info::PKG_DESCRIPTION
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

            let druid_controller = Controller::new(
                watch_namespace.get_api::<DeserializeGuard<v1alpha1::DruidCluster>>(&client),
                watcher::Config::default(),
            );
            let config_map_store = druid_controller.store();
            druid_controller
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
                .watches(
                    watch_namespace.get_api::<DeserializeGuard<ConfigMap>>(&client),
                    watcher::Config::default(),
                    move |config_map| {
                        config_map_store
                            .state()
                            .into_iter()
                            .filter(move |druid| references_config_map(druid, &config_map))
                            .map(|druid| ObjectRef::from_obj(&*druid))
                    },
                )
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

fn references_config_map(
    druid: &DeserializeGuard<v1alpha1::DruidCluster>,
    config_map: &DeserializeGuard<ConfigMap>,
) -> bool {
    let Ok(druid) = &druid.0 else {
        return false;
    };

    druid.spec.cluster_config.zookeeper_config_map_name == config_map.name_any()
        || match &druid.spec.cluster_config.authorization {
            Some(druid_authorization) => {
                druid_authorization.opa.config_map_name == config_map.name_any()
            }
            None => false,
        }
        || match &druid.spec.cluster_config.deep_storage {
            crd::DeepStorageSpec::Hdfs(hdfs_spec) => {
                hdfs_spec.config_map_name == config_map.name_any()
            }
            _ => false,
        }
}
