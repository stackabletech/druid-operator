mod config;
mod discovery;
mod druid_controller;

use clap::Parser;
use futures::StreamExt;
use stackable_druid_crd::DruidCluster;
use stackable_operator::{
    cli::Command,
    cli::ProductOperatorRun,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        api::ListParams,
        runtime::{controller::Context, Controller},
        CustomResourceExt,
    },
    logging::controller::report_controller_reconciled,
};

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser)]
#[clap(about = built_info::PKG_DESCRIPTION, author = stackable_operator::cli::AUTHOR)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stackable_operator::logging::initialize_logging("DRUID_OPERATOR_LOG");

    let opts = Opts::parse();
    match opts.cmd {
        Command::Crd => println!("{}", serde_yaml::to_string(&DruidCluster::crd())?),
        Command::Run(ProductOperatorRun { product_config }) => {
            stackable_operator::utils::print_startup_string(
                built_info::PKG_DESCRIPTION,
                built_info::PKG_VERSION,
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
                stackable_operator::client::create_client(Some("druid.stackable.tech".to_string()))
                    .await?;

            Controller::new(client.get_all_api::<DruidCluster>(), ListParams::default())
                .owns(client.get_all_api::<Service>(), ListParams::default())
                .owns(client.get_all_api::<StatefulSet>(), ListParams::default())
                .owns(client.get_all_api::<ConfigMap>(), ListParams::default())
                .shutdown_on_signal()
                .run(
                    druid_controller::reconcile_druid,
                    druid_controller::error_policy,
                    Context::new(druid_controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                )
                .map(|res| {
                    report_controller_reconciled(
                        &client,
                        "druidclusters.druid.stackable.tech",
                        &res,
                    )
                })
                .collect::<()>()
                .await;
        }
    }

    Ok(())
}
