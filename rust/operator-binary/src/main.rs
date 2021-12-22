mod config;
mod druid_controller;
mod utils;

use futures::{compat::Future01CompatExt, StreamExt};
use stackable_druid_crd::DruidCluster;
use stackable_operator::{
    cli::Command,
    k8s_openapi::api::{
        apps::v1::StatefulSet,
        core::v1::{ConfigMap, Service},
    },
    kube::{
        api::{DynamicObject, ListParams},
        runtime::{
            controller::{Context, ReconcilerAction},
            reflector::ObjectRef,
            Controller,
        },
        CustomResourceExt, Resource,
    },
};
use structopt::StructOpt;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const APP_NAME: &str = "druid";
pub const APP_PORT: u16 = 2181;

#[derive(StructOpt)]
#[structopt(about = built_info::PKG_DESCRIPTION, author = stackable_operator::cli::AUTHOR)]
struct Opts {
    #[structopt(subcommand)]
    cmd: Command,
}

/// Erases the concrete types of the controller result, so that we can merge the streams of multiple controllers for different resources.
///
/// In particular, we convert `ObjectRef<K>` into `ObjectRef<DynamicObject>` (which carries `K`'s metadata at runtime instead), and
/// `E` into the trait object `anyhow::Error`.
fn erase_controller_result_type<K: Resource, E: std::error::Error + Send + Sync + 'static>(
    res: Result<(ObjectRef<K>, ReconcilerAction), E>,
) -> anyhow::Result<(ObjectRef<DynamicObject>, ReconcilerAction)> {
    let (obj_ref, action) = res?;
    Ok((obj_ref.erase(), action))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stackable_operator::logging::initialize_logging("DRUID_OPERATOR_LOG");
    // tokio-zookeeper depends on Tokio 0.1
    let tokio01_runtime = tokio01::runtime::Runtime::new()?;

    let opts = Opts::from_args();
    match opts.cmd {
        Command::Crd => println!("{}", serde_yaml::to_string(&DruidCluster::crd())?),
        Command::Run { product_config } => {
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
            let druid_controller_builder =
                Controller::new(client.get_all_api::<DruidCluster>(), ListParams::default());
            let druid_controller = druid_controller_builder
                .owns(client.get_all_api::<Service>(), ListParams::default())
                .owns(client.get_all_api::<StatefulSet>(), ListParams::default())
                .owns(client.get_all_api::<ConfigMap>(), ListParams::default())
                .run(
                    druid_controller::reconcile_druid,
                    druid_controller::error_policy,
                    Context::new(druid_controller::Ctx {
                        client: client.clone(),
                        product_config,
                    }),
                );
            druid_controller
                .map(erase_controller_result_type)
                .for_each(|res| async {
                    match res {
                        Ok((obj, _)) => tracing::info!(object = %obj, "Reconciled object"),
                        Err(err) => {
                            tracing::error!(
                                error = &*err as &dyn std::error::Error,
                                "Failed to reconcile object",
                            )
                        }
                    }
                })
                .await;
        }
    }

    tokio01_runtime.shutdown_now().compat().await.unwrap();
    Ok(())
}
