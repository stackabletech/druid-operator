use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_druid_crd::security::DruidTlsSecurity;
use stackable_druid_crd::DruidRole;
use stackable_operator::k8s_openapi::api::core::v1::{ExecAction, LifecycleHandler};
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder},
    time::Duration,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to set terminationGracePeriod"))]
    SetTerminationGracePeriod {
        source: stackable_operator::builder::pod::Error,
    },
}

pub fn add_graceful_shutdown_config(
    role: &DruidRole,
    tls_security: &DruidTlsSecurity,
    graceful_shutdown_timeout: Option<Duration>,
    pod_builder: &mut PodBuilder,
    druid_builder: &mut ContainerBuilder,
) -> Result<(), Error> {
    // This must be always set by the merge mechanism, as we provide a default value,
    // users can not disable graceful shutdown.
    if let Some(termination_grace_period) = graceful_shutdown_timeout {
        match role {
            DruidRole::Coordinator
            | DruidRole::Broker
            | DruidRole::Historical
            | DruidRole::Router => {
                pod_builder
                    .termination_grace_period(&termination_grace_period)
                    .context(SetTerminationGracePeriodSnafu)?;
            }
            DruidRole::MiddleManager => {
                pod_builder
                    .termination_grace_period(&termination_grace_period)
                    .context(SetTerminationGracePeriodSnafu)?;

                let (protocol, port) = if tls_security.tls_enabled() {
                    ("https", role.get_https_port())
                } else {
                    ("http", role.get_http_port())
                };

                let middle_manager_host = format!("{protocol}://127.0.0.1:{port}");
                let debug_timestamp = "$(date --utc +%FT%T,%3N) INFO";
                let sleep_interval = 2;

                druid_builder.lifecycle_pre_stop(LifecycleHandler {
                    exec: Some(ExecAction {
                        command: Some(vec![
                            "/bin/bash".to_string(),
                            "-x".to_string(),
                            "-euo".to_string(),
                            "pipefail".to_string(),
                            "-c".to_string(),
                            // See: https://druid.apache.org/docs/latest/operations/rolling-updates/#rolling-restart-graceful-termination-based
                            formatdoc!(r#"
                                response=$(curl -v --fail --insecure -X POST {middle_manager_host}/druid/worker/v1/disable)
                                echo "{debug_timestamp} Disable middle manager to stop overlord from sending tasks: $response" >> /proc/1/fd/1 2>&1
                                
                                end_time_seconds=$(date --date="+{termination_grace_period_seconds} seconds" '+%s')
                                while :
                                do
                                  current_time_seconds=$(date '+%s')
                                  echo "{debug_timestamp} Check if termination grace period ({termination_grace_period_seconds} seconds) is reached..." >> /proc/1/fd/1 2>&1
                                  if [ $current_time_seconds -gt $end_time_seconds ]
                                  then
                                    echo "{debug_timestamp} The termination grace period is reached!" >> /proc/1/fd/1 2>&1
                                    break
                                  fi
                                  
                                  tasks=$(curl -v --fail --insecure -X GET {middle_manager_host}/druid/worker/v1/tasks)
                                  echo "{debug_timestamp} Check if all tasks are finished... $tasks" >> /proc/1/fd/1 2>&1
                                  if [ $tasks = "[]" ]
                                  then
                                    echo "{debug_timestamp} All tasks finished!" >> /proc/1/fd/1 2>&1
                                     break
                                  fi
                                  
                                  echo "{debug_timestamp} Sleeping {sleep_interval} seconds..."
                                  echo ""
                                  sleep {sleep_interval}
                                done
                                echo "{debug_timestamp} All done!"
                                "#,
                                termination_grace_period_seconds = termination_grace_period.as_secs()
                            ),
                        ]),
                    }),
                    ..Default::default()
                });
            }
        }
    }

    Ok(())
}
