use indoc::formatdoc;
use stackable_operator::{
    k8s_openapi::api::core::v1::{ExecAction, LifecycleHandler},
    shared::time::Duration,
};

use crate::crd::{DruidRole, security::DruidTlsSecurity};

/// The `druid` container's pre-stop hook that drains a MiddleManager before it stops: the hook
/// disables the MiddleManager so the Overlord sends it no new tasks, then waits until the running
/// tasks finish or the termination grace period elapses.
///
/// See: <https://druid.apache.org/docs/latest/operations/rolling-updates/#rolling-restart-graceful-termination-based>
///
/// The role is read for the port the hook talks to. The `DRUID_PID` file is written by
/// [`DruidRole::main_container_start_command`].
pub fn drain_pre_stop_hook(
    role: &DruidRole,
    tls_security: &DruidTlsSecurity,
    termination_grace_period: &Duration,
) -> LifecycleHandler {
    let (protocol, port) = if tls_security.tls_enabled() {
        ("https", role.get_https_port())
    } else {
        ("http", role.get_http_port())
    };

    let middle_manager_host = format!("{protocol}://127.0.0.1:{port}");
    let debug_message = "$(date --utc +%FT%T,%3N) INFO [stackable_lifecycle_pre_stop] -";
    let sleep_interval = 2;

    LifecycleHandler {
        exec: Some(ExecAction {
            command: Some(vec![
                "/bin/bash".to_string(),
                "-x".to_string(),
                "-euo".to_string(),
                "pipefail".to_string(),
                "-c".to_string(),
                formatdoc!(
                    r#"
                    log() {{
                      echo "{debug_message} $1" >> /proc/$(cat /tmp/DRUID_PID)/fd/1 2>&1
                    }}

                    response=$(curl -v --fail --insecure -X POST {middle_manager_host}/druid/worker/v1/disable)
                    log "Disable middle manager to stop overlord from sending tasks: $response"

                    end_time_seconds=$(date --date="+{termination_grace_period_seconds} seconds" '+%s')
                    while :
                    do
                      current_time_seconds=$(date '+%s')
                      log "Check if termination grace period ({termination_grace_period_seconds} seconds) is reached..."
                      if [ $current_time_seconds -gt $end_time_seconds ]
                      then
                        log "The termination grace period is reached!"
                        break
                      fi

                      tasks=$(curl -v --fail --insecure -X GET {middle_manager_host}/druid/worker/v1/tasks)
                      log "Check if all tasks are finished... Running: $tasks"
                      if [ $tasks = "[]" ]
                      then
                        log "All tasks finished!"
                         break
                      fi

                      log "Sleeping {sleep_interval} seconds..."
                      log ""
                      sleep {sleep_interval}
                    done
                    log "All done!"
                    "#,
                    termination_grace_period_seconds = termination_grace_period.as_secs()
                ),
            ]),
        }),
        ..Default::default()
    }
}
