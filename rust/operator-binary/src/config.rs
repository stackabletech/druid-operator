use crate::druid_controller::{Error, FormatMemoryStringForJavaSnafu};
use indoc::formatdoc;
use snafu::ResultExt;
use stackable_druid_crd::{DruidRole, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD};
use stackable_operator::memory::MemoryQuantity;

pub fn get_jvm_config(
    role: &DruidRole,
    heap: MemoryQuantity,
    direct_memory: Option<MemoryQuantity>,
) -> Result<String, Error> {
    let heap_str = heap
        .format_for_java()
        .context(FormatMemoryStringForJavaSnafu)?;
    let direct_memory_str = if let Some(m) = direct_memory {
        Some(
            m.format_for_java()
                .context(FormatMemoryStringForJavaSnafu)?,
        )
    } else {
        None
    };
    let mut config = formatdoc! {"
        -server
        -Duser.timezone=UTC
        -Dfile.encoding=UTF-8
        -Djava.io.tmpdir=/tmp
        -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
        -XX:+UseG1GC
        -XX:+ExitOnOutOfMemoryError
        -Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}
        -Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}
        -Djavax.net.ssl.trustStoreType=pkcs12
        -Xms{heap_str}
        -Xmx{heap_str}"};

    if let Some(direct_memory) = direct_memory_str {
        config += &format!("\n-XX:MaxDirectMemorySize={direct_memory}");
    }

    if role == &DruidRole::Coordinator {
        config += "\n-Dderby.stream.error.file=/stackable/var/druid/derby.log";
    }
    Ok(config)
}

pub fn get_log4j_config(_role: &DruidRole) -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>
<Configuration status=\"WARN\">
  <Appenders>
    <Console name=\"Console\" target=\"SYSTEM_OUT\">
      <PatternLayout pattern=\"%d{ISO8601} %p [%t] %c - %m%n\"/>
    </Console>
  </Appenders>
  <Loggers>
    <Root level=\"info\">
      <AppenderRef ref=\"Console\"/>
    </Root>
    <Logger name=\"org.apache.druid.server.QueryLifecycle\" level=\"info\" additivity=\"false\">
      <Appender-ref ref=\"Console\"/>
    </Logger>
    <Logger name=\"org.apache.druid.server.coordinator\" level=\"info\" additivity=\"false\">
      <Appender-ref ref=\"Console\"/>
    </Logger>
    <Logger name=\"org.apache.druid.segment\" level=\"info\" additivity=\"false\">
      <Appender-ref ref=\"Console\"/>
    </Logger>
    <Logger name=\"org.apache.druid.initialization\" level=\"info\" additivity=\"false\">
      <Appender-ref ref=\"Console\"/>
    </Logger>
    <Logger name=\"org.skife.config\" level=\"warn\" additivity=\"false\">
      <Appender-ref ref=\"Console\"/>
    </Logger>
    <Logger name=\"com.sun.jersey.guice\" level=\"warn\" additivity=\"false\">
      <Appender-ref ref=\"Console\"/>
    </Logger>
  </Loggers>
</Configuration>
"
    .to_string()
}
