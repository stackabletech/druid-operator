use indoc::formatdoc;
use stackable_druid_crd::{DruidRole, STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD};

pub fn get_jvm_config(role: &DruidRole) -> String {
    let common_config = formatdoc! {"
      -server
      -Duser.timezone=UTC
      -Dfile.encoding=UTF-8
      -Djava.io.tmpdir=/tmp
      -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
      -XX:+UseG1GC
      -XX:+ExitOnOutOfMemoryError
      -Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}
      -Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}
      -Djavax.net.ssl.trustStoreType=pkcs12"};

    match role {
        DruidRole::Broker => {
            formatdoc! {"
              {common_config}
              -Xms512m
              -Xmx512m
              -XX:MaxDirectMemorySize=400m
            "}
        }
        DruidRole::Coordinator => {
            formatdoc! {"
              {common_config}
              -Xms256m
              -Xmx256m
              -Dderby.stream.error.file=/stackable/var/druid/derby.log
            "}
        }
        DruidRole::Historical => {
            formatdoc! {"
              {common_config}
              -Xms512m
              -Xmx512m
              -XX:MaxDirectMemorySize=400m
            "}
        }
        DruidRole::MiddleManager => {
            formatdoc! {"
              {common_config}
              -Xms64m
              -Xmx64m
            "}
        }
        DruidRole::Router => {
            formatdoc! {"
              {common_config}
              -Xms128m
              -Xmx128m
              -XX:MaxDirectMemorySize=128m
            "}
        }
    }
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
