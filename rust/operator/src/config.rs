use stackable_druid_crd::DruidRole;
use std::collections::BTreeMap;


pub fn get_jvm_config(role: &DruidRole) -> String {
    let common_props = "
    -server
    -Duser.timezone=UTC
    -Dfile.encoding=UTF-8
    -Djava.io.tmpdir=/tmp/druid
    -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
    -XX:+UseG1GC
    -XX:+ExitOnOutOfMemoryError
    ";

    match role {
        DruidRole::Broker => common_props.to_string() + "
            -Xms512m
            -Xmx512m
            -XX:MaxDirectMemorySize=400m
        ",
        DruidRole::Coordinator => common_props.to_string() + "
            -Xms256m
            -Xmx256m
            -Dderby.stream.error.file=/var/druid/derby.log
        ",
        DruidRole::Historical => common_props.to_string() + "
            -Xms512m
            -Xmx512m
            -XX:MaxDirectMemorySize=400m
        ",
        DruidRole::MiddleManager => common_props.to_string() + "
            -Xms64m
            -Xmx64m
        ",
        DruidRole::Router => common_props.to_string() + "
            -Xms128m
            -Xmx128m
            -XX:MaxDirectMemorySize=128m
        ",
    }
}

pub fn get_runtime_properties(role: &DruidRole, other_props: &BTreeMap<String, Option<String>>) -> String {
    let common = "
    druid.host=localhost
    druid.extensions.loadList=[\"druid-hdfs-storage\", \"druid-kafka-indexing-service\", \"druid-datasketches\"]
    druid.startup.logging.logProperties=true
    druid.zk.service.host=localhost
    druid.zk.paths.base=/druid
    druid.storage.type=local
    druid.storage.storageDirectory=var/druid/segments
    druid.indexer.logs.type=file
    druid.indexer.logs.directory=var/druid/indexing-logs
    druid.selectors.indexing.serviceName=druid/overlord
    druid.selectors.coordinator.serviceName=druid/coordinator
    druid.monitoring.monitors=[\"org.apache.druid.java.util.metrics.JvmMonitor\"]
    druid.emitter=noop
    druid.emitter.logging.logLevel=info
    druid.indexing.doubleStorage=double
    druid.server.hiddenProperties=[\"druid.s3.accessKey\",\"druid.s3.secretKey\",\"druid.metadata.storage.connector.password\"]
    druid.sql.enable=true
    druid.lookup.enableLookupSyncOnStartup=false
    ";

    let role_specifics = match role {
        DruidRole::Broker => "
        druid.service=druid/broker

        # HTTP server settings
        druid.server.http.numThreads=6

        # HTTP client settings
        druid.broker.http.numConnections=5
        druid.broker.http.maxQueuedBytes=5MiB

        # Processing threads and buffers
        druid.processing.buffer.sizeBytes=50MiB
        druid.processing.numMergeBuffers=2
        druid.processing.numThreads=1
        druid.processing.tmpDir=var/druid/processing

        # Query cache disabled -- push down caching and merging instead
        druid.broker.cache.useCache=false
        druid.broker.cache.populateCache=false
        ",
        DruidRole::Coordinator => "
        druid.service=druid/coordinator

        druid.coordinator.startDelay=PT10S
        druid.coordinator.period=PT5S

        # Run the overlord service in the coordinator process
        druid.coordinator.asOverlord.enabled=true
        druid.coordinator.asOverlord.overlordService=druid/overlord

        druid.indexer.queue.startDelay=PT5S

        druid.indexer.runner.type=remote
        druid.indexer.storage.type=metadata
        ",
        DruidRole::Historical => "
        druid.service=druid/historical

        # HTTP server threads
        druid.server.http.numThreads=6

        # Processing threads and buffers
        druid.processing.buffer.sizeBytes=50MiB
        druid.processing.numMergeBuffers=2
        druid.processing.numThreads=1
        druid.processing.tmpDir=var/druid/processing

        # Segment storage
        druid.segmentCache.locations=[{\"path\":\"var/druid/segment-cache\",\"maxSize\":\"300g\"}]

        # Query cache
        druid.historical.cache.useCache=true
        druid.historical.cache.populateCache=true
        druid.cache.type=caffeine
        druid.cache.sizeInBytes=50MiB
        ",
        DruidRole::MiddleManager => "
        druid.service=druid/middleManager

        # Number of tasks per middleManager
        druid.worker.capacity=2

        # Task launch parameters
        druid.indexer.runner.javaOpts=-server -Xms256m -Xmx256m -XX:MaxDirectMemorySize=300m -Duser.timezone=UTC -Dfile.encoding=UTF-8 -XX:+ExitOnOutOfMemoryError -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager
        druid.indexer.task.baseTaskDir=var/druid/task

        # HTTP server threads
        druid.server.http.numThreads=6

        # Processing threads and buffers on Peons
        druid.indexer.fork.property.druid.processing.numMergeBuffers=2
        druid.indexer.fork.property.druid.processing.buffer.sizeBytes=25MiB
        druid.indexer.fork.property.druid.processing.numThreads=1

        # Hadoop indexing
        druid.indexer.task.hadoopWorkingPath=var/druid/hadoop-tmp
        ",
        DruidRole::Router => "
        druid.service=druid/router

        # HTTP proxy
        druid.router.http.numConnections=25
        druid.router.http.readTimeout=PT5M
        druid.router.http.numMaxThreads=50
        druid.server.http.numThreads=50

        # Service discovery
        druid.router.defaultBrokerServiceName=druid/broker
        druid.router.coordinatorServiceName=druid/coordinator

        # Management proxy to coordinator / overlord: required for unified web console.
        druid.router.managementProxy.enabled=true
        ",
    };
    let others = product_config::writer::to_java_properties_string(other_props.iter());
    format!("{}\n{}\n{}", common, role_specifics, others.unwrap())
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
".to_string()
}