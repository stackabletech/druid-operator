use indoc::formatdoc;
use snafu::{ResultExt, Snafu};
use stackable_operator::memory::MemoryQuantity;

use crate::crd::{
    DruidRole, JVM_SECURITY_PROPERTIES_FILE, LOG4J2_CONFIG, RW_CONFIG_DIRECTORY,
    STACKABLE_TRUST_STORE, STACKABLE_TRUST_STORE_PASSWORD,
};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display(
        "failed to format memory quantity '{value:?}' for Java. try increasing the memory limit"
    ))]
    FormatMemoryStringForJava {
        value: MemoryQuantity,
        source: stackable_operator::memory::Error,
    },
}

pub fn get_jvm_config(
    role: &DruidRole,
    heap: MemoryQuantity,
    direct_memory: Option<MemoryQuantity>,
) -> Result<String, Error> {
    let heap_str = heap
        .format_for_java()
        .with_context(|_| FormatMemoryStringForJavaSnafu { value: heap })?;
    let direct_memory_str = if let Some(m) = direct_memory {
        Some(
            m.format_for_java()
                .with_context(|_| FormatMemoryStringForJavaSnafu { value: m })?,
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
        -Dlog4j.configurationFile={RW_CONFIG_DIRECTORY}/{LOG4J2_CONFIG}
        -XX:+UseG1GC
        -XX:+ExitOnOutOfMemoryError
        -Djavax.net.ssl.trustStore={STACKABLE_TRUST_STORE}
        -Djavax.net.ssl.trustStorePassword={STACKABLE_TRUST_STORE_PASSWORD}
        -Djavax.net.ssl.trustStoreType=pkcs12
        -Xms{heap_str}
        -Xmx{heap_str}
        -Djava.security.properties={RW_CONFIG_DIRECTORY}/{JVM_SECURITY_PROPERTIES_FILE}"};

    if let Some(direct_memory) = direct_memory_str {
        config += &format!("\n-XX:MaxDirectMemorySize={direct_memory}");
    }

    if role == &DruidRole::Coordinator {
        config += "\n-Dderby.stream.error.file=/stackable/var/druid/derby.log";
    }
    Ok(config)
}
