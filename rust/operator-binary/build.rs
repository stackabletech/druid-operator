use stackable_druid_crd::DruidCluster;
use stackable_operator::crd::CustomResourceExt;

fn main() -> Result<(), stackable_operator::error::Error> {
    built::write_built_file().expect("Failed to acquire build-time information");

    DruidCluster::write_yaml_schema("../../deploy/crd/druidcluster.crd.yaml")?;

    Ok(())
}
