use stackable_druid_crd::DruidCluster;
use stackable_operator::crd::CustomResourceExt;
use stackable_operator::error::OperatorResult;

fn main() -> OperatorResult<()> {
    built::write_built_file().expect("Failed to acquire build-time information");

    DruidCluster::write_yaml_schema("../../deploy/crd/druidcluster.crd.yaml")?;

    Ok(())
}
