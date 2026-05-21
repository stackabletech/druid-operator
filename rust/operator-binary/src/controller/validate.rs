//! The validate step in the DruidCluster controller
//!
//! Synchronously validates inputs that don't require a Kubernetes client. Produces
//! [`ValidatedInputs`], consumed by the rest of `reconcile_druid`.

use product_config::ProductConfigManager;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    commons::product_image_selection::{self, ResolvedProductImage},
    product_config_utils::{
        ValidatedRoleConfigByPropertyKind, transform_all_roles_to_config,
        validate_all_roles_and_groups_config,
    },
};

use crate::{
    authentication::DruidAuthenticationConfig,
    controller::dereference::DereferencedObjects,
    crd::{security::DruidTlsSecurity, v1alpha1},
};

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("failed to resolve product image"))]
    ResolveProductImage {
        source: product_image_selection::Error,
    },

    #[snafu(display("invalid authentication configuration"))]
    InvalidDruidAuthenticationConfig {
        source: crate::authentication::Error,
    },

    #[snafu(display("failed to transform configs"))]
    ProductConfigTransform {
        source: stackable_operator::product_config_utils::Error,
    },

    #[snafu(display("invalid product configuration"))]
    InvalidProductConfig {
        source: stackable_operator::product_config_utils::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Synchronous inputs the rest of `reconcile_druid` needs after dereferencing.
pub struct ValidatedInputs {
    pub resolved_product_image: ResolvedProductImage,
    pub druid_tls_security: DruidTlsSecurity,
    pub druid_auth_config: Option<DruidAuthenticationConfig>,
    pub validated_role_config: ValidatedRoleConfigByPropertyKind,
}

/// Validates the cluster spec and the dereferenced inputs.
pub fn validate(
    druid: &v1alpha1::DruidCluster,
    dereferenced_objects: &DereferencedObjects,
    operator_environment: &OperatorEnvironmentOptions,
    product_config: &ProductConfigManager,
) -> Result<ValidatedInputs> {
    let resolved_product_image = druid
        .spec
        .image
        .resolve(
            super::CONTAINER_IMAGE_BASE_NAME,
            &operator_environment.image_repository,
            crate::built_info::PKG_VERSION,
        )
        .context(ResolveProductImageSnafu)?;

    let druid_tls_security = DruidTlsSecurity::new_from_druid_cluster(
        druid,
        &dereferenced_objects.resolved_authentication_classes,
    );

    let druid_auth_config = DruidAuthenticationConfig::try_from(
        dereferenced_objects.resolved_authentication_classes.clone(),
    )
    .context(InvalidDruidAuthenticationConfigSnafu)?;

    let role_config = transform_all_roles_to_config(druid, &druid.build_role_properties())
        .context(ProductConfigTransformSnafu)?;
    let validated_role_config = validate_all_roles_and_groups_config(
        &resolved_product_image.product_version,
        &role_config,
        product_config,
        false,
        false,
    )
    .context(InvalidProductConfigSnafu)?;

    Ok(ValidatedInputs {
        resolved_product_image,
        druid_tls_security,
        druid_auth_config,
        validated_role_config,
    })
}
