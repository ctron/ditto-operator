use crate::{
    controller::{keycloak_url, KUBERNETES_LABEL_COMPONENT},
    crd::Ditto,
    data::{openapi_v2, ApiOptions},
};
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{ConfigMapVolumeSource, ServicePort, Volume, VolumeMount},
    },
    apimachinery::pkg::util::intstr::IntOrString,
};
use kube::ResourceExt;
use operator_framework::{
    install::{
        config::AppendString,
        container::{ApplyContainer, ApplyEnvironmentVariable, ApplyPort},
        meta::OwnedBy,
        Delete,
    },
    process::create_or_update,
    tracker::{ConfigTracker, Trackable},
    utils::UseOrCreate,
};
use serde_json::json;
use std::{collections::BTreeMap, ops::Deref};

pub struct SwaggerUi<'a>(pub &'a super::Context);

impl<'a> Deref for SwaggerUi<'a> {
    type Target = super::Context;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> SwaggerUi<'a> {
    pub async fn process(
        &self,
        ditto: &Ditto,
        nginx_tracker: &mut ConfigTracker,
    ) -> anyhow::Result<()> {
        let prefix = ditto.name();
        let namespace = ditto.namespace().expect("Missing namespace");

        if self.want_swagger(ditto) {
            create_or_update(
                &self.services,
                Some(&namespace),
                prefix.clone() + "-swaggerui",
                |mut service| {
                    service.owned_by_controller(ditto)?;
                    service.spec.use_or_create(|spec| {
                        // set labels

                        let mut labels = BTreeMap::new();
                        labels.extend(self.service_selector("swaggerui", ditto));
                        spec.selector = Some(labels);

                        // set ports
                        spec.ports = Some(vec![ServicePort {
                            port: 8080,
                            name: Some("http".into()),
                            target_port: Some(IntOrString::String("http".into())),
                            ..Default::default()
                        }]);
                    });

                    Ok::<_, anyhow::Error>(service)
                },
            )
            .await?;

            create_or_update(
                &self.configmaps,
                Some(&namespace),
                prefix.clone() + "-swaggerui-api",
                |mut cm| {
                    let keycloak = ditto.spec.keycloak.as_ref();
                    let openapi = ditto.spec.open_api.as_ref();
                    let oauth_auth_url = keycloak.map(|keycloak| keycloak_url(keycloak, "/auth"));

                    let options = ApiOptions {
                        server_label: openapi.and_then(|o| o.server_label.clone()),
                        oauth_auth_url,
                        oauth_label: keycloak.and_then(|k| k.label.clone()),
                        oauth_description: keycloak.and_then(|k| k.description.clone()),
                    };

                    cm.owned_by_controller(ditto)?;
                    cm.append_string("ditto-api-v2.yaml", openapi_v2(&options)?);
                    cm.track_with(nginx_tracker);

                    Ok::<_, anyhow::Error>(cm)
                },
            )
            .await?;

            create_or_update(
                &self.deployments,
                Some(&namespace),
                prefix.clone() + "-swaggerui",
                |obj| self.reconcile_swaggerui_deployment(&ditto, obj),
            )
            .await?;
        } else {
            self.services
                .delete_optionally(format!("{}-swaggerui", prefix), &Default::default())
                .await?;
            self.configmaps
                .delete_optionally(format!("{}-swaggerui-api", prefix), &Default::default())
                .await?;
            self.deployments
                .delete_optionally(format!("{}-swaggerui", prefix), &Default::default())
                .await?;
        }

        Ok(())
    }

    fn reconcile_swaggerui_deployment(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
    ) -> anyhow::Result<Deployment> {
        let prefix = ditto.name();

        self.create_defaults(
            ditto,
            &mut deployment,
            |labels| {
                labels.insert(KUBERNETES_LABEL_COMPONENT.into(), "frontend".into());
            },
            vec![],
            |_| {},
        );

        deployment.owned_by_controller(ditto)?;

        deployment.spec.use_or_create_err(|spec| {
            spec.template.spec.use_or_create_err(|template_spec| {
                template_spec
                    .init_containers
                    .apply_container("init", |container| {
                        container.image = Some(self.swaggerui_image(ditto));
                        container.command = Some(
                            vec![
                                "sh",
                                "-ec",
                                r#"
                                cp -rv /etc/nginx/. /init-config/
                                cp -rv /usr/share/nginx/html/. /init-content/
                                mkdir -p /var/lib/nginx/logs
                                mkdir -p /var/lib/nginx/tmp
                                "#,
                            ]
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                        );

                        let mut mounts = Vec::new();
                        for m in &[
                            ("swagger-ui-config", "/init-config"),
                            ("swagger-ui-content", "/init-content"),
                            ("swagger-ui-work", "/var/lib/nginx"),
                        ] {
                            mounts.push(VolumeMount {
                                name: m.0.into(),
                                mount_path: m.1.into(),
                                ..Default::default()
                            });
                        }
                        container.volume_mounts = Some(mounts);

                        Ok(())
                    })?;

                template_spec
                    .containers
                    .apply_container("swagger-ui", |container| {
                        container.image = Some(self.swaggerui_image(ditto));

                        container.add_port("http", 8080, None)?;

                        if let Some(keycloak) = &ditto.spec.keycloak {
                            keycloak
                                .client_id
                                .apply_to_env(container, "OAUTH_CLIENT_ID");
                            container.set_env("OAUTH_REALM", Some(keycloak.realm.clone()))?;
                            container.set_env("OAUTH_SCOPES", Some("openid"))?;
                            // unfortunately Swagger UI doesn't support nonces
                            container.set_env(
                                "OAUTH_ADDITIONAL_PARAMS",
                                Some(json!({"nonce": "1"}).to_string()),
                            )?;
                        } else {
                            container.drop_env("OAUTH_CLIENT_ID");
                            container.drop_env("OAUTH_REALM");
                            container.drop_env("OAUTH_SCOPES");
                            container.drop_env("OAUTH_ADDITIONAL_PARAMS");
                        }

                        let mut mounts = Vec::new();
                        for m in &[
                            ("swagger-ui-api", "/usr/share/nginx/html/openapi"),
                            ("swagger-ui-cache", "/var/cache/nginx"),
                            ("swagger-ui-work", "/var/lib/nginx"),
                            ("swagger-ui-config", "/etc/nginx"),
                            ("swagger-ui-content", "/usr/share/nginx/html"),
                            ("swagger-ui-run", "/run/nginx"),
                        ] {
                            mounts.push(VolumeMount {
                                name: m.0.into(),
                                mount_path: m.1.into(),
                                ..Default::default()
                            });
                        }
                        container.volume_mounts = Some(mounts);

                        Ok(())
                    })?;

                let mut volumes = vec![];
                for m in &[
                    "swagger-ui-cache",
                    "swagger-ui-work",
                    "swagger-ui-config",
                    "swagger-ui-content",
                    "swagger-ui-run",
                ] {
                    volumes.push(Volume {
                        name: m.to_string(),
                        empty_dir: Some(Default::default()),
                        ..Default::default()
                    });
                }
                volumes.push(Volume {
                    name: "swagger-ui-api".into(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: Some(format!("{}-swaggerui-api", prefix)),
                        ..Default::default()
                    }),
                    ..Default::default()
                });
                template_spec.volumes = Some(volumes);

                Ok(())
            })?;
            Ok(())
        })?;

        Ok(deployment)
    }
}
