use crate::{
    controller::{
        keycloak_url_arg, nginx, KUBERNETES_LABEL_COMPONENT, OPENSHIFT_ANNOTATION_CONNECT,
    },
    crd::Ditto,
    data,
};
use k8s_openapi::{
    api::apps::v1::Deployment,
    api::core::v1::{
        ConfigMapVolumeSource, Container, EmptyDirVolumeSource, HTTPGetAction, PodTemplateSpec,
        Probe, SecretVolumeSource, ServicePort,
    },
    apimachinery::pkg::util::intstr::IntOrString,
};
use kube::ResourceExt;
use operator_framework::{
    install::{
        config::{AppendBinary, AppendString},
        container::{
            ApplyContainer, ApplyEnvironmentVariable, ApplyPort, ApplyVolume, ApplyVolumeMount,
            DropVolume, DropVolumeMount, RemoveContainer,
        },
        meta::OwnedBy,
    },
    process::create_or_update,
    tracker::{ConfigTracker, Trackable, TrackerState},
    utils::UseOrCreate,
};
use std::{collections::BTreeMap, ops::Deref};

const NGINX_IMAGE: &str = "docker.io/library/nginx:mainline";

pub struct Nginx<'a>(pub &'a super::Context);

impl<'a> Deref for Nginx<'a> {
    type Target = super::Context;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> Nginx<'a> {
    pub async fn process(
        &self,
        ditto: &Ditto,
        mut nginx_tracker: ConfigTracker,
    ) -> anyhow::Result<()> {
        let prefix = ditto.name();
        let namespace = ditto.namespace().expect("Missing namespace");

        create_or_update(
            &self.services,
            Some(&namespace),
            prefix.clone() + "-nginx",
            |mut service| {
                service.owned_by_controller(ditto)?;
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.extend(self.service_selector("nginx", ditto));
                    spec.selector = Some(labels);

                    let target_port = match &ditto.spec.keycloak {
                        Some(keycloak) if !keycloak.disable_proxy => "oauth",
                        _ => "http",
                    };

                    // set ports
                    spec.ports = Some(vec![ServicePort {
                        port: 8080,
                        name: Some("http".into()),
                        target_port: Some(IntOrString::String(target_port.into())),
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
            format!("{}-nginx-conf", prefix),
            |mut cm| {
                cm.owned_by_controller(ditto)?;
                cm.append_string(
                    "nginx.conf",
                    data::nginx_conf(
                        prefix.clone(),
                        self.want_swagger(ditto),
                        ditto.spec.keycloak.is_some(),
                        self.expose_infra(ditto),
                        self.expose_devops(ditto),
                        self.want_welcome(ditto),
                    ),
                );
                cm.track_with(&mut nginx_tracker);
                Ok::<_, anyhow::Error>(cm)
            },
        )
        .await?;

        if self.want_preaut(ditto) {
            // only create htpasswd if we are not using OAuth ...
            create_or_update(
                &self.configmaps,
                Some(&namespace),
                format!("{}-nginx-htpasswd", prefix),
                |mut cm| {
                    cm.owned_by_controller(ditto)?;
                    if ditto.spec.create_default_user.unwrap_or(true) {
                        cm.init_string("nginx.htpasswd", "ditto:A6BgmB8IEtPTs");
                    }
                    cm.track_with(&mut nginx_tracker);
                    Ok::<_, anyhow::Error>(cm)
                },
            )
            .await?;
            // ... however, we don't delete an existing secret, as it may contain information you
            // want to keep.
        }

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-cors",
            |mut cm| {
                cm.owned_by_controller(ditto)?;
                cm.append_string("nginx-cors.conf", include_str!("../resources/nginx.cors"));
                cm.track_with(&mut nginx_tracker);
                Ok::<_, anyhow::Error>(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-data",
            |mut cm| {
                if cm.metadata.creation_timestamp.is_none() {
                    // only take ownership if we created the config map
                    cm.owned_by_controller(ditto)?;
                }
                // owned or not, we inject additional content to the configmap
                cm.append_string(
                    "index.default.html",
                    data::nginx_default(
                        ditto.spec.keycloak.is_some(),
                        self.want_swagger(ditto),
                        self.expose_infra(ditto),
                    ),
                );
                cm.append_string("index.json", "{}");
                cm.append_string("ditto-up.svg", include_str!("../resources/ditto-up.svg"));
                cm.append_string(
                    "ditto-down.svg",
                    include_str!("../resources/ditto-down.svg"),
                );
                cm.append_string(
                    "ditto-api-v2.yaml",
                    include_str!("../resources/ditto-api-v2.yaml"),
                );
                cm.append_binary(
                    "favicon-16x16.png",
                    &include_bytes!("../resources/favicon-16x16.png")[..],
                );
                cm.append_binary(
                    "favicon-32x32.png",
                    &include_bytes!("../resources/favicon-32x32.png")[..],
                );
                cm.append_binary(
                    "favicon-96x96.png",
                    &include_bytes!("../resources/favicon-96x96.png")[..],
                );
                cm.track_with(&mut nginx_tracker);
                Ok::<_, anyhow::Error>(cm)
            },
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-nginx",
            |obj| self.reconcile_nginx_deployment(ditto, obj, nginx_tracker.freeze()),
        )
        .await?;

        Ok(())
    }

    fn reconcile_nginx_deployment(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
        tracker: TrackerState,
    ) -> anyhow::Result<Deployment> {
        let prefix = ditto.name();

        self.create_defaults(
            ditto,
            &mut deployment,
            |labels| {
                labels.insert(KUBERNETES_LABEL_COMPONENT.into(), "integration".into());
            },
            vec![],
            |annotations| {
                annotations.insert(
                    OPENSHIFT_ANNOTATION_CONNECT.into(),
                    self.connects_to(ditto, vec!["gateway", "swaggerui"]),
                );
            },
        );

        deployment.owned_by_controller(ditto)?;

        match &ditto.spec.keycloak {
            Some(keycloak) if !keycloak.disable_proxy => {
                log::debug!("Enable SSO integration");
                deployment.apply_container("oauth-proxy", |container| {
                    container.image = Some("quay.io/oauth2-proxy/oauth2-proxy:v7.2.0".into());
                    container.image_pull_policy = Some("IfNotPresent".into());

                    container.add_env_from_field_path("HOSTNAME", "status.podIP")?;
                    keycloak
                        .client_id
                        .apply_to_env(container, "OAUTH2_PROXY_CLIENT_ID");
                    keycloak
                        .client_secret
                        .apply_to_env(container, "OAUTH2_PROXY_CLIENT_SECRET");

                    let mut args: Vec<_> = vec![
                        "--email-domain=*".to_string(),
                        "--scope=openid".to_string(),
                        "--reverse-proxy=true".to_string(),
                        "--http-address=0.0.0.0:4180".to_string(),
                        "--upstream=http://$(HOSTNAME):8080/".to_string(),
                        "--provider=keycloak".to_string(),
                        keycloak_url_arg("--login-url", keycloak, "/auth"),
                        keycloak_url_arg("--redeem-url", keycloak, "/token"),
                        keycloak_url_arg("--profile-url", keycloak, "/userinfo"),
                        keycloak_url_arg("--validate-url", keycloak, "/userinfo"),
                    ];

                    container
                        .set_env("OAUTH2_PROXY_PROVIDER_DISPLAY_NAME", keycloak.label.clone())?;
                    container
                        .set_env("OAUTH2_PROXY_REDIRECT_URL", keycloak.redirect_url.clone())?;

                    if !keycloak.url.starts_with("https://") {
                        container.add_env("OAUTH2_PROXY_COOKIE_SECURE", "false")?;
                    } else {
                        container.drop_env("OAUTH2_PROXY_COOKIE_SECURE");
                    }

                    for group in &keycloak.groups {
                        args.push(format!("--allowed-group={}", group));
                    }

                    container.args = Some(args);

                    container.add_env_from_secret(
                        "OAUTH2_PROXY_COOKIE_SECRET",
                        prefix.clone() + "-oauth",
                        "cookie.secret",
                    )?;

                    container.add_port("oauth", 4180, None)?;

                    Ok(())
                })?;
            }
            _ => {
                deployment.remove_container_by_name("oauth-proxy");
            }
        }

        deployment.spec.use_or_create_err(|spec| {
            spec.template.metadata.use_or_create(|metadata| {
                metadata.annotations.use_or_create(|annotations| {
                    annotations.insert("config-hash".into(), tracker.0);
                });
            });

            let mut volumes = vec![
                nginx::Volume::empty_dir("nginx-cache", "/var/cache/nginx"),
                nginx::Volume::empty_dir("nginx-run", "/run/nginx"),
                nginx::Volume::configmap(
                    "nginx-conf",
                    "/etc/nginx/nginx.conf",
                    prefix.clone() + "-nginx-conf",
                )
                .with_sub_path("nginx.conf"),
                nginx::Volume::configmap(
                    "nginx-cors",
                    "/etc/nginx/nginx-cors.conf",
                    prefix.clone() + "-nginx-cors",
                )
                .with_sub_path("nginx-cors.conf"),
                nginx::Volume::configmap(
                    "nginx-data",
                    "/etc/nginx/html",
                    prefix.clone() + "-nginx-data",
                ),
            ];

            if self.want_preaut(ditto) {
                volumes.push(
                    nginx::Volume::configmap(
                        "nginx-htpasswd",
                        "/etc/nginx/nginx.htpasswd",
                        prefix.clone() + "-nginx-htpasswd",
                    )
                    .with_sub_path("nginx.htpasswd"),
                );
            } else {
                spec.template.drop_volume("nginx-htpasswd");
                spec.template.apply_container("nginx", |container| {
                    container.drop_volume_mount("nginx-htpasswd");
                    Ok(())
                })?;
            }

            nginx::apply_volumes(&volumes, &mut spec.template, "nginx")?;

            spec.template.apply_container("nginx", |mut container| {
                container.image = Some(NGINX_IMAGE.into());

                container.args = None;
                container.command = None;

                container.add_port("http", 8080, None)?;

                default_nginx_probes("http", &mut container);

                Ok(())
            })?;

            Ok(())
        })?;

        Ok(deployment)
    }
}

#[derive(Clone, Debug)]
pub enum Source {
    EmptyDir,
    ConfigMap(String),
    #[allow(dead_code)]
    Secret(String),
}

#[derive(Clone, Debug)]
pub struct Volume {
    pub name: String,
    pub path: String,
    pub sub_path: Option<String>,
    pub source: Source,
}

impl Volume {
    pub fn empty_dir<S1, S2>(name: S1, path: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            name: name.into(),
            path: path.into(),
            sub_path: None,
            source: Source::EmptyDir,
        }
    }

    pub fn configmap<S1, S2, S3>(name: S1, path: S2, source: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Volume {
            name: name.into(),
            path: path.into(),
            sub_path: None,
            source: Source::ConfigMap(source.into()),
        }
    }

    #[allow(dead_code)]
    pub fn secret<S1, S2, S3>(name: S1, path: S2, source: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Volume {
            name: name.into(),
            path: path.into(),
            sub_path: None,
            source: Source::Secret(source.into()),
        }
    }

    pub fn with_sub_path<S: Into<String>>(mut self, sub_path: S) -> Self {
        self.sub_path = Some(sub_path.into());
        self
    }
}

pub fn apply_volumes<S>(
    volumes: &[Volume],
    spec: &mut PodTemplateSpec,
    container_name: S,
) -> anyhow::Result<()>
where
    S: AsRef<str>,
{
    spec.apply_container(container_name.as_ref(), |container| {
        for v in volumes {
            container.apply_volume_mount(&v.name, |volume| {
                volume.mount_path = v.path.clone();
                volume.sub_path = v.sub_path.as_ref().cloned();
                Ok(())
            })?;
        }

        Ok(())
    })?;

    for v in volumes {
        spec.apply_volume(&v.name, |volume| {
            match &v.source {
                Source::EmptyDir => {
                    volume.empty_dir = Some(EmptyDirVolumeSource {
                        ..Default::default()
                    });
                    volume.config_map = None;
                    volume.secret = None;
                }
                Source::ConfigMap(name) => {
                    volume.config_map = Some(ConfigMapVolumeSource {
                        name: Some(name.clone()),
                        ..Default::default()
                    });
                    volume.empty_dir = None;
                    volume.secret = None;
                }
                Source::Secret(name) => {
                    volume.secret = Some(SecretVolumeSource {
                        secret_name: Some(name.clone()),
                        ..Default::default()
                    });
                    volume.empty_dir = None;
                    volume.config_map = None;
                }
            }
            Ok(())
        })?;
    }

    Ok(())
}

fn default_nginx_probes(port: &str, container: &mut Container) {
    container.readiness_probe = Some(Probe {
        initial_delay_seconds: Some(2),
        period_seconds: Some(5),
        timeout_seconds: Some(1),
        failure_threshold: Some(3),
        http_get: Some(HTTPGetAction {
            port: IntOrString::String(port.to_string()),
            path: Some("/".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    });
    container.liveness_probe = Some(Probe {
        initial_delay_seconds: Some(2),
        period_seconds: Some(5),
        timeout_seconds: Some(3),
        failure_threshold: Some(5),
        http_get: Some(HTTPGetAction {
            port: IntOrString::String(port.to_string()),
            path: Some("/".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    });
}
