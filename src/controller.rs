/**
 * Copyright (c) 2020 Red Hat Inc.
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
use anyhow::Result;

use crate::crd::{Ditto, DittoStatus};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use k8s_openapi::{ByteString, Resource};
use kube::api::{Meta, PostParams};
use kube::{Api, Client};
use std::collections::BTreeMap;

use operator_framework::install::config::AppendData;
use operator_framework::install::container::ApplyContainer;
use operator_framework::install::container::ApplyEnvironmentVariable;
use operator_framework::install::container::ApplyPort;
use operator_framework::install::container::SetArgs;
use operator_framework::install::container::SetResources;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use crate::data;

use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource,
    HTTPGetAction, PodSpec, Probe, Secret, Service, ServiceAccount, ServicePort, Volume,
    VolumeMount,
};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, Subject};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use operator_framework::process::create_or_update;
use operator_framework::tracker::{ConfigTracker, Trackable};
use operator_framework::utils::UseOrCreate;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub struct DittoController {
    client: Client,
    deployments: Api<Deployment>,
    secrets: Api<Secret>,
    configmaps: Api<ConfigMap>,
    service_accounts: Api<ServiceAccount>,
    roles: Api<Role>,
    role_bindings: Api<RoleBinding>,
    services: Api<Service>,
}

pub const DITTO_VERSION: &str = "1.1.1";

impl DittoController {
    pub fn new(namespace: &str, client: Client) -> Self {
        DittoController {
            client: client.clone(),
            deployments: Api::namespaced(client.clone(), &namespace),
            secrets: Api::namespaced(client.clone(), &namespace),
            service_accounts: Api::namespaced(client.clone(), &namespace),
            roles: Api::namespaced(client.clone(), &namespace),
            role_bindings: Api::namespaced(client.clone(), &namespace),
            services: Api::namespaced(client.clone(), &namespace),
            configmaps: Api::namespaced(client.clone(), &namespace),
        }
    }

    pub async fn reconcile(&self, ditto: &Ditto) -> Result<()> {
        let original_ditto = ditto;
        let mut ditto = original_ditto.clone();

        let prefix = ditto.name();
        let namespace = ditto.namespace().expect("Missing namespace");

        log::info!("Reconcile: {}/{}", namespace, ditto.name());

        let service_account_name = format!("{}", prefix);

        let ditto_tracker = &mut ConfigTracker::new();

        create_or_update(
            &self.secrets,
            Some(&namespace),
            prefix.clone() + "-gateway-secret",
            |mut secret| {
                secret.data.use_or_create(|data| {
                    data.entry("devops-password".into()).or_insert_with(|| {
                        let pwd: String =
                            thread_rng().sample_iter(&Alphanumeric).take(30).collect();
                        ByteString(pwd.into())
                    });
                    data.entry("status-password".into()).or_insert_with(|| {
                        let pwd: String =
                            thread_rng().sample_iter(&Alphanumeric).take(30).collect();
                        ByteString(pwd.into())
                    });
                    data.track_with(ditto_tracker);
                });

                Ok(secret)
            },
        )
        .await?;

        create_or_update(
            &self.secrets,
            Some(&namespace),
            prefix.clone() + "-mongodb-secret",
            |mut secret| {
                for n in vec![
                    "concierge",
                    "connectivity",
                    "things",
                    "searchDB",
                    "policies",
                ] {
                    let credentials =
                        match (&ditto.spec.mongo_db.username, &ditto.spec.mongo_db.password) {
                            (Some(username), Some(password)) => {
                                let username = utf8_percent_encode(&username, NON_ALPHANUMERIC);
                                let password = utf8_percent_encode(&password, NON_ALPHANUMERIC);
                                format!("{}:{}@", username, password)
                            }
                            _ => "".to_string(),
                        };
                    secret.append_data(
                        format!("{}-uri", n),
                        format!(
                            "mongodb://{}{}:{}/{}",
                            credentials, ditto.spec.mongo_db.host, ditto.spec.mongo_db.port, n,
                        ),
                    );
                }
                secret.track_with(ditto_tracker);
                Ok(secret)
            },
        )
        .await?;

        create_or_update(
            &self.service_accounts,
            Some(&namespace),
            &service_account_name,
            |service_account| Ok(service_account),
        )
        .await?;

        create_or_update(&self.roles, Some(&namespace), &prefix, |mut role| {
            role.rules = Some(vec![PolicyRule {
                api_groups: Some(vec!["".into()]),
                resources: Some(vec!["pods".into()]),
                verbs: vec!["get".into(), "watch".into(), "list".into()],
                ..Default::default()
            }]);
            Ok(role)
        })
        .await?;

        create_or_update(
            &self.role_bindings,
            Some(&namespace),
            format!("{}", prefix),
            |mut role_binding| {
                role_binding.role_ref.kind = Role::KIND.to_string();
                role_binding.role_ref.api_group = Role::GROUP.to_string();
                role_binding.role_ref.name = prefix.clone();

                role_binding.subjects = Some(vec![Subject {
                    kind: ServiceAccount::KIND.into(),
                    name: service_account_name.clone(),
                    ..Default::default()
                }]);

                Ok(role_binding)
            },
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-concierge",
            |obj| self.reconcile_concierge_deployment(&ditto, obj, ditto_tracker),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-connectivity",
            |obj| self.reconcile_connectivity_deployment(&ditto, obj, ditto_tracker),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-gateway",
            |obj| self.reconcile_gateway_deployment(&ditto, obj, ditto_tracker),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-policies",
            |obj| self.reconcile_policies_deployment(&ditto, obj, ditto_tracker),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-things",
            |obj| self.reconcile_things_deployment(&ditto, obj, ditto_tracker),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-things-search",
            |obj| self.reconcile_things_search_deployment(&ditto, obj, ditto_tracker),
        )
        .await?;

        create_or_update(
            &self.services,
            Some(&namespace),
            prefix.clone() + "-gateway",
            |mut service| {
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.insert(
                        "app.kubernetes.io/name".into(),
                        format!("{}-gateway", ditto.name()),
                    );
                    labels.insert("app.kubernetes.io/instance".into(), ditto.name());
                    spec.selector = Some(labels);

                    // set ports
                    spec.ports = Some(vec![ServicePort {
                        port: 8080,
                        name: Some("http".into()),
                        target_port: Some(IntOrString::String("http".into())),
                        ..Default::default()
                    }]);
                });

                Ok(service)
            },
        )
        .await?;

        create_or_update(
            &self.services,
            Some(&namespace),
            prefix.clone() + "-nginx",
            |mut service| {
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.insert(
                        "app.kubernetes.io/name".into(),
                        format!("{}-nginx", ditto.name()),
                    );
                    labels.insert("app.kubernetes.io/instance".into(), ditto.name());
                    spec.selector = Some(labels);

                    // set ports
                    spec.ports = Some(vec![ServicePort {
                        port: 8080,
                        name: Some("http".into()),
                        target_port: Some(IntOrString::String("http".into())),
                        ..Default::default()
                    }]);
                });

                Ok(service)
            },
        )
        .await?;

        create_or_update(
            &self.services,
            Some(&namespace),
            prefix.clone() + "-swaggerui",
            |mut service| {
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.insert(
                        "app.kubernetes.io/name".into(),
                        format!("{}-swaggerui", ditto.name()),
                    );
                    labels.insert("app.kubernetes.io/instance".into(), ditto.name());
                    spec.selector = Some(labels);

                    // set ports
                    spec.ports = Some(vec![ServicePort {
                        port: 8080,
                        name: Some("http".into()),
                        target_port: Some(IntOrString::String("http".into())),
                        ..Default::default()
                    }]);
                });

                Ok(service)
            },
        )
        .await?;

        let mut nginx_tracker = &mut ConfigTracker::new();

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-swaggerui-api",
            |mut cm| {
                cm.append_data("ditto-api-v1.yaml", include_str!("data/ditto-api-v1.yaml"));
                cm.append_data("ditto-api-v2.yaml", include_str!("data/ditto-api-v2.yaml"));
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-conf",
            |mut cm| {
                cm.append_data("nginx.conf", data::nginx_conf(ditto.name(), true));
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-htpasswd",
            |mut cm| {
                cm.append_data("nginx.htpasswd", "ditto:A6BgmB8IEtPTs");
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-cors",
            |mut cm| {
                cm.append_data("nginx-cors.conf", include_str!("data/nginx.cors"));
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-index",
            |mut cm| {
                cm.append_data("index.html", include_str!("data/index.html"));
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-ditto-up",
            |mut cm| {
                cm.append_data("ditto-up.svg", include_str!("data/ditto-up.svg"));
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-ditto-down",
            |mut cm| {
                cm.append_data("ditto-down.svg", include_str!("data/ditto-down.svg"));
                cm.track_with(&mut nginx_tracker);
                Ok(cm)
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

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-nginx",
            |obj| self.reconcile_nginx_deployment(&ditto, obj, &nginx_tracker),
        )
        .await?;

        ditto.status = Some(DittoStatus {
            phase: "Active".into(),
            ..Default::default()
        });

        if !original_ditto.eq(&ditto) {
            Api::<Ditto>::namespaced(self.client.clone(), &namespace)
                .replace_status(
                    &ditto.name(),
                    &PostParams::default(),
                    serde_json::to_vec(&ditto)?,
                )
                .await?;
        }

        Ok(())
    }

    fn reconcile_concierge_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            "docker.io/eclipse/ditto-concierge:1.1.0",
            Some("concierge-uri"),
            config_tracker,
        )
    }

    fn reconcile_gateway_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        let mut deployment = self.reconcile_default_deployment(
            ditto,
            deployment,
            "docker.io/eclipse/ditto-gateway:1.1.0",
            None,
            config_tracker,
        )?;

        deployment.apply_container("service", |container| {
            container.add_env(
                "ENABLE_DUMMY_AUTH",
                ditto.spec.enable_dummy_auth.to_string(),
            )?;
            container.add_env(
                "DEVOPS_SECURE_STATUS",
                ditto.spec.devops_secure_status.to_string(),
            )?;

            container.add_env_from_secret(
                "DEVOPS_PASSWORD",
                format!("{}-gateway-secret", ditto.name()),
                "devops-password",
            )?;
            container.add_env_from_secret(
                "STATUS_PASSWORD",
                format!("{}-gateway-secret", ditto.name()),
                "status-password",
            )?;

            Ok(())
        })?;

        Ok(deployment)
    }

    fn reconcile_connectivity_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            "docker.io/eclipse/ditto-connectivity:1.1.0",
            Some("connectivity-uri"),
            config_tracker,
        )
    }

    fn reconcile_policies_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            "docker.io/eclipse/ditto-policies:1.1.0",
            Some("policies-uri"),
            config_tracker,
        )
    }

    fn reconcile_things_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            "docker.io/eclipse/ditto-things:1.1.0",
            Some("things-uri"),
            config_tracker,
        )
    }

    fn reconcile_things_search_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            "docker.io/eclipse/ditto-things-search:1.1.0",
            Some("searchDB-uri"),
            config_tracker,
        )
    }

    fn reconcile_default_deployment(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
        image_name: &str,
        uri_key: Option<&str>,
        config_tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        let prefix = ditto.name();

        let mut labels = BTreeMap::new();

        labels.insert("app.kubernetes.io/name".into(), deployment.name());
        labels.insert("app.kubernetes.io/instance".into(), ditto.name());

        if let Some(ref mut metadata) = deployment.metadata {
            metadata.owner_references = Some(vec![OwnerReference {
                api_version: Ditto::API_VERSION.into(),
                kind: Ditto::KIND.into(),
                block_owner_deletion: Some(true),
                controller: Some(true),
                name: ditto.name(),
                uid: ditto.meta().uid.as_ref().expect("UID missing").clone(),
            }]);
        }

        if deployment.spec.is_none() {
            deployment.spec = Some(Default::default());
        }

        if let Some(ref mut spec) = deployment.spec {
            spec.selector.match_labels = Some(labels.clone());
            labels.insert("actorSystemName".into(), "ditto-cluster".into());

            spec.template.metadata.use_or_create(|metadata| {
                metadata.labels.use_or_create(|meta_labels| {
                    meta_labels.extend(labels);
                });
                metadata.annotations.use_or_create(|annotations| {
                    annotations.insert(
                        "ditto.iot.eclipse.org/config-hash".into(),
                        config_tracker.current_hash(),
                    );
                });
            });

            spec.template.spec.use_or_create(|template_spec| {
                template_spec.service_account_name = Some(prefix.clone());
            });

            spec.template.apply_container("service", |container| {

                container.image = Some(image_name.to_string());

                container.args(vec!["java", "-jar", "/opt/ditto/starter.jar"]);
                container.command = None;

                container.add_port("http", 8080, None)?;
                container.add_port("remoting", 2551, None)?;
                container.add_port("management", 8558, None)?;

                container.add_env("POD_LABEL_SELECTOR", "app.kubernetes.io/name=%s")?;
                container.add_env("DISCOVERY_METHOD", "kubernetes-api")?;
                container.add_env("OPENJ9_JAVA_OPTIONS", "-XX:+ExitOnOutOfMemoryError -Xtune:virtualized -Xss512k -XX:MaxRAMPercentage=80 -XX:InitialRAMPercentage=40 -Dakka.coordinated-shutdown.exit-jvm=on -Dorg.mongodb.async.type=netty")?;
                container.add_env("MONGO_DB_SSL_ENABLED", "false")?;
                container.add_env_from_field_path("POD_NAMESPACE", "metadata.namespace")?;
                container.add_env_from_field_path("INSTANCE_INDEX", "metadata.name")?;
                container.add_env_from_field_path("HOSTNAME", "status.podIP")?;

                container.set_resources("memory", Some("1Gi"), Some("1Gi"));

                if let Some(uri_key)= uri_key {
                    container.add_env_from_secret("MONGO_DB_URI", prefix + "-mongodb-secret", uri_key)?;
                }

                self.add_probes(container)?;

                Ok(())
            })?;
        }

        Ok(deployment)
    }

    fn reconcile_nginx_deployment(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
        tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        let prefix = ditto.name();

        let mut labels = BTreeMap::new();

        labels.insert("app.kubernetes.io/name".into(), deployment.name());
        labels.insert("app.kubernetes.io/instance".into(), ditto.name());

        if let Some(ref mut metadata) = deployment.metadata {
            metadata.owner_references = Some(vec![OwnerReference {
                api_version: Ditto::API_VERSION.into(),
                kind: Ditto::KIND.into(),
                block_owner_deletion: Some(true),
                controller: Some(true),
                name: ditto.name(),
                uid: ditto.meta().uid.as_ref().expect("UID missing").clone(),
            }]);
        }

        deployment.spec.use_or_create_err(|spec| {
            spec.selector.match_labels = Some(labels.clone());
            spec.template.metadata.use_or_create(|metadata| {
                metadata.labels = Some(labels.clone());
                metadata.annotations.use_or_create(|annotations| {
                    annotations.insert("config-hash".into(), tracker.current_hash())
                });
            });

            spec.template.spec.use_or_create_err(|template_spec| {
                let mut volumes = vec![];

                for n in vec![
                    ("conf", "nginx-conf"),
                    ("htpasswd", "nginx-htpasswd"),
                    ("cors", "nginx-cors"),
                    ("index", "nginx-index"),
                    ("ditto-down", "nginx-ditto-down"),
                    ("ditto-up", "nginx-ditto-up"),
                ] {
                    volumes.push(Volume {
                        name: format!("nginx-{}", n.0),
                        config_map: Some(ConfigMapVolumeSource {
                            name: Some(prefix.clone() + "-" + n.1.into()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    });
                }
                for n in vec!["cache", "run"] {
                    volumes.push(Volume {
                        name: format!("nginx-{}", n),
                        empty_dir: Some(Default::default()),
                        ..Default::default()
                    });
                }
                template_spec.volumes = Some(volumes);
                Ok(())
            })?;

            spec.template.apply_container("nginx", |container| {
                container.image = Some("docker.io/nginx:1.17.5-alpine".into());

                container.args = None;
                container.command = None;

                container.add_port("http", 8080, None)?;

                let mut volume_mounts = vec![];
                for n in vec![
                    ("conf", "/etc/nginx/nginx.conf", Some("nginx.conf")),
                    (
                        "htpasswd",
                        "/etc/nginx/nginx.htpasswd",
                        Some("nginx.htpasswd"),
                    ),
                    (
                        "cors",
                        "/etc/nginx/nginx-cors.conf",
                        Some("nginx-cors.conf"),
                    ),
                    ("index", "/etc/nginx/html/index.html", Some("index.html")),
                    (
                        "ditto-down",
                        "/etc/nginx/html/ditto-down.svg",
                        Some("ditto-down.svg"),
                    ),
                    (
                        "ditto-up",
                        "/etc/nginx/html/ditto-up.svg",
                        Some("ditto-up.svg"),
                    ),
                    ("cache", "/var/cache/nginx", None),
                    ("run", "/run/nginx", None),
                ] {
                    volume_mounts.push(VolumeMount {
                        name: format!("nginx-{}", n.0),
                        mount_path: n.1.to_string(),
                        sub_path: n.2.map(|s| s.to_string()),
                        ..Default::default()
                    });
                }
                container.volume_mounts = Some(volume_mounts);

                Ok(())
            })?;

            Ok(())
        })?;

        Ok(deployment)
    }

    fn reconcile_swaggerui_deployment(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
    ) -> Result<Deployment> {
        let prefix = ditto.name();

        let mut labels = BTreeMap::new();

        labels.insert("app.kubernetes.io/name".into(), deployment.name());
        labels.insert("app.kubernetes.io/instance".into(), ditto.name());

        deployment.metadata.use_or_create(|metadata| {
            metadata.owner_references = Some(vec![OwnerReference {
                api_version: Ditto::API_VERSION.into(),
                kind: Ditto::KIND.into(),
                block_owner_deletion: Some(true),
                controller: Some(true),
                name: ditto.name(),
                uid: ditto.meta().uid.as_ref().expect("UID missing").clone(),
            }]);
        });

        deployment.spec.use_or_create_err(|spec| {
            spec.selector.match_labels = Some(labels.clone());
            spec.template.metadata = Some(ObjectMeta {
                labels: Some(labels.clone()),
                ..Default::default()
            });

            spec.template.spec.use_or_create_err(|template_spec| {
                template_spec
                    .init_containers
                    .apply_container("init", |container| {
                        container.image = Some("docker.io/swaggerapi/swagger-ui:3.17.4".into());
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
                        for m in vec![
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
                        container.image = Some("docker.io/swaggerapi/swagger-ui:3.17.4".into());
                        container.add_port("http", 8080, None)?;

                        let mut mounts = Vec::new();
                        for m in vec![
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
                for m in vec![
                    "swagger-ui-cache",
                    "swagger-ui-work",
                    "swagger-ui-config",
                    "swagger-ui-content",
                    "swagger-ui-run",
                ] {
                    volumes.push(Volume {
                        name: m.into(),
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

    fn add_probes(&self, container: &mut Container) -> Result<()> {
        container.readiness_probe = Some(Probe {
            initial_delay_seconds: Some(30),
            period_seconds: Some(10),
            timeout_seconds: Some(1),
            failure_threshold: Some(3),
            http_get: Some(HTTPGetAction {
                port: IntOrString::String("management".to_string()),
                path: Some("/ready".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });
        container.liveness_probe = Some(Probe {
            initial_delay_seconds: Some(30),
            period_seconds: Some(10),
            timeout_seconds: Some(3),
            failure_threshold: Some(5),
            http_get: Some(HTTPGetAction {
                port: IntOrString::String("management".to_string()),
                path: Some("/alive".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });
        Ok(())
    }
}
