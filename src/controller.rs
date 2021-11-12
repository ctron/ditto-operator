/*
 * Copyright (c) 2020, 2021 Red Hat Inc.
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
use crate::{
    crd::{Ditto, DittoStatus, Keycloak},
    data::{
        self, {openapi_v1, openapi_v2, ApiOptions},
    },
    nginx,
};
use anyhow::{anyhow, Result};
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, IngressBackend, IngressServiceBackend, ServiceBackendPort,
};
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{
            ConfigMap, ConfigMapVolumeSource, Container, HTTPGetAction, Probe, Secret, Service,
            ServiceAccount, ServicePort, Volume, VolumeMount,
        },
        networking::v1::{HTTPIngressRuleValue, Ingress, IngressRule},
        rbac::v1::{PolicyRule, Role, RoleBinding, Subject},
    },
    apimachinery::pkg::util::intstr::IntOrString,
    ByteString, Resource,
};
use kube::{
    api::{DeleteParams, PostParams},
    Api, Client, ResourceExt,
};
use log::debug;
use operator_framework::{
    install::{
        config::{AppendBinary, AppendString},
        container::{
            ApplyContainer, ApplyEnvironmentVariable, ApplyPort, ApplyVolumeMount, RemoveContainer,
            SetArgs, SetCommand, SetResources,
        },
        meta::OwnedBy,
        Delete, KubeReader,
    },
    process::create_or_update,
    tracker::{ConfigTracker, Trackable},
    utils::UseOrCreate,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde_json::json;
use std::{collections::BTreeMap, fmt::Display};

pub struct DittoController {
    has_openshift: bool,

    client: Client,
    deployments: Api<Deployment>,
    secrets: Api<Secret>,
    configmaps: Api<ConfigMap>,
    service_accounts: Api<ServiceAccount>,
    roles: Api<Role>,
    role_bindings: Api<RoleBinding>,
    services: Api<Service>,
    ingress: Api<Ingress>,
}

pub const DITTO_REGISTRY: &str = "docker.io/eclipse";
pub const DITTO_VERSION: &str = "1.5.0";
pub const KUBERNETES_LABEL_COMPONENT: &str = "app.kubernetes.io/component";
pub const OPENSHIFT_ANNOTATION_CONNECT: &str = "app.openshift.io/connects-to";
pub const NGINX_IMAGE: &str = "docker.io/nginx:mainline";

impl DittoController {
    pub fn new(namespace: &str, client: Client, has_openshift: bool) -> Self {
        DittoController {
            has_openshift,
            client: client.clone(),
            deployments: Api::namespaced(client.clone(), &namespace),
            secrets: Api::namespaced(client.clone(), &namespace),
            service_accounts: Api::namespaced(client.clone(), &namespace),
            roles: Api::namespaced(client.clone(), &namespace),
            role_bindings: Api::namespaced(client.clone(), &namespace),
            services: Api::namespaced(client.clone(), &namespace),
            configmaps: Api::namespaced(client.clone(), &namespace),
            ingress: Api::namespaced(client, &namespace),
        }
    }

    fn image_name<S>(&self, base: S, ditto: &Ditto) -> String
    where
        S: ToString + Display,
    {
        format!("{}/{}:{}", DITTO_REGISTRY, base, self.image_version(ditto))
    }

    fn image_version(&self, ditto: &Ditto) -> String {
        ditto
            .spec
            .version
            .as_deref()
            .unwrap_or(DITTO_VERSION)
            .to_string()
    }

    pub async fn reconcile(&self, ditto: Ditto) -> Result<()> {
        let name = ditto.name();
        let namespace = ditto
            .namespace()
            .ok_or_else(|| anyhow!("Missing namespace"))?;
        let original_ditto = ditto.clone();

        let result = self.do_reconcile(ditto).await;

        let (ditto, result) = match result {
            Ok(mut ditto) => {
                ditto.status = Some(DittoStatus {
                    phase: "Active".into(),
                    ..Default::default()
                });
                (ditto, Ok(()))
            }
            Err(err) => {
                let mut ditto = original_ditto.clone();
                ditto.status = Some(DittoStatus {
                    phase: "Failed".into(),
                    message: Some(err.to_string()),
                    // FIXME: use conditions
                    conditions: vec![],
                });
                (ditto, Err(err))
            }
        };

        if !original_ditto.eq(&ditto) {
            Api::<Ditto>::namespaced(self.client.clone(), &namespace)
                .replace_status(&name, &PostParams::default(), serde_json::to_vec(&ditto)?)
                .await?;
        }

        result
    }

    async fn do_reconcile(&self, ditto: Ditto) -> Result<Ditto> {
        let name = ditto.name();
        let prefix = ditto.name();
        let namespace = ditto.namespace().expect("Missing namespace");

        log::info!("Reconcile: {}/{}", namespace, name);

        let service_account_name = prefix.to_string();

        let ditto_tracker = &mut ConfigTracker::new();
        let mut gateway_tracker = &mut ConfigTracker::new();
        let mut nginx_tracker = &mut ConfigTracker::new();

        create_or_update(
            &self.secrets,
            Some(&namespace),
            prefix.clone() + "-gateway-secret",
            |mut secret| {
                secret.owned_by_controller(&ditto)?;
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

                Ok::<_, anyhow::Error>(secret)
            },
        )
        .await?;

        // handle the ditto internal service
        let internal_service = {
            // if we want internal ingress, we create a secret
            let service_name = prefix.clone() + "-preauth";
            let secret_name = prefix.clone() + "-preauth-secret";
            let cm_name = prefix.clone() + "-nginx-preauth-tpl";

            if let Some(internal) = &ditto.spec.internal_service {
                // create credentials for internal service

                create_or_update(
                    &self.secrets,
                    Some(&namespace),
                    secret_name.clone(),
                    |mut secret| {
                        if secret.metadata.creation_timestamp.is_none() {
                            // we only take ownership when we create the secret ourselves
                            secret.owned_by_controller(&ditto)?;
                        }

                        match &internal.username {
                            // provided information
                            Some(username) => {
                                secret.append_string("username", username);
                            }
                            // generate initially
                            None => {
                                secret.init_string("username", "ditto");
                            }
                        }

                        match &internal.password {
                            // provided information
                            Some(password) => {
                                secret.append_string("password", password);
                            }
                            // generate initially
                            None => {
                                secret.init_string_from("password", || {
                                    thread_rng()
                                        .sample_iter(&Alphanumeric)
                                        .take(32)
                                        .map(char::from)
                                        .collect::<String>()
                                });
                            }
                        }

                        secret.track_with(gateway_tracker);

                        Ok::<_, anyhow::Error>(secret)
                    },
                )
                .await?;

                // create internal service

                create_or_update(
                    &self.services,
                    Some(&namespace),
                    service_name,
                    |mut service| {
                        service.owned_by_controller(&ditto)?;

                        service.spec.use_or_create(|spec| {
                            // set labels

                            let mut labels = BTreeMap::new();
                            labels.extend(self.service_selector("gateway", &ditto));
                            spec.selector = Some(labels);

                            // set ports
                            spec.ports = Some(vec![ServicePort {
                                port: 80,
                                name: Some("http".into()),
                                target_port: Some(IntOrString::String("http-preauth".into())),
                                ..Default::default()
                            }]);
                        });

                        Ok::<_, anyhow::Error>(service)
                    },
                )
                .await?;

                // create the configmap

                create_or_update(&self.configmaps, Some(&namespace), cm_name, |mut cm| {
                    cm.owned_by_controller(&ditto)?;
                    cm.append_string("nginx.conf.template", data::nginx_conf_preauth());
                    cm.track_with(&mut gateway_tracker);
                    Ok::<_, anyhow::Error>(cm)
                })
                .await?;

                true
            } else {
                // delete all internal service resources
                self.secrets
                    .delete_conditionally(&secret_name, |secret| {
                        secret.is_owned_by_controller(&ditto)
                    })
                    .await?;
                self.configmaps
                    .delete_optionally(&cm_name, &Default::default())
                    .await?;
                self.services
                    .delete_optionally(&service_name, &Default::default())
                    .await?;

                false
            }
        };

        let reader = KubeReader::new(&self.configmaps, &self.secrets);
        let credentials = match (&ditto.spec.mongo_db.username, &ditto.spec.mongo_db.password) {
            (Some(username), Some(password)) => {
                let username = username.read_value(&reader).await?.unwrap_or_default();
                let password = password.read_value(&reader).await?.unwrap_or_default();
                let username = utf8_percent_encode(&username, NON_ALPHANUMERIC);
                let password = utf8_percent_encode(&password, NON_ALPHANUMERIC);
                format!("{}:{}@", username, password)
            }
            _ => "".to_string(),
        };
        let database = match &ditto.spec.mongo_db.database {
            Some(database) => database.read_value(&reader).await?.unwrap_or_default(),
            None => "ditto".to_string(),
        };

        create_or_update(
            &self.secrets,
            Some(&namespace),
            prefix.clone() + "-mongodb-secret",
            |mut secret| {
                secret.owned_by_controller(&ditto)?;

                for n in &[
                    "concierge",
                    "connectivity",
                    "things",
                    "searchDB",
                    "policies",
                ] {
                    secret.append_string(
                        format!("{}-uri", n),
                        format!(
                            "mongodb://{}{}:{}/{}",
                            credentials,
                            ditto.spec.mongo_db.host,
                            ditto.spec.mongo_db.port,
                            database,
                        ),
                    );
                }
                secret.track_with(ditto_tracker);
                Ok::<_, anyhow::Error>(secret)
            },
        )
        .await?;

        create_or_update(
            &self.service_accounts,
            Some(&namespace),
            &service_account_name,
            |mut service_account| {
                service_account.owned_by_controller(&ditto)?;
                Ok::<_, anyhow::Error>(service_account)
            },
        )
        .await?;

        create_or_update(&self.roles, Some(&namespace), &prefix, |mut role| {
            role.owned_by_controller(&ditto)?;
            role.rules = Some(vec![PolicyRule {
                api_groups: Some(vec!["".into()]),
                resources: Some(vec!["pods".into()]),
                verbs: vec!["get".into(), "watch".into(), "list".into()],
                ..Default::default()
            }]);
            Ok::<_, anyhow::Error>(role)
        })
        .await?;

        create_or_update(
            &self.role_bindings,
            Some(&namespace),
            prefix.to_string(),
            |mut role_binding| {
                role_binding.owned_by_controller(&ditto)?;

                role_binding.role_ref.kind = Role::KIND.to_string();
                role_binding.role_ref.api_group = Role::GROUP.to_string();
                role_binding.role_ref.name = prefix.to_string();

                role_binding.subjects = Some(vec![Subject {
                    kind: ServiceAccount::KIND.into(),
                    name: service_account_name.clone(),
                    ..Default::default()
                }]);

                Ok::<_, anyhow::Error>(role_binding)
            },
        )
        .await?;

        if ditto.spec.keycloak.is_some() {
            create_or_update(
                &self.secrets,
                Some(&namespace),
                prefix.clone() + "-oauth",
                |mut secret| {
                    secret.owned_by_controller(&ditto)?;
                    secret.init_string_from("cookie.secret", || {
                        thread_rng()
                            .sample_iter(&Alphanumeric)
                            .take(32)
                            .map(char::from)
                            .collect::<String>()
                    });
                    secret.track_with(&mut gateway_tracker);
                    Ok::<_, anyhow::Error>(secret)
                },
            )
            .await?;
        } else {
            self.secrets
                .delete_optionally(&(prefix.clone() + "-oauth"), &DeleteParams::default())
                .await?;
        }

        // extend the gateway tracker with the ditto tracker
        gateway_tracker.track(ditto_tracker.current_hash().as_bytes());

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
            |obj| self.reconcile_gateway_deployment(&ditto, obj, gateway_tracker, internal_service),
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
            prefix.clone() + "-akka",
            |mut service| {
                service.owned_by_controller(&ditto)?;
                service.spec.use_or_create(|spec| {
                    // set labels

                    let cluster_marker = format!("{}-cluster", name);

                    let mut labels = BTreeMap::new();
                    labels.insert("akka.cluster".into(), cluster_marker);

                    spec.selector = Some(labels);
                    spec.cluster_ip = Some("None".into());
                    spec.publish_not_ready_addresses = Some(true);

                    // set ports
                    spec.ports = Some(vec![
                        ServicePort {
                            port: 2551,
                            name: Some("remoting".into()),
                            target_port: Some(IntOrString::String("remoting".into())),
                            ..Default::default()
                        },
                        ServicePort {
                            port: 8558,
                            name: Some("management".into()),
                            target_port: Some(IntOrString::String("management".into())),
                            ..Default::default()
                        },
                    ]);
                });

                Ok::<_, anyhow::Error>(service)
            },
        )
        .await?;

        create_or_update(
            &self.services,
            Some(&namespace),
            prefix.clone() + "-gateway",
            |mut service| {
                service.owned_by_controller(&ditto)?;
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.extend(self.service_selector("gateway", &ditto));
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
            &self.services,
            Some(&namespace),
            prefix.clone() + "-nginx",
            |mut service| {
                service.owned_by_controller(&ditto)?;
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.extend(self.service_selector("nginx", &ditto));
                    spec.selector = Some(labels);

                    let target_port = match ditto.spec.keycloak {
                        Some(_) => "oauth",
                        None => "http",
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
            &self.services,
            Some(&namespace),
            prefix.clone() + "-swaggerui",
            |mut service| {
                service.owned_by_controller(&ditto)?;
                service.spec.use_or_create(|spec| {
                    // set labels

                    let mut labels = BTreeMap::new();
                    labels.extend(self.service_selector("swaggerui", &ditto));
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
                let oauth_auth_url = keycloak.map(|keycloak| Self::keycloak_url(keycloak, "/auth"));

                let options = ApiOptions {
                    server_label: openapi.and_then(|o| o.server_label.clone()),
                    oauth_auth_url,
                    oauth_label: keycloak.and_then(|k| k.label.clone()),
                    oauth_description: keycloak.and_then(|k| k.description.clone()),
                };

                cm.owned_by_controller(&ditto)?;
                cm.append_string("ditto-api-v1.yaml", openapi_v1(&options)?);
                cm.append_string("ditto-api-v2.yaml", openapi_v2(&options)?);
                cm.track_with(&mut nginx_tracker);

                Ok::<_, anyhow::Error>(cm)
            },
        )
        .await?;

        create_or_update(
            &self.configmaps,
            Some(&namespace),
            prefix.clone() + "-nginx-conf",
            |mut cm| {
                cm.owned_by_controller(&ditto)?;
                cm.append_string(
                    "nginx.conf",
                    data::nginx_conf(name, true, ditto.spec.keycloak.is_some()),
                );
                cm.track_with(&mut nginx_tracker);
                Ok::<_, anyhow::Error>(cm)
            },
        )
        .await?;

        if ditto.spec.keycloak.is_none() {
            // only create htpasswd if we are not using OAuth ...
            create_or_update(
                &self.configmaps,
                Some(&namespace),
                prefix.clone() + "-nginx-htpasswd",
                |mut cm| {
                    cm.owned_by_controller(&ditto)?;
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
                cm.owned_by_controller(&ditto)?;
                cm.append_string("nginx-cors.conf", include_str!("resources/nginx.cors"));
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
                    cm.owned_by_controller(&ditto)?;
                }
                // owned or not, we inject additional content to the configmap
                cm.append_string(
                    "index.default.html",
                    data::nginx_default(ditto.spec.keycloak.is_some()),
                );
                cm.append_string("ditto-up.svg", include_str!("resources/ditto-up.svg"));
                cm.append_string("ditto-down.svg", include_str!("resources/ditto-down.svg"));
                cm.append_string(
                    "ditto-api-v1.yaml",
                    include_str!("resources/ditto-api-v1.yaml"),
                );
                cm.append_string(
                    "ditto-api-v2.yaml",
                    include_str!("resources/ditto-api-v2.yaml"),
                );
                cm.append_binary(
                    "favicon-16x16.png",
                    &include_bytes!("resources/favicon-16x16.png")[..],
                );
                cm.append_binary(
                    "favicon-32x32.png",
                    &include_bytes!("resources/favicon-32x32.png")[..],
                );
                cm.append_binary(
                    "favicon-96x96.png",
                    &include_bytes!("resources/favicon-96x96.png")[..],
                );
                cm.track_with(&mut nginx_tracker);
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

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-nginx",
            |obj| self.reconcile_nginx_deployment(&ditto, obj, &nginx_tracker),
        )
        .await?;

        if let Some(ditto_ingress) = &ditto.spec.ingress {
            create_or_update(
                &self.ingress,
                Some(&namespace),
                prefix.clone() + "-console",
                |mut ingress| {
                    ingress.owned_by_controller(&ditto)?;

                    ingress.spec.use_or_create(|spec| {
                        spec.ingress_class_name = ditto_ingress.class_name.clone();
                        spec.rules = Some(vec![IngressRule {
                            host: Some(ditto_ingress.host.clone()),
                            http: Some(HTTPIngressRuleValue {
                                paths: vec![HTTPIngressPath {
                                    path: Some("/".into()),
                                    path_type: Some("Prefix".into()),
                                    backend: IngressBackend {
                                        service: Some(IngressServiceBackend {
                                            name: prefix.clone() + "-nginx",
                                            port: Some(ServiceBackendPort {
                                                name: Some("http".into()),
                                                ..Default::default()
                                            }),
                                        }),
                                        ..Default::default()
                                    },
                                }],
                            }),
                        }]);
                    });

                    if !ditto_ingress.annotations.is_empty() {
                        // if we have annotations, we apply them
                        *ingress.annotations_mut() = ditto_ingress.annotations.clone();
                    } else if self.has_openshift {
                        // if we have no annotations and run on openshift, we set some defaults
                        ingress
                            .annotations_mut()
                            .insert("route.openshift.io/termination".into(), "edge".into());
                    } else {
                        // otherwise, we clear them out
                        ingress.annotations_mut().clear();
                    }

                    Ok::<_, anyhow::Error>(ingress)
                },
            )
            .await?;
        } else {
            self.ingress
                .delete_optionally(&prefix, &DeleteParams::default())
                .await?;
        }

        Ok(ditto)
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
            self.image_name("ditto-concierge", &ditto),
            Some("concierge-uri"),
            config_tracker,
            |_| {},
            |_| {},
        )
    }

    fn keycloak_url(keycloak: &Keycloak, path: &str) -> String {
        format!(
            "{url}/auth/realms/{realm}/protocol/openid-connect{path}",
            url = keycloak.url,
            realm = keycloak.realm,
            path = path
        )
    }

    fn keycloak_url_arg(arg: &str, keycloak: &Keycloak, path: &str) -> String {
        format!("{}={}", arg, Self::keycloak_url(keycloak, path))
    }

    fn reconcile_gateway_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: &ConfigTracker,
        internal_service: bool,
    ) -> Result<Deployment> {
        let prefix = ditto.name();

        let mut deployment = self.reconcile_default_deployment(
            ditto,
            deployment,
            self.image_name("ditto-gateway", &ditto),
            None,
            config_tracker,
            |_| {},
            |_| {},
        )?;

        // that was a mistake, it belongs to the nginx
        deployment.remove_container_by_name("oauth-proxy");

        // internal service - pre-auth

        let internal_service_volumes = vec![
            nginx::Volume::empty_dir("internal-cache", "/var/cache/nginx"),
            nginx::Volume::empty_dir("internal-run", "/run/nginx"),
            nginx::Volume::empty_dir("internal-conf", "/etc/nginx"),
            nginx::Volume::configmap(
                "internal-template",
                "/etc/init/tpl",
                prefix.clone() + "-nginx-preauth-tpl",
            ),
            nginx::Volume::secret(
                "internal-auth",
                "/etc/init/secrets",
                format!("{}-preauth-secret", prefix),
            ),
        ];

        // handle the internal (pre-auth) service
        if internal_service {
            deployment.spec.use_or_create_err(|spec| {
                spec.template.spec.use_or_create_err(|pod_spec| {
                    // we use an init container to write out the generated nginx.conf
                    // and the htpasswd, created from the secret

                    pod_spec.init_containers.apply_container(
                        "internal-init",
                        |mut container| {
                            container.image = Some(NGINX_IMAGE.into());
                            container.command(vec![
                                "sh",
                                "-ec",
                                r#"
cp -rv /etc/nginx/* /writable-conf/

envsubst '${HOSTNAME}' < /etc/init/tpl/nginx.conf.template > /writable-conf/nginx.conf

cat /etc/init/secrets/username > /writable-conf/nginx.htpasswd
echo -n ":" >> /writable-conf/nginx.htpasswd
openssl passwd -apr1 -in /etc/init/secrets/password >> /writable-conf/nginx.htpasswd 
"#,
                            ]);
                            container.args = None;

                            container.apply_volume_mount_simple(
                                "internal-template",
                                "/etc/init/tpl",
                                true,
                            )?;
                            container.apply_volume_mount_simple(
                                "internal-auth",
                                "/etc/init/secrets",
                                true,
                            )?;
                            container.apply_volume_mount_simple(
                                "internal-conf",
                                "/writable-conf",
                                false,
                            )?;

                            Ok(())
                        },
                    )?;

                    Ok(())
                })?;

                Ok(())
            })?;

            deployment.apply_container("internal-proxy", |mut container| {
                container.image = Some(NGINX_IMAGE.into());

                container.args = None;
                container.command = None;

                container.add_env_from_field_path("HOSTNAME", "status.podIP")?;
                container.add_port("http-preauth", 8090, None)?;

                Self::default_nginx_probes("http-preauth", &mut container);

                Ok(())
            })?;
            deployment.spec.use_or_create_err(|spec| {
                nginx::apply_volumes(
                    &internal_service_volumes,
                    &mut spec.template,
                    "internal-proxy",
                )?;
                Ok(())
            })?;
        } else {
            deployment.spec.use_or_create_err(|spec| {
                spec.template.spec.use_or_create_err(|pod_spec| {
                    pod_spec
                        .init_containers
                        .remove_container_by_name("internal-init");
                    Ok(())
                })?;
                Ok(())
            })?;
            deployment.remove_container_by_name("internal-proxy");
            if let Some(spec) = &mut deployment.spec {
                nginx::drop_volumes(&internal_service_volumes, &mut spec.template)?;
            }
        }

        deployment.apply_container("service", |container| {
            if let Some(keycloak) = &ditto.spec.keycloak {
                let issuer_url = format!("{url}/auth/realms/{realm}", url=keycloak.url, realm=keycloak.realm);
                container.args.use_or_create(|args| {
                    // we need to insert this in the front, as `-D` is an argument for the JVM, no the application
                    if let Some(url) = issuer_url.strip_prefix("https://") {
                        args.insert(0, format!("-Dditto.gateway.authentication.oauth.openid-connect-issuers.keycloak.issuer={}", url));    
                    } else {
                        anyhow::bail!("Using a non-https issuer URL with Ditto is not supported");
                    }

                     Ok(())
                 })?;
            }

            let pre_auth = internal_service || ditto.spec.keycloak.is_none();
            container.add_env("ENABLE_PRE_AUTHENTICATION", pre_auth.to_string())?;
            // deprecated variable
            container.drop_env("ENABLE_DUMMY_AUTH");

            container.add_env(
                "DEVOPS_SECURE_STATUS",
                ditto.spec.devops_secure_status.to_string(),
            )?;

            container.add_env_from_secret(
                "DEVOPS_PASSWORD",
                format!("{}-gateway-secret", prefix),
                "devops-password",
            )?;
            container.add_env_from_secret(
                "STATUS_PASSWORD",
                format!("{}-gateway-secret", prefix),
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
            self.image_name("ditto-connectivity", &ditto),
            Some("connectivity-uri"),
            config_tracker,
            |_| {},
            |_| {},
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
            self.image_name("ditto-policies", &ditto),
            Some("policies-uri"),
            config_tracker,
            |_| {},
            |_| {},
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
            self.image_name("ditto-things", &ditto),
            Some("things-uri"),
            config_tracker,
            |_| {},
            |_| {},
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
            self.image_name("ditto-things-search", &ditto),
            Some("searchDB-uri"),
            config_tracker,
            |_| {},
            |_| {},
        )
    }

    fn reconcile_default_deployment<S, L, A>(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
        image_name: S,
        uri_key: Option<&str>,
        config_tracker: &ConfigTracker,
        add_labels: L,
        add_annotations: A,
    ) -> Result<Deployment>
    where
        S: ToString,
        L: FnOnce(&mut BTreeMap<String, String>),
        A: FnOnce(&mut BTreeMap<String, String>),
    {
        let prefix = ditto.name();

        let cluster_marker = format!("{}-cluster", prefix);

        self.create_defaults(
            &ditto,
            &mut deployment,
            |labels| {
                add_labels(labels);
                labels.insert("akka.cluster".into(), cluster_marker);
                labels.insert(KUBERNETES_LABEL_COMPONENT.into(), "backend".into());
            },
            vec![],
            |annotations| {
                add_annotations(annotations);
                annotations.remove(OPENSHIFT_ANNOTATION_CONNECT);
            },
        );

        deployment.owned_by_controller(ditto)?;

        if deployment.spec.is_none() {
            deployment.spec = Some(Default::default());
        }

        if let Some(ref mut spec) = deployment.spec {
            spec.template.metadata.use_or_create(|metadata| {
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

                container.command(vec!["java"]); 
                container.args(vec![ "-jar", "/opt/ditto/starter.jar"]);

                container.add_port("http", 8080, None)?;
                container.add_port("remoting", 2551, None)?;
                container.add_port("management", 8558, None)?;

                container.add_env("DISCOVERY_METHOD", "akka-dns")?;
                container.add_env("CLUSTER_BS_SERVICE_NAME", format!("{}-akka", prefix))?;
                container.add_env("CLUSTER_BS_SERVICE_NAMESPACE", ditto.namespace().unwrap_or_default())?;

                container.add_env("OPENJ9_JAVA_OPTIONS", "-XX:+ExitOnOutOfMemoryError -Xtune:virtualized -Xss512k -XX:MaxRAMPercentage=80 -XX:InitialRAMPercentage=40 -Dakka.coordinated-shutdown.exit-jvm=on -Dorg.mongodb.async.type=netty")?;
                container.add_env("MONGO_DB_SSL_ENABLED", "false")?;
                container.add_env_from_field_path("POD_NAMESPACE", "metadata.namespace")?;
                container.add_env_from_field_path("INSTANCE_INDEX", "metadata.name")?;
                container.add_env_from_field_path("HOSTNAME", "status.podIP")?;

                container.set_resources("memory", Some("1Gi"), Some("1Gi"));

                if let Some(uri_key) = uri_key {
                    container.add_env_from_secret("MONGO_DB_URI", prefix + "-mongodb-secret", uri_key)?;
                }

                self.add_probes(container)?;

                Ok(())
            })?;
        }

        Ok(deployment)
    }

    fn connects_to(&self, ditto: &Ditto, to: Vec<&str>) -> String {
        let name = ditto.name();

        let connects = to
            .iter()
            .map(|n| format!("{}-{}", n, name))
            .collect::<Vec<String>>();

        serde_json::to_string(&connects).unwrap_or_else(|_| "".into())
    }

    fn reconcile_nginx_deployment(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
        tracker: &ConfigTracker,
    ) -> Result<Deployment> {
        let prefix = ditto.name();

        self.create_defaults(
            &ditto,
            &mut deployment,
            |labels| {
                labels.insert(KUBERNETES_LABEL_COMPONENT.into(), "integration".into());
            },
            vec![],
            |annotations| {
                annotations.insert(
                    OPENSHIFT_ANNOTATION_CONNECT.into(),
                    self.connects_to(&ditto, vec!["gateway", "swaggerui"]),
                );
            },
        );

        deployment.owned_by_controller(ditto)?;

        if let Some(keycloak) = &ditto.spec.keycloak {
            deployment.apply_container("oauth-proxy", |container| {
                container.image = Some("quay.io/oauth2-proxy/oauth2-proxy:v7.0.1".into());
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
                    Self::keycloak_url_arg("--login-url", &keycloak, "/auth"),
                    Self::keycloak_url_arg("--redeem-url", &keycloak, "/token"),
                    Self::keycloak_url_arg("--profile-url", &keycloak, "/userinfo"),
                    Self::keycloak_url_arg("--validate-url", &keycloak, "/userinfo"),
                ];

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
        } else {
            deployment.remove_container_by_name("oauth-proxy");
        }

        deployment.spec.use_or_create_err(|spec| {
            spec.template.metadata.use_or_create(|metadata| {
                metadata.annotations.use_or_create(|annotations| {
                    annotations.insert("config-hash".into(), tracker.current_hash())
                });
            });

            let volumes = vec![
                nginx::Volume::empty_dir("nginx-cache", "/var/cache/nginx"),
                nginx::Volume::empty_dir("nginx-run", "/run/nginx"),
                nginx::Volume::configmap(
                    "nginx-conf",
                    "/etc/nginx/nginx.conf",
                    prefix.clone() + "-nginx-conf",
                )
                .with_sub_path("nginx.conf"),
                nginx::Volume::configmap(
                    "nginx-htpasswd",
                    "/etc/nginx/nginx.htpasswd",
                    prefix.clone() + "-nginx-htpasswd",
                )
                .with_sub_path("nginx.htpasswd"),
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

            nginx::apply_volumes(&volumes, &mut spec.template, "nginx")?;

            spec.template.apply_container("nginx", |mut container| {
                container.image = Some(NGINX_IMAGE.into());

                container.args = None;
                container.command = None;

                container.add_port("http", 8080, None)?;

                Self::default_nginx_probes("http", &mut container);

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

        self.create_defaults(
            &ditto,
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
                        container.image = Some("docker.io/swaggerapi/swagger-ui:v3.44.1".into());
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
                        container.image = Some("docker.io/swaggerapi/swagger-ui:v3.44.1".into());

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

    fn create_defaults<L, A>(
        &self,
        ditto: &Ditto,
        deployment: &mut Deployment,
        add_labels: L,
        add_selector_labels: Vec<String>,
        add_annotations: A,
    ) where
        L: FnOnce(&mut BTreeMap<String, String>),
        A: FnOnce(&mut BTreeMap<String, String>),
    {
        let ditto_name = ditto.name();
        let prefix = format!("{}-", ditto_name);
        let name = deployment.name();
        let name = if name.starts_with(&prefix) {
            name[prefix.len()..].to_string()
        } else {
            name
        };

        // add labels

        let mut labels = BTreeMap::new();

        labels.insert("app.kubernetes.io/name".into(), name.clone());
        labels.insert(
            "app.kubernetes.io/instance".into(),
            format!("{}-{}", name, ditto_name),
        );

        labels.insert("app.kubernetes.io/part-of".into(), ditto_name);
        labels.insert("app.kubernetes.io/version".into(), DITTO_VERSION.into());
        labels.insert(
            "app.kubernetes.io/managed-by".into(),
            "ditto-operator".into(),
        );

        add_labels(&mut labels);

        // set selector labels

        let mut selector_labels = BTreeMap::new();

        for (k, v) in &labels {
            if k == "app.kubernetes.io/name"
                || k == "app.kubernetes.io/instance"
                || add_selector_labels.contains(k)
            {
                selector_labels.insert(k.clone(), v.clone());
            }
        }

        debug!("Selector: {:?}", selector_labels);

        // set labels

        deployment.spec.use_or_create(|spec| {
            spec.selector.match_labels = Some(selector_labels);
            spec.template.metadata.use_or_create(|m| {
                m.labels.use_or_create(|l| {
                    l.extend(labels.clone());
                });
            });
        });

        deployment.metadata.labels = Some(labels);

        // add annotations

        deployment
            .metadata
            .annotations
            .use_or_create(|annotations| {
                add_annotations(annotations);
            });
    }

    fn service_selector(&self, component: &str, ditto: &Ditto) -> Vec<(String, String)> {
        vec![
            ("app.kubernetes.io/name".into(), component.to_string()),
            (
                "app.kubernetes.io/instance".into(),
                format!("{}-{}", component, ditto.name()),
            ),
        ]
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
}
