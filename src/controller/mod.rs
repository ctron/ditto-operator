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

mod context;
mod ditto;
mod ingress;
mod nginx;
mod rbac;
mod swaggerui;

use crate::{
    controller::{ingress::Ingress, nginx::Nginx, rbac::Rbac, swaggerui::SwaggerUi},
    crd::{Ditto, Keycloak},
};
use anyhow::{anyhow, Result};
use context::Context;
use indexmap::IndexMap;
use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{Container, HTTPGetAction, Probe, ServicePort},
    },
    apimachinery::pkg::util::intstr::IntOrString,
    ByteString,
};
use kube::{
    api::{DeleteParams, PostParams},
    Api, Client, ResourceExt,
};
use operator_framework::{
    conditions::{Conditions, State, StateBuilder},
    install::{
        config::AppendString,
        container::{
            ApplyContainer, ApplyEnvironmentVariable, ApplyPort, RemoveContainer, SetArgs,
            SetCommand, SetResources,
        },
        meta::OwnedBy,
        Delete, KubeReader,
    },
    process::create_or_update,
    tracker::{ConfigTracker, Trackable, TrackerState},
    utils::UseOrCreate,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{collections::BTreeMap, ops::Deref};

pub const KUBERNETES_LABEL_COMPONENT: &str = "app.kubernetes.io/component";
pub const OPENSHIFT_ANNOTATION_CONNECT: &str = "app.openshift.io/connects-to";

pub struct DittoController {
    context: Context,
}

impl Deref for DittoController {
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

impl DittoController {
    pub fn new(namespace: &str, client: Client, has_openshift: bool) -> Self {
        DittoController {
            context: Context {
                client: client.clone(),
                deployments: Api::namespaced(client.clone(), namespace),
                secrets: Api::namespaced(client.clone(), namespace),
                service_accounts: Api::namespaced(client.clone(), namespace),
                roles: Api::namespaced(client.clone(), namespace),
                role_bindings: Api::namespaced(client.clone(), namespace),
                services: Api::namespaced(client.clone(), namespace),
                configmaps: Api::namespaced(client.clone(), namespace),
                ingress: Api::namespaced(client, namespace),
                has_openshift,
            },
        }
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
                ditto.status.use_or_create(|status| {
                    status.phase = "Active".into();
                    status.message = None;
                    status.update_condition(
                        "Ready",
                        State::True
                            .with_reason("AsExpected")
                            .with_message("All is well"),
                    );
                });
                (ditto, Ok(()))
            }
            Err(err) => {
                let mut ditto = original_ditto.clone();
                ditto.status.use_or_create(|status| {
                    status.phase = "Failed".into();
                    status.message = Some(err.to_string());
                    status.update_condition(
                        "Ready",
                        State::False
                            .with_reason("Failed")
                            .with_message(err.to_string())
                            .with_observed(ditto.metadata.generation),
                    );
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

        let mut ditto_tracker = ConfigTracker::new();
        let mut gateway_tracker = ConfigTracker::new();
        let mut nginx_tracker = ConfigTracker::new();

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

        let devops_password = match ditto
            .spec
            .devops
            .as_ref()
            .and_then(|devops| devops.password.as_ref())
        {
            Some(password) => password.read_value(&reader).await?,
            None => None,
        };

        let status_password = match ditto
            .spec
            .devops
            .as_ref()
            .and_then(|devops| devops.status_password.as_ref())
        {
            Some(password) => password.read_value(&reader).await?,
            None => None,
        };

        create_or_update(
            &self.secrets,
            Some(&namespace),
            prefix.clone() + "-gateway-secret",
            |mut secret| {
                secret.owned_by_controller(&ditto)?;
                secret.data.use_or_create(|data| {
                    if let Some(password) = devops_password {
                        data.insert("devops-password".into(), ByteString(password.into()));
                    } else {
                        data.entry("devops-password".into()).or_insert_with(|| {
                            let pwd: String =
                                thread_rng().sample_iter(&Alphanumeric).take(30).collect();
                            ByteString(pwd.into())
                        });
                    }
                    if let Some(password) = status_password {
                        data.insert("status-password".into(), ByteString(password.into()));
                    } else {
                        data.entry("status-password".into()).or_insert_with(|| {
                            let pwd: String =
                                thread_rng().sample_iter(&Alphanumeric).take(30).collect();
                            ByteString(pwd.into())
                        });
                    }

                    data.track_with(&mut ditto_tracker);
                });

                Ok::<_, anyhow::Error>(secret)
            },
        )
        .await?;

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
                secret.track_with(&mut ditto_tracker);
                Ok::<_, anyhow::Error>(secret)
            },
        )
        .await?;

        Rbac(&self.context)
            .process(&ditto, service_account_name.clone())
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

        let ditto_tracker = ditto_tracker.freeze();

        // extend the gateway tracker with the ditto tracker
        gateway_tracker.track(&ditto_tracker);

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-concierge",
            |obj| self.reconcile_concierge_deployment(&ditto, obj, ditto_tracker.clone()),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-connectivity",
            |obj| self.reconcile_connectivity_deployment(&ditto, obj, ditto_tracker.clone()),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-gateway",
            |obj| self.reconcile_gateway_deployment(&ditto, obj, gateway_tracker.freeze()),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-policies",
            |obj| self.reconcile_policies_deployment(&ditto, obj, ditto_tracker.clone()),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-things",
            |obj| self.reconcile_things_deployment(&ditto, obj, ditto_tracker.clone()),
        )
        .await?;

        create_or_update(
            &self.deployments,
            Some(&namespace),
            prefix.clone() + "-things-search",
            |obj| self.reconcile_things_search_deployment(&ditto, obj, ditto_tracker.clone()),
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

        SwaggerUi(&self.context)
            .process(&ditto, &mut nginx_tracker)
            .await?;
        Nginx(&self.context).process(&ditto, nginx_tracker).await?;
        Ingress(&self.context).process(&ditto).await?;

        Ok(ditto)
    }

    fn reconcile_concierge_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: TrackerState,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            self.ditto_image_name("ditto-concierge", ditto),
            Some("concierge-uri"),
            config_tracker,
            default_system_properties(),
            |_| {},
            |_| {},
        )
    }

    fn reconcile_gateway_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: TrackerState,
    ) -> Result<Deployment> {
        let prefix = ditto.name();

        let props = {
            let mut props = IndexMap::new();
            if let Some(keycloak) = &ditto.spec.keycloak {
                let issuer_url = format!(
                    "{url}/auth/realms/{realm}",
                    url = keycloak.url,
                    realm = keycloak.realm
                );

                // we need to insert this in the front, as `-D` is an argument for the JVM, not the application
                if let Some(url) = issuer_url.strip_prefix("https://") {
                    props.insert(
                        "ditto.gateway.authentication.oauth.openid-connect-issuers.keycloak.issuer"
                            .to_string(),
                        url.to_string(),
                    );
                } else if let Some(url) = issuer_url.strip_prefix("http://") {
                    props.insert(
                        "ditto.gateway.authentication.oauth.openid-connect-issuers.keycloak.issuer"
                            .to_string(),
                        url.to_string(),
                    );
                    props.insert(
                        "ditto.gateway.authentication.oauth.protocol".to_string(),
                        "http".to_string(),
                    );
                } else {
                    anyhow::bail!("Using a non-http(s) issuer URL with Ditto is not supported");
                }
                props.insert(
                    "ditto.gateway.authentication.oauth.openid-connect-issuers.keycloak.auth-subjects.0".to_string(),
                    "{{ jwt:sub }}".to_string()
                );
                props.insert(
                    "ditto.gateway.authentication.oauth.openid-connect-issuers.keycloak.auth-subjects.1".to_string(),
                    "{{ jwt:realm_access/roles }}".to_string()
                );
            }

            props
        };

        let mut deployment = self.reconcile_default_deployment(
            ditto,
            deployment,
            self.ditto_image_name("ditto-gateway", ditto),
            None,
            config_tracker,
            default_system_properties().append(props),
            |_| {},
            |_| {},
        )?;

        // that was a mistake, it belongs to the nginx
        deployment.remove_container_by_name("oauth-proxy");

        deployment.apply_container("service", |container| {
            // deprecated variables
            container.drop_env("ENABLE_DUMMY_AUTH");
            container.drop_env("DEVOPS_SECURE_STATUS");

            container.add_env(
                "ENABLE_PRE_AUTHENTICATION",
                self.want_preaut(ditto).to_string(),
            )?;

            container.add_env(
                "DEVOPS_SECURED",
                (!ditto
                    .spec
                    .devops
                    .as_ref()
                    .map(|devops| devops.insecure)
                    .unwrap_or_default())
                .to_string(),
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
        config_tracker: TrackerState,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            self.ditto_image_name("ditto-connectivity", ditto),
            Some("connectivity-uri"),
            config_tracker,
            default_system_properties().append([(
                "akka.cluster.distributed-data.durable.lmdb.dir".to_string(),
                "/var/tmp/ditto/ddata".to_string(),
            )]),
            |_| {},
            |_| {},
        )
    }

    fn reconcile_policies_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: TrackerState,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            self.ditto_image_name("ditto-policies", ditto),
            Some("policies-uri"),
            config_tracker,
            default_system_properties(),
            |_| {},
            |_| {},
        )
    }

    fn reconcile_things_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: TrackerState,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            self.ditto_image_name("ditto-things", ditto),
            Some("things-uri"),
            config_tracker,
            default_system_properties(),
            |_| {},
            |_| {},
        )
    }

    fn reconcile_things_search_deployment(
        &self,
        ditto: &Ditto,
        deployment: Deployment,
        config_tracker: TrackerState,
    ) -> Result<Deployment> {
        self.reconcile_default_deployment(
            ditto,
            deployment,
            self.ditto_image_name("ditto-things-search", ditto),
            Some("searchDB-uri"),
            config_tracker,
            default_system_properties(),
            |_| {},
            |_| {},
        )
    }

    fn reconcile_default_deployment<S, SP, L, A>(
        &self,
        ditto: &Ditto,
        mut deployment: Deployment,
        image_name: S,
        uri_key: Option<&str>,
        config_tracker: TrackerState,
        add_system_properties: SP,
        add_labels: L,
        add_annotations: A,
    ) -> Result<Deployment>
    where
        S: ToString,
        SP: IntoIterator<Item = (String, String)>,
        L: FnOnce(&mut BTreeMap<String, String>),
        A: FnOnce(&mut BTreeMap<String, String>),
    {
        let prefix = ditto.name();

        let cluster_marker = format!("{}-cluster", prefix);

        self.create_defaults(
            ditto,
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
                    annotations
                        .insert("ditto.iot.eclipse.org/config-hash".into(), config_tracker.0);
                });
            });

            spec.template.spec.use_or_create(|template_spec| {
                template_spec.service_account_name = Some(prefix.clone());
            });

            spec.template.apply_container("service", |container| {
                let image_name = image_name.to_string();
                container.image_pull_policy = pull_policy(ditto, &image_name);
                container.image = Some(image_name);

                container.command(vec!["java"]);

                let mut args:Vec<_> = add_system_properties.into_iter().map(|(k,v)|format!("-D{}={}", k, v )).collect();
                args.extend(["-jar".to_string(), "/opt/ditto/starter.jar".to_string()]);
                container.args(args);

                container.add_port("http", 8080, None)?;
                container.add_port("remoting", 2551, None)?;
                container.add_port("management", 8558, None)?;

                container.add_env("DISCOVERY_METHOD", "akka-dns")?;
                container.add_env("CLUSTER_BS_SERVICE_NAME", format!("{}-akka", prefix))?;
                container.add_env("CLUSTER_BS_SERVICE_NAMESPACE", ditto.namespace().unwrap_or_default())?;

                container.add_env("OPENJ9_JAVA_OPTIONS", "-XX:+ExitOnOutOfMemoryError -Xtune:virtualized -Xss512k -XX:MaxRAMPercentage=80 -XX:InitialRAMPercentage=40 -Dorg.mongodb.async.type=netty")?;
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

fn default_system_properties() -> IndexMap<String, String> {
    let mut map = IndexMap::new();
    map.insert(
        "akka.cluster.failure-detector.threshold".to_string(),
        "15.0".to_string(),
    );
    map.insert(
        "akka.cluster.failure-detector.expected-response-after".to_string(),
        "10s".to_string(),
    );
    map.insert(
        "akka.cluster.failure-detector.acceptable-heartbeat-pause".to_string(),
        "30s".to_string(),
    );
    map.insert(
        "akka.cluster.shutdown-after-unsuccessful-join-seed-nodes".to_string(),
        "120s".to_string(),
    );
    map.insert(
        "akka.coordinated-shutdown.exit-jvm".to_string(),
        "on".to_string(),
    );
    map
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
    format!("{}={}", arg, keycloak_url(keycloak, path))
}

fn pull_policy<S: AsRef<str>>(ditto: &Ditto, image_name: S) -> Option<String> {
    Some(match &ditto.spec.pull_policy {
        Some(policy) => policy.to_string(),
        None if image_name.as_ref().ends_with(":latest") => "Always".to_string(),
        None => "IfNotPresent".to_string(),
    })
}

pub trait Append<A> {
    fn append_one<T>(self, item: T) -> Self
    where
        T: Into<A>;
    fn append<T>(self, iter: T) -> Self
    where
        T: IntoIterator<Item = A>;
}

impl<E, A> Append<A> for E
where
    E: Extend<A>,
{
    fn append_one<T>(mut self, item: T) -> Self
    where
        T: Into<A>,
    {
        self.extend([item.into()]);
        self
    }
    fn append<T>(mut self, iter: T) -> Self
    where
        T: IntoIterator<Item = A>,
    {
        self.extend(iter);
        self
    }
}
