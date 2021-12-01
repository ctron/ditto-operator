use crate::crd::Ditto;
use k8s_openapi::api::{
    apps::v1::Deployment,
    core::v1::{ConfigMap, Secret, Service, ServiceAccount},
    networking::v1::Ingress,
    rbac::v1::{Role, RoleBinding},
};
use kube::{Api, Client, ResourceExt};
use log::debug;
use operator_framework::utils::UseOrCreate;
use std::collections::BTreeMap;
use std::fmt::Display;

pub struct Context {
    pub client: Client,
    pub deployments: Api<Deployment>,
    pub secrets: Api<Secret>,
    pub configmaps: Api<ConfigMap>,
    pub service_accounts: Api<ServiceAccount>,
    pub roles: Api<Role>,
    pub role_bindings: Api<RoleBinding>,
    pub services: Api<Service>,
    pub ingress: Api<Ingress>,
    pub has_openshift: bool,
}

impl Context {
    pub fn service_selector(&self, component: &str, ditto: &Ditto) -> Vec<(String, String)> {
        vec![
            ("app.kubernetes.io/name".into(), component.to_string()),
            (
                "app.kubernetes.io/instance".into(),
                format!("{}-{}", component, ditto.name()),
            ),
        ]
    }

    pub fn want_welcome(&self, ditto: &Ditto) -> bool {
        !ditto.spec.disable_welcome_page
    }

    pub fn want_swagger(&self, ditto: &Ditto) -> bool {
        !ditto
            .spec
            .swagger_ui
            .as_ref()
            .map(|ui| ui.disable)
            .unwrap_or_default()
    }

    pub fn ditto_image_name<S>(&self, base: S, ditto: &Ditto) -> String
    where
        S: ToString + Display,
    {
        format!(
            "{}/{}:{}",
            Self::ditto_image_registry(ditto),
            base,
            Self::ditto_image_version(ditto)
        )
    }

    pub fn ditto_image_registry(ditto: &Ditto) -> &str {
        ditto
            .spec
            .registry
            .as_deref()
            .unwrap_or(super::ditto::DITTO_REGISTRY)
    }

    pub fn ditto_image_version(ditto: &Ditto) -> &str {
        ditto
            .spec
            .version
            .as_deref()
            .unwrap_or(super::ditto::DITTO_VERSION)
    }

    pub fn connects_to(&self, ditto: &Ditto, to: Vec<&str>) -> String {
        let name = ditto.name();

        let connects = to
            .iter()
            .map(|n| format!("{}-{}", n, name))
            .collect::<Vec<String>>();

        serde_json::to_string(&connects).unwrap_or_else(|_| "".into())
    }

    pub fn create_defaults<L, A>(
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
        labels.insert(
            "app.kubernetes.io/version".into(),
            super::ditto::DITTO_VERSION.into(),
        );
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
}
