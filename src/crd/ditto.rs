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
use k8s_openapi::api::core::v1::ResourceRequirements;
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::Condition,
    chrono::{DateTime, Utc},
};
use kube::CustomResource;
use operator_framework::{
    conditions::{Conditions, StateDetails},
    install::ValueOrReference,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Default, Debug, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "iot.eclipse.org",
    version = "v1alpha1",
    kind = "Ditto",
    namespaced,
    derive = "Default",
    derive = "PartialEq",
    status = "DittoStatus"
)]
#[kube(printcolumn = r#"{"name": "Phase", "jsonPath": ".status.phase", "type": "string"}"#)]
#[kube(printcolumn = r#"{"name": "Message", "jsonPath": ".status.message", "type": "string"}"#)]
#[serde(default, rename_all = "camelCase")]
pub struct DittoSpec {
    pub mongo_db: MongoDb,

    /// Don't expose infra endpoints
    #[serde(skip_serializing_if = "is_default")]
    pub disable_infra_proxy: bool,

    /// Create the default "ditto" user when initially deploying.
    ///
    /// This has no effect when using OAuth2.
    pub create_default_user: Option<bool>,
    /// Allow to override the Ditto image version.
    pub version: Option<String>,
    /// Allow to override the Ditto container registry
    pub registry: Option<String>,
    /// Override the imagePullPolicy
    ///
    /// By default this will use Always if the image version is ":latest" and IfNotPresent otherwise
    pub pull_policy: Option<String>,
    /// Enable and configure keycloak integration.
    pub keycloak: Option<Keycloak>,

    /// Provide additional OAuth configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OAuth>,

    /// Influence some options of the hosted OpenAPI spec.
    pub open_api: Option<OpenApi>,

    /// Influence some options of the hosted SwaggerUI.
    pub swagger_ui: Option<SwaggerUi>,

    /// Allow disabling the welcome page
    #[serde(skip_serializing_if = "is_default")]
    pub disable_welcome_page: bool,

    /// Configure ingress options
    ///
    /// If the field is missing, no ingress resource is being created.
    pub ingress: Option<IngressSpec>,

    /// Devops endpoint
    pub devops: Option<Devops>,

    /// Services configuration
    #[serde(default)]
    pub services: Services,

    #[serde(default)]
    pub metrics: Metrics,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    /// Enable metrics integration
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Services {
    /// The concierge service
    #[serde(default)]
    pub concierge: ServiceSpec,
    /// The connectivity service
    #[serde(default)]
    pub connectivity: ServiceSpec,
    /// The gateway service
    #[serde(default)]
    pub gateway: ServiceSpec,
    /// The policies service
    #[serde(default)]
    pub policies: ServiceSpec,
    /// The things service
    #[serde(default)]
    pub things: ServiceSpec,
    /// The things search service
    #[serde(default)]
    pub things_search: ServiceSpec,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Number of replicas. Defaults to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,

    /// Service resource limits
    pub resources: Option<ResourceRequirements>,
    /// Additional system properties, which will be appended to the list of system properties.
    ///
    /// Note: Setting arbitrary system properties may break the deployment and may also not be
    /// compatible with future versions.
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_properties: BTreeMap<String, String>,
    /// Allow configuring the application log level.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[serde(alias = "information")]
    Info,
    #[serde(alias = "warn")]
    Warning,
    Error,
}

impl LogLevel {
    pub fn into_value(self) -> String {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Error => "ERROR",
        }
        .to_string()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Devops {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<ValueOrReference>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_password: Option<ValueOrReference>,

    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub insecure: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub expose: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IngressSpec {
    /// The host of the ingress resource.
    ///
    /// This is required if the ingress resource should be created by the operator
    pub host: String,
    /// The optional ingress class name.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    /// Annotations which should be applied to the ingress resources.
    ///
    /// The annotations will be set to the resource, not merged. All changes done on the ingress
    /// resource itself will be overridden.
    ///
    /// If no annotations are configured, reasonable defaults will be used instead. You can
    /// prevent this by setting a single dummy annotation.
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SwaggerUi {
    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub disable: bool,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// Keycloak configuration options.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Keycloak {
    pub url: String,
    pub realm: String,

    pub client_id: ValueOrReference,
    pub client_secret: ValueOrReference,

    #[serde(default)]
    #[serde(skip_serializing_if = "is_default")]
    pub disable_proxy: bool,

    /// Allow overriding the redirect URL.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,

    /// Label when referencing this login option.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Description of this login option.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OAuth {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub issuers: BTreeMap<String, OAuthIssuer>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OAuthIssuer {
    pub url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
}

fn is_default<T: Default + Eq>(value: &T) -> bool {
    *value == T::default()
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OpenApi {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_label: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(default)]
pub struct MongoDb {
    /// The hostname of the MongoDB instance.
    pub host: String,
    /// The port name of the MongoDB instance.
    pub port: u16,
    /// The optional database name used to connect, defaults to "ditto".
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<ValueOrReference>,

    /// The username used to connect to the MongoDB instance.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<ValueOrReference>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The password used to connect to the MongoDB instance.
    pub password: Option<ValueOrReference>,
}

impl Default for MongoDb {
    fn default() -> Self {
        MongoDb {
            port: 27017,
            host: "mongodb".into(),
            database: Default::default(),
            username: Default::default(),
            password: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, JsonSchema)]
#[serde(default)]
pub struct DittoStatus {
    /// The phase the deployment is in.
    pub phase: String,

    /// An optional message
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Status conditions
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

impl Conditions for DittoStatus {
    fn update_condition_on<S, D, DT>(&mut self, r#type: S, state: D, now: DT)
    where
        S: AsRef<str>,
        D: Into<StateDetails>,
        DT: Into<DateTime<Utc>>,
    {
        self.conditions.update_condition_on(r#type, state, now)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use kube::Resource;

    #[test]
    fn verify_resource() {
        assert_eq!(Ditto::kind(&()), "Ditto");
        assert_eq!(Ditto::group(&()), "iot.eclipse.org");
        assert_eq!(Ditto::version(&()), "v1alpha1");
        assert_eq!(Ditto::api_version(&()), "iot.eclipse.org/v1alpha1");
    }
}
