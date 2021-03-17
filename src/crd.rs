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
use kube_derive::CustomResource;
use operator_framework::install::ValueOrReference;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
#[kube(
    group = "iot.eclipse.org",
    version = "v1alpha1",
    kind = "Ditto",
    namespaced,
    derive = "Default",
    derive = "PartialEq",
    status = "DittoStatus"
)]
#[kube(apiextensions = "v1beta1")]
#[serde(default, rename_all = "camelCase")]
pub struct DittoSpec {
    pub mongo_db: MongoDb,
    pub devops_secure_status: bool,
    /// set the "false" to prevent creating the default "ditto" user.
    pub create_default_user: Option<bool>,
    /// allow to override the Ditto image version.
    pub version: Option<String>,
    /// Enable and configure keycloak integration.
    pub keycloak: Option<Keycloak>,

    /// Influence some options of the hosted OpenAPI spec.
    pub open_api: Option<OpenApi>,

    /// Configure an internal service.
    pub internal_service: Option<InternalService>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InternalService {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Keycloak {
    pub url: String,
    pub realm: String,

    pub client_id: ValueOrReference,
    pub client_secret: ValueOrReference,

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenApi {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_label: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(default)]
pub struct MongoDb {
    pub host: String,
    pub port: u16,
    pub database: Option<String>,

    pub username: Option<String>,
    pub password: Option<ValueOrReference>,
}

impl Default for MongoDb {
    fn default() -> Self {
        MongoDb {
            port: 27017,
            host: Default::default(),
            database: Default::default(),
            username: Default::default(),
            password: Default::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
pub struct DittoStatus {
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod test {

    use super::*;
    use k8s_openapi::Resource;

    #[test]
    fn verify_resource() {
        assert_eq!(Ditto::KIND, "Ditto");
        assert_eq!(Ditto::GROUP, "iot.eclipse.org");
        assert_eq!(Ditto::VERSION, "v1alpha1");
        assert_eq!(Ditto::API_VERSION, "iot.eclipse.org/v1alpha1");
    }
}
