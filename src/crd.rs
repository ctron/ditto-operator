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
use kube_derive::CustomResource;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
#[kube(
    group = "iot.eclipse.org",
    version = "v1alpha1",
    kind = "Ditto",
    namespaced,
    derive = "PartialEq",
    status = "DittoStatus"
)]
#[kube(apiextensions = "v1beta1")]
#[serde(default)]
pub struct DittoSpec {
    pub mongo_db: MongoDb,
    pub enable_dummy_auth: bool,
    pub devops_secure_status: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(default)]
pub struct MongoDb {
    pub host: String,
    pub port: u16,
}

impl Default for MongoDb {
    fn default() -> Self {
        MongoDb {
            port: 27017,
            host: String::new(),
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
