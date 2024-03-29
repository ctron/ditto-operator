// required for kube-runtime
#![type_length_limit = "20000000"]

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

use ditto_operator::controller::DittoController;
use ditto_operator::crd::Ditto;

use futures::StreamExt;
use k8s_openapi::api::{
    apps::v1::Deployment,
    core::v1::{ConfigMap, Secret, Service, ServiceAccount},
    networking::v1::Ingress,
    rbac::v1::{Role, RoleBinding},
};
use kube::{
    api::ListParams,
    runtime::{
        controller::{Context, Controller, ReconcilerAction},
        reflector::ObjectRef,
    },
    Api, Client,
};
use snafu::Snafu;
use std::{error::Error, fmt, time::Duration};

#[derive(Debug, Snafu)]
enum ReconcileError {
    ControllerError { source: anyhow::Error },
}

#[derive(Debug, Clone)]
struct StringError {
    message: String,
}

impl Error for StringError {}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.message)
    }
}

fn has_flag<S>(name: S, default_value: bool) -> anyhow::Result<bool>
where
    S: AsRef<str>,
{
    Ok(std::env::var_os(name.as_ref())
        .map(|s| s.into_string())
        .transpose()
        .map_err(|err| StringError {
            message: err.to_string_lossy().into(),
        })?
        .map_or(default_value, |s| s == "true"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let client = Client::try_default().await?;
    let namespace = std::env::var("NAMESPACE").unwrap_or_else(|_| "default".into());
    let has_openshift = has_flag("HAS_OPENSHIFT", false)?;

    let controller = DittoController::new(&namespace, client.clone(), has_openshift);
    let context = Context::new(controller);

    log::info!("Starting operator...");

    let dittos: Api<Ditto> = Api::namespaced(client.clone(), &namespace);
    let mut c = Controller::new(dittos, ListParams::default());

    c = c.shutdown_on_signal();

    // trigger changes for every configmap and secret, as any of them could be referenced
    let store = c.store();
    c = c.watches(
        Api::<ConfigMap>::namespaced(client.clone(), &namespace),
        Default::default(),
        move |_| store.state().into_iter().map(|i| ObjectRef::from_obj(&i)),
    );
    let store = c.store();
    c = c.watches(
        Api::<Secret>::namespaced(client.clone(), &namespace),
        Default::default(),
        move |_| store.state().into_iter().map(|i| ObjectRef::from_obj(&i)),
    );

    c = c
        .owns(
            Api::<Deployment>::namespaced(client.clone(), &namespace),
            Default::default(),
        )
        .owns(
            Api::<Role>::namespaced(client.clone(), &namespace),
            Default::default(),
        )
        .owns(
            Api::<RoleBinding>::namespaced(client.clone(), &namespace),
            Default::default(),
        )
        .owns(
            Api::<Service>::namespaced(client.clone(), &namespace),
            Default::default(),
        )
        .owns(
            Api::<ServiceAccount>::namespaced(client.clone(), &namespace),
            Default::default(),
        )
        .owns(
            Api::<Ingress>::namespaced(client.clone(), &namespace),
            Default::default(),
        );

    // now run it

    c.run(
        |resource, context| async {
            match context.into_inner().reconcile(resource).await {
                Ok(_) => Ok(ReconcilerAction {
                    requeue_after: None,
                }),
                Err(err) => Err(ReconcileError::ControllerError { source: err }),
            }
        },
        |_, _| ReconcilerAction {
            requeue_after: Some(Duration::from_secs(60)),
        },
        context,
    )
    // the next two lines are required to poll from the stream
    .for_each(|res| async move {
        match res {
            Ok(o) => log::debug!("reconciled {:?}", o),
            Err(e) => log::info!("reconcile failed: {:?}", e),
        }
    })
    .await;

    Ok(())
}
