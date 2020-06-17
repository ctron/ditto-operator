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
mod controller;
mod crd;
mod data;

use kube::api::ListParams;
use kube::runtime::{Informer, Reflector};
use kube::{Api, Client};

use crd::Ditto;

use crate::controller::DittoController;
use async_std::sync::{Arc, Mutex};

async fn run_once(controller: &Arc<Mutex<DittoController>>, crds: Vec<Ditto>) {
    for crd in crds {
        let r = controller.lock().await.reconcile(&crd).await;

        match r {
            Err(e) => {
                log::warn!("Failed to reconcile: {}", e);
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let client = Client::try_default().await?;
    let namespace = std::env::var("NAMESPACE").unwrap_or("default".into());

    let dittos: Api<Ditto> = Api::namespaced(client.clone(), &namespace);
    let lp = ListParams::default().timeout(20); // low timeout in this example
    let rf = Reflector::new(dittos).params(lp);

    let inf: Informer<Ditto> = Informer::new(Api::namespaced(client.clone(), &namespace));

    let rf2 = rf.clone(); // read from a clone in a task

    let controller = Arc::new(Mutex::new(DittoController::new(&namespace, client)));
    let loop_controller = controller.clone();

    log::info!("Starting operator...");

    tokio::spawn(async move {
        tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
        loop {
            run_once(&loop_controller, rf2.state().await.unwrap()).await;
            tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
        }
    });

    rf.run().await?;

    Ok(())
}
