use crate::crd::Ditto;
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, IngressBackend, IngressRule, IngressServiceBackend,
    ServiceBackendPort,
};
use kube::{api::DeleteParams, ResourceExt};
use operator_framework::{
    install::{meta::OwnedBy, Delete},
    process::create_or_update,
    utils::UseOrCreate,
};
use std::ops::Deref;

pub struct Ingress<'a>(pub &'a super::Context);

impl<'a> Deref for Ingress<'a> {
    type Target = super::Context;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl Ingress<'_> {
    pub async fn process(&self, ditto: &Ditto) -> anyhow::Result<()> {
        let prefix = ditto.name();
        let namespace = ditto.namespace().expect("Missing namespace");

        if let Some(ditto_ingress) = &ditto.spec.ingress {
            create_or_update(
                &self.ingress,
                Some(&namespace),
                prefix.clone() + "-console",
                |mut ingress| {
                    ingress.owned_by_controller(ditto)?;

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

        Ok(())
    }
}
