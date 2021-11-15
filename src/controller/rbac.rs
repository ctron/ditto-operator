use crate::crd::Ditto;
use k8s_openapi::api::{
    core::v1::ServiceAccount,
    rbac::v1::{PolicyRule, Role, Subject},
};
use k8s_openapi::Resource;
use kube::ResourceExt;
use operator_framework::{install::meta::OwnedBy, process::create_or_update};
use std::ops::Deref;

pub struct Rbac<'a>(pub &'a super::Context);

impl<'a> Deref for Rbac<'a> {
    type Target = super::Context;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> Rbac<'a> {
    pub async fn process(&self, ditto: &Ditto, service_account_name: String) -> anyhow::Result<()> {
        let prefix = ditto.name();
        let namespace = ditto.namespace().expect("Missing namespace");

        create_or_update(
            &self.service_accounts,
            Some(&namespace),
            &service_account_name,
            |mut service_account| {
                service_account.owned_by_controller(ditto)?;
                Ok::<_, anyhow::Error>(service_account)
            },
        )
        .await?;

        create_or_update(&self.roles, Some(&namespace), &prefix, |mut role| {
            role.owned_by_controller(ditto)?;
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
                role_binding.owned_by_controller(ditto)?;

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

        Ok(())
    }
}
