use anyhow::{anyhow, Context, Result};
use serde_yaml::{Mapping, Sequence, Value};

#[derive(Clone, Debug, Default)]
pub struct ApiOptions {
    pub oauth_label: Option<String>,
    pub oauth_auth_url: Option<String>,
    pub oauth_description: Option<String>,
}

pub fn openapi_v1(options: &ApiOptions) -> Result<String> {
    openapi_inject(include_str!("../resources/ditto-api-v1.yaml"), options)
}

pub fn openapi_v2(options: &ApiOptions) -> Result<String> {
    openapi_inject(include_str!("../resources/ditto-api-v2.yaml"), options)
}

fn openapi_inject(api: &str, options: &ApiOptions) -> Result<String> {
    let mut api: Value = serde_yaml::from_str(api).context("Failed to parse OpenAPI YAML")?;

    // remove other remote servers

    let servers = api["servers"]
        .as_sequence_mut()
        .ok_or_else(|| anyhow!("Unable to finder 'server' section"))?;
    servers.retain(|server| {
        server["url"]
            .as_str()
            .map_or(false, |url| url.starts_with('/'))
    });

    // oauth

    if let Some(url) = &options.oauth_auth_url {
        let id = options
            .oauth_label
            .as_ref()
            .map_or_else(|| "SSO".to_string(), |s| s.clone());

        // remove other security options

        let security = api["security"]
            .as_sequence_mut()
            .ok_or_else(|| anyhow!("Unable to find 'security' section"))?;

        security.clear();

        // add "sso" entry with empty sequence
        let mut sso = Mapping::new();
        sso.insert(id.clone().into(), Value::Sequence(Sequence::new()));
        security.push(Value::Mapping(sso));

        // inject "sso" security scheme

        let security_schemes = api["components"]["securitySchemes"]
            .as_mapping_mut()
            .ok_or_else(|| anyhow!("Unable to find 'securitySchemes' section"))?;

        security_schemes.clear();

        let mut sso: Value = serde_yaml::from_str(
            r#"---
type: oauth2
description: SSO
flows:
  implicit:
    authorizationUrl: http://localhost
    scopes:
      openid: OpenID Connect
"#,
        )?;

        if let Some(desc) = &options.oauth_description {
            sso["description"] = Value::String(desc.clone());
        }

        sso["flows"]["implicit"]["authorizationUrl"] = Value::String(url.to_string());

        security_schemes.insert(id.into(), sso);
    }

    Ok(serde_yaml::to_string(&api).context("Failed to encode OpenAPI as YAML")?)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_openapi_v1() {
        let api = openapi_v1(&ApiOptions {
            oauth_auth_url: Some("https://foo.bar".into()),
            oauth_description: Some("Single sign-on".into()),
            oauth_label: Some("My Service".into()),
        })
        .unwrap();

        println!("{}", api);

        let api: Value = serde_yaml::from_str(&api).unwrap();

        assert_eq!(api["servers"].as_sequence().unwrap().len(), 1);

        // oauth section

        assert_eq!(api["security"].as_sequence().unwrap().len(), 1);
        assert_eq!(
            api["security"][0]["My Service"],
            Value::Sequence(Sequence::new())
        );
    }
}
