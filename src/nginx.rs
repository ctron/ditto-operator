use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, EmptyDirVolumeSource, PodTemplateSpec, SecretVolumeSource,
};
use operator_framework::install::container::{
    ApplyContainer, ApplyVolume, ApplyVolumeMount, DropVolume,
};

#[derive(Clone, Debug)]
pub enum Source {
    EmptyDir,
    ConfigMap(String),
    Secret(String),
}

#[derive(Clone, Debug)]
pub struct Volume {
    pub name: String,
    pub path: String,
    pub sub_path: Option<String>,
    pub source: Source,
}

impl Volume {
    pub fn empty_dir<S1, S2>(name: S1, path: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            name: name.into(),
            path: path.into(),
            sub_path: None,
            source: Source::EmptyDir,
        }
    }

    pub fn configmap<S1, S2, S3>(name: S1, path: S2, source: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Volume {
            name: name.into(),
            path: path.into(),
            sub_path: None,
            source: Source::ConfigMap(source.into()),
        }
    }

    pub fn secret<S1, S2, S3>(name: S1, path: S2, source: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<String>,
    {
        Volume {
            name: name.into(),
            path: path.into(),
            sub_path: None,
            source: Source::Secret(source.into()),
        }
    }

    pub fn with_sub_path<S: Into<String>>(mut self, sub_path: S) -> Self {
        self.sub_path = Some(sub_path.into());
        self
    }
}

pub fn drop_volumes(volumes: &Vec<Volume>, spec: &mut PodTemplateSpec) -> anyhow::Result<()> {
    for v in volumes {
        spec.drop_volume(&v.name);
    }

    Ok(())
}

pub fn apply_volumes<S>(
    volumes: &[Volume],
    spec: &mut PodTemplateSpec,
    container_name: S,
) -> anyhow::Result<()>
where
    S: AsRef<str>,
{
    spec.apply_container(container_name.as_ref(), |container| {
        for v in volumes {
            container.apply_volume_mount(&v.name, |volume| {
                volume.mount_path = v.path.clone();
                volume.sub_path = v.sub_path.as_ref().cloned();
                Ok(())
            })?;
        }

        Ok(())
    })?;

    for v in volumes {
        spec.apply_volume(&v.name, |volume| {
            match &v.source {
                Source::EmptyDir => {
                    volume.empty_dir = Some(EmptyDirVolumeSource {
                        ..Default::default()
                    });
                    volume.config_map = None;
                    volume.secret = None;
                }
                Source::ConfigMap(name) => {
                    volume.config_map = Some(ConfigMapVolumeSource {
                        name: Some(name.clone()),
                        ..Default::default()
                    });
                    volume.empty_dir = None;
                    volume.secret = None;
                }
                Source::Secret(name) => {
                    volume.secret = Some(SecretVolumeSource {
                        secret_name: Some(name.clone()),
                        ..Default::default()
                    });
                    volume.empty_dir = None;
                    volume.config_map = None;
                }
            }
            Ok(())
        })?;
    }

    Ok(())
}
