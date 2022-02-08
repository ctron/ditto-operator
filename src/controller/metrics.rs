use crate::crd::Ditto;
use std::collections::BTreeMap;

pub const fn default_prometheus_port() -> i32 {
    9095
}

pub fn add_annotations(ditto: &Ditto, annotations: &mut BTreeMap<String, String>) {
    if ditto.spec.metrics.enabled {
        annotations.insert("prometheus.io/scrape".to_string(), "true".to_string());
        annotations.insert("prometheus.io/path".to_string(), "/".to_string());
        annotations.insert(
            "prometheus.io/port".to_string(),
            format!("{}", default_prometheus_port()),
        );
    } else {
        annotations.retain(|k, _| k.starts_with("prometheus.io/"));
    }
}
