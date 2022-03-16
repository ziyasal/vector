use std::collections::HashMap;

use bytes::Bytes;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use vrl::value::Value;

use crate::conditions::ConditionConfig;
use crate::{
    conditions::{datadog_search::DatadogSearchConfig, Condition},
    config::{DataType, Input, Output, TransformConfig, TransformContext},
    event::Event,
    schema,
    transforms::{FunctionTransform, OutputBuffer, Transform},
};
use sha_3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
struct ScanningGroup {
    id: String,
    filter: Condition,
    scanning_rules: Vec<ScanningRule>,
}

impl ScanningGroup {
    fn scan(&self, event: &mut Event) {
        if self.filter.check(event) {
            for rule in &self.scanning_rules {
                rule.scan(event);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ScanningRule {
    id: String,
    pattern: Regex,
    coverage: ScanningCoverage,
    tags: HashMap<String, String>,
    action: Action,
}

impl ScanningRule {
    fn scan(&self, event: &mut Event) {
        match event {
            Event::Log(log) => {
                match &self.coverage {
                    ScanningCoverage::Include(attributes) => {
                        for attribute in attributes {
                            if let Some(value) = log.get_mut(attribute.as_str()) {
                                self.scan_nested(value);
                            }
                        }
                    }
                    ScanningCoverage::Exclude(_) => {} // TODO
                }
            }
            _ => unimplemented!("Only log events can be scanned"),
        }
    }

    fn scan_nested(&self, value: &mut Value) {
        let mut values = vec![value];

        while let Some(value) = values.pop() {
            match value {
                Value::Bytes(val) => {
                    let mut content = std::str::from_utf8(val).unwrap();
                    let new_content = match &self.action {
                        Action::Scrub(replacement) => {
                            debug!("scrubbed with {:?}", replacement);
                            self.pattern.replace_all(content, replacement)
                        }
                        Action::Hash => {
                            debug!("hashed");
                            self.pattern.replace_all(content, |captures: &Captures| {
                                hex::encode(Sha3_256::digest(
                                    captures.get(1).map_or("", |m| m.as_str()).to_string(),
                                ))
                            })
                        }
                    };
                    let replacement = new_content.into_owned();
                    *val = Bytes::from(replacement);
                }
                Value::Object(val) => values.extend(val.values_mut()),
                Value::Array(val) => values.extend(val.iter_mut()),
                _ => continue,
            }
        }
    }
}

#[derive(Debug, Clone)]
enum ScanningCoverage {
    Include(Vec<String>),
    Exclude(Vec<String>),
}

#[derive(Debug, Clone)]
enum Action {
    Scrub(String),
    Hash,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DatadogSensitiveDataScannerConfig {}

fn build_tags(tags: &'static str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for tag in tags.split(",") {
        let pieces = tag.split(":").collect::<Vec<_>>();
        map.insert(pieces[0].to_string(), pieces[1].to_string());
    }
    map
}

#[async_trait::async_trait]
#[typetag::serde(name = "datadog_sensitive_data_scanner")]
impl TransformConfig for DatadogSensitiveDataScannerConfig {
    async fn build(&self, context: &TransformContext) -> crate::Result<Transform> {
        let amex_rule = ScanningRule {
            id: "amex rule".to_string(),
            pattern: Regex::new(r"").unwrap(),
            coverage: ScanningCoverage::Exclude(Vec::new()), // match entire event
            tags: build_tags(
                "sensitive_data:american_express_credit_card,sensitive_data_category:credit_card",
            ),
            action: Action::Hash,
        };

        let stripe_api_rule = ScanningRule {
            id: "stripe rule".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Include(vec!["message".to_string()]),
            tags: build_tags("sensitive_data_category:credentials,sensitive_data:stripe_api_key"),
            // action: Action::Scrub("REDACT".to_string()),
            action: Action::Hash,
        };

        let scanning_rules = vec![amex_rule, stripe_api_rule];

        let group = ScanningGroup {
            id: "group1".to_string(),
            filter: DatadogSearchConfig {
                source: "*".to_string(),
            }
            .build(&Default::default())
            .unwrap(),
            scanning_rules,
        };

        Ok(Transform::function(DatadogSensitiveDataScanner {
            groups: vec![group],
        }))
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn outputs(&self, _: &schema::Definition) -> Vec<Output> {
        vec![Output::default(DataType::all())]
    }

    fn enable_concurrency(&self) -> bool {
        true
    }

    fn transform_type(&self) -> &'static str {
        "datadog_sensitive_data_scanner"
    }
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct DatadogSensitiveDataScanner {
    groups: Vec<ScanningGroup>,
}

impl FunctionTransform for DatadogSensitiveDataScanner {
    fn transform(&mut self, output: &mut OutputBuffer, mut event: Event) {
        for group in &self.groups {
            group.scan(&mut event);
        }
        output.push(event);
    }
}
