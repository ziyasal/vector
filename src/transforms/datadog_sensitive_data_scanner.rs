use std::collections::HashMap;

use bytes::Bytes;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use vector_core::event::LogEvent;
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
        trace!("Running scanning group: {:?}", self.id);
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
        trace!("Running scanning rule: {:?}", self.id);
        match event {
            Event::Log(log) => match &self.coverage {
                ScanningCoverage::Include(attributes) => {
                    let mut inserted_tags = false;
                    for attribute in attributes {
                        if let Some(value) = log.get_mut(attribute.as_str()) {
                            let scanned = self.scan_nested(value);
                            if !inserted_tags && scanned {
                                inserted_tags = true;
                                self.insert_tags(log);
                            }
                        }
                    }
                }
                ScanningCoverage::Exclude(attributes) => {
                    let mut inserted_tags = false;
                    let lookups = log
                        .keys()
                        .filter(|k| !attributes.iter().any(|attribute| k.starts_with(attribute)))
                        .collect::<Vec<_>>();
                    for lookup in lookups {
                        if let Some(value) = log.get_mut(lookup.as_str()) {
                            let scanned = self.scan_nested(value);
                            if !inserted_tags && scanned {
                                inserted_tags = true;
                                self.insert_tags(log);
                            }
                        }
                    }
                }
            },
            _ => unimplemented!("Only log events can be scanned"),
        }
    }

    fn scan_nested(&self, value: &mut Value) -> bool {
        let mut values = vec![value];
        let mut matched = false;

        while let Some(value) = values.pop() {
            match value {
                Value::Bytes(val) => {
                    let content = std::str::from_utf8(val).unwrap();
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

                    // Set matched to true if a pattern has matched
                    if let std::borrow::Cow::Owned(_) = new_content {
                        matched = true;
                    }

                    let replacement = new_content.into_owned();
                    *val = Bytes::from(replacement);
                }
                Value::Object(val) => values.extend(val.values_mut()),
                Value::Array(val) => values.extend(val.iter_mut()),
                _ => continue,
            }
        }
        matched
    }

    fn insert_tags(&self, event: &mut LogEvent) {
        for (key, value) in self.tags.iter() {
            event.insert(key.as_str(), value.clone());
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
        if pieces.len() >= 2 {
            map.insert(pieces[0].to_string(), pieces[1].to_string());
        }
    }
    map
}

fn build_filter(s: &'static str) -> Condition {
    DatadogSearchConfig {
        source: s.to_string(),
    }
    .build(&Default::default())
    .unwrap()
}

#[async_trait::async_trait]
#[typetag::serde(name = "datadog_sensitive_data_scanner")]
impl TransformConfig for DatadogSensitiveDataScannerConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        let amex_rule = ScanningRule {
            id: "card rule".to_string(),
            pattern: Regex::new(r"").unwrap(),
            coverage: ScanningCoverage::Exclude(Vec::new()), // match entire event
            tags: build_tags(
                "sensitive_data:american_express_credit_card,sensitive_data_category:credit_card",
            ),
            action: Action::Hash,
        };

        let stripe_api_rule = ScanningRule {
            id: "api key rule".to_string(),
            pattern: Regex::new(r"").unwrap(),
            coverage: ScanningCoverage::Exclude(Vec::new()), // match entire event
            tags: build_tags("sensitive_data_category:credentials,sensitive_data:stripe_api_key"),
            action: Action::Scrub("REDACT".to_string()),
        };

        let scanning_rules = vec![amex_rule, stripe_api_rule];

        let group = ScanningGroup {
            id: "group1".to_string(),
            filter: build_filter("*"),
            scanning_rules,
        };

        Ok(Transform::function(DatadogSensitiveDataScanner::new(vec![
            group,
        ])))
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

impl DatadogSensitiveDataScanner {
    fn new(groups: Vec<ScanningGroup>) -> Self {
        Self { groups }
    }
}

impl FunctionTransform for DatadogSensitiveDataScanner {
    fn transform(&mut self, output: &mut OutputBuffer, mut event: Event) {
        for group in &self.groups {
            group.scan(&mut event);
        }
        output.push(event);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{event::Event, transforms::test::transform_one};

    #[test]
    fn hash_includes_simple() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Include(vec!["message".to_string()]),
            tags: build_tags("sensitive_data_category:credentials,sensitive_data:api_key"),
            action: Action::Hash,
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter("*"),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);
        let event = Event::from("hello world");

        let mut result = transform_one(&mut scanner, event).unwrap().into_log();
        assert_eq!(
            Value::from("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a world"),
            result.remove("message").unwrap()
        );
        assert_eq!(
            Value::from("credentials"),
            result.remove("sensitive_data_category").unwrap()
        );
        assert_eq!(
            Value::from("api_key"),
            result.remove("sensitive_data").unwrap()
        );
    }

    #[test]
    fn scrub_includes_simple() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Include(vec!["message".to_string()]),
            tags: build_tags("sensitive_data_category:credentials,sensitive_data:api_key"),
            action: Action::Scrub("REDACTED".to_string()),
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter("*"),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);
        let event = Event::from("hello world");

        let mut result = transform_one(&mut scanner, event).unwrap().into_log();
        assert_eq!(
            Value::from("REDACTED world"),
            result.remove("message").unwrap()
        );
        assert_eq!(
            Value::from("credentials"),
            result.remove("sensitive_data_category").unwrap()
        );
        assert_eq!(
            Value::from("api_key"),
            result.remove("sensitive_data").unwrap()
        );
    }

    #[test]
    fn scrub_includes_nested() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Include(vec!["namespace".to_string()]),
            tags: build_tags(""),
            action: Action::Scrub("REDACTED".to_string()),
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter("*"),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);

        let event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "namespace": { "nope": 1, "nada": "goodbye", "match": { "here": "hello world" } }, "boolean": true, "number": 47.5, "object": { "key": "value" }, "string": "bar" }"#).unwrap());
        let scanned_event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "namespace": { "nope": 1, "nada": "goodbye", "match": { "here": "REDACTED world" } }, "boolean": true, "number": 47.5, "object": { "key": "value" }, "string": "bar" }"#).unwrap());

        let result = transform_one(&mut scanner, event).unwrap();
        assert_eq!(scanned_event, result);
    }

    #[test]
    fn hash_excludes_nested() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Exclude(vec!["namespace".to_string()]),
            tags: build_tags(""),
            action: Action::Hash,
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter("*"),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);

        let event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "namespace": { "nope": 1, "nada": "hello", "match": { "here": "hello world" } }, "boolean": true, "number": 47.5, "message": "hello" }"#).unwrap());
        let scanned_event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "namespace": { "nope": 1, "nada": "hello", "match": { "here": "hello world" } }, "boolean": true, "number": 47.5, "message": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" }"#).unwrap());

        let result = transform_one(&mut scanner, event).unwrap();
        assert_eq!(scanned_event, result);
    }

    #[test]
    fn scrub_excludes_nested() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Exclude(vec!["non-existent".to_string()]),
            tags: build_tags("test:tag"),
            action: Action::Scrub("REDACTED".to_string()),
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter("*"),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);

        let event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "namespace": { "nope": 1, "nada": "hello", "match": { "here": "hello world" } }, "boolean": true, "number": 47.5, "message": "hello" }"#).unwrap());
        let scanned_event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "namespace": { "nope": 1, "nada": "REDACTED", "match": { "here": "REDACTED world" } }, "boolean": true, "number": 47.5, "message": "REDACTED", "test": "tag" }"#).unwrap());

        let result = transform_one(&mut scanner, event).unwrap();
        assert_eq!(scanned_event, result);
    }

    #[test]
    fn filter_matched() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Exclude(vec![]),
            tags: build_tags("test:tag"),
            action: Action::Scrub("REDACTED".to_string()),
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter(r#"@match.here:"hello world""#),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);

        let event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "custom": { "nope": 1, "nada": "hello", "match": { "here": "hello world" } }, "boolean": true, "number": 47.5, "message": "hello" }"#).unwrap());
        let scanned_event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "custom": { "nope": 1, "nada": "REDACTED", "match": { "here": "REDACTED world" } }, "boolean": true, "number": 47.5, "message": "REDACTED", "test": "tag" }"#).unwrap());

        let result = transform_one(&mut scanner, event).unwrap();
        assert_eq!(scanned_event, result);
    }

    #[test]
    fn filter_not_matched() {
        let rule = ScanningRule {
            id: "foo".to_string(),
            pattern: Regex::new(r"hello").unwrap(),
            coverage: ScanningCoverage::Exclude(vec![]),
            tags: build_tags("test:tag"),
            action: Action::Scrub("REDACTED".to_string()),
        };

        let scanning_rules = vec![rule];

        let scanning_groups = vec![ScanningGroup {
            id: "group".to_string(),
            filter: build_filter(r#"@match.here:"goodbye""#),
            scanning_rules,
        }];

        let mut scanner = DatadogSensitiveDataScanner::new(scanning_groups);

        let event = Event::from(serde_json::from_str::<HashMap<_, _>>(r#"{ "custom": { "nope": 1, "nada": "hello", "match": { "here": "hello world" } }, "boolean": true, "number": 47.5, "message": "hello" }"#).unwrap());
        let scanned_event = event.clone();

        let result = transform_one(&mut scanner, event).unwrap();
        assert_eq!(scanned_event, result);
    }
}
