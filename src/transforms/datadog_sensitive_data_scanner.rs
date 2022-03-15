use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        DataType, Input, Output, TransformConfig, TransformContext,
    },
    event::Event,
    schema,
    transforms::{FunctionTransform, OutputBuffer, Transform}, conditions::datadog_search::DatadogSearchRunner,
};

struct ScanningGroup {
    id: String,
    filter: DatadogSearchRunner,
    scanning_rules: Vec<ScanningRule>,
}

struct ScanningRule {
    name: String,
    pattern: Regex,
    coverage: ScanningCoverage,
    tags: HashMap<String, String>,
    action: Action,
}

enum ScanningCoverage {
    Include(Vec<String>),
    Exclude(Vec<String>),
}

enum Action {
    Replace(String),
    Hash,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DatadogSensitiveDataScannerConfig {
}

#[async_trait::async_trait]
#[typetag::serde(name = "datadog_sensitive_data_scanner")]
impl TransformConfig for DatadogSensitiveDataScannerConfig {
    async fn build(&self, context: &TransformContext) -> crate::Result<Transform> {
        // todo: build hard-coded scanning rules
        // todo: wire up scanning rules to run in transform()
        Ok(Transform::function(DatadogSensitiveDataScanner {}))
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
}

impl FunctionTransform for DatadogSensitiveDataScanner {
    fn transform(&mut self, output: &mut OutputBuffer, event: Event) {
        println!("hello world");
        output.push(event);
    }
}
