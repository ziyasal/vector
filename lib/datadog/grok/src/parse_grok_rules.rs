use fancy_regex::Regex;
use grok::Grok;
use lazy_static::lazy_static;
use lookup::LookupBuf;
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
    sync::Arc,
};
use vrl_compiler::Value;

use crate::{
    ast::{self, Destination, GrokPattern},
    grok_filter::GrokFilter,
    matchers::{date, date::DateFilter},
    parse_grok_pattern::parse_grok_pattern,
};

/// The result of parsing a grok rule with a final regular expression and the related field information, needed at runtime.
#[derive(Debug, Clone)]
pub struct GrokRule {
    /// a compiled regex pattern
    pub pattern: Arc<Regex>,
    /// a map of capture names(grok0, grok1, ...) to field information.
    pub fields: HashMap<String, GrokField>,
}

/// A grok field, that should be extracted, with its lookup path and post-processing filters to apply.
#[derive(Debug, Clone)]
pub struct GrokField {
    pub lookup: LookupBuf,
    pub filters: Vec<GrokFilter>,
}

/// The context used to parse grok rules.
#[derive(Debug, Clone)]
pub struct GrokRuleParseContext {
    /// a currently built regular expression
    pub regex: String,
    /// a map of capture names(grok0, grok1, ...) to field information.
    pub fields: HashMap<String, GrokField>,
    /// aliases and their definitions
    pub aliases: BTreeMap<String, String>,
    /// used to detect cycles in alias definitions
    pub alias_stack: Vec<String>,
    pub grok: HashMap<String, String>,
}

impl GrokRuleParseContext {
    /// appends to the rule's regular expression
    fn append_regex(&mut self, regex: &str) {
        self.regex.push_str(regex);
    }

    fn append_grok_pattern(&mut self, name: &str) -> Result<(), Error> {
        let option = self.grok.get(name).cloned();
        if let Some(rule_def) = option {
            parse_grok_rule(&rule_def, self)?;
        } else {
            self.append_regex("TODO");
        }
        Ok(())
        // self.regex.push_str(x);
    }

    /// registers a given grok field under a given grok name(used in a regex)
    fn register_grok_field(&mut self, grok_name: &str, field: GrokField) {
        self.fields.insert(grok_name.to_string(), field);
    }

    /// adds a filter to a field, associated with this grok alias
    fn register_filter(&mut self, grok_name: &str, filter: GrokFilter) {
        self.fields
            .entry(grok_name.to_string())
            .and_modify(|v| v.filters.insert(0, filter));
    }

    fn new(aliases: BTreeMap<String, String>) -> Self {
        Self {
            regex: String::new(),
            fields: HashMap::new(),
            aliases,
            alias_stack: vec![],
            grok: initialize_grok(),
        }
    }

    /// Generates a grok-safe name for a given field(grok0, grok1 ...)
    fn generate_grok_compliant_name(&mut self) -> String {
        format!("grok{}", self.fields.len())
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("failed to parse grok expression '{}': {}", .0, .1)]
    InvalidGrokExpression(String, String),
    #[error("invalid arguments for the function '{}'", .0)]
    InvalidFunctionArguments(String),
    #[error("unknown filter '{}'", .0)]
    UnknownFilter(String),
    #[error("Circular dependency found in the alias '{}'", .0)]
    CircularDependencyInAliasDefinition(String),
}

///
/// Parses DD grok rules.
///
/// Here is an example:
/// patterns:
///  %{access.common} \[%{_date_access}\] "(?>%{_method} |)%{_url}(?> %{_version}|)" %{_status_code} (?>%{_bytes_written}|-)
///  %{access.common} (%{number:duration:scale(1000000000)} )?"%{_referer}" "%{_user_agent}"( "%{_x_forwarded_for}")?.*"#
/// aliases:
///  "access.common" : %{_client_ip} %{_ident} %{_auth}
///
/// You can write grok patterns with the %{MATCHER:EXTRACT:FILTER} syntax:
/// - Matcher: A rule (possibly a reference to another token rule) that describes what to expect (number, word, notSpace, etc.)
/// - Extract (optional): An identifier representing the capture destination for the piece of text matched by the Matcher.
/// - Filter (optional): A post-processor of the match to transform it.
///
/// Rules can reference aliases as %{alias_name}, aliases can reference each other themselves, cross-references or circular dependencies are not allowed and result in an error.
/// Only one can match any given log. The first one that matches, from top to bottom, is the one that does the parsing.
/// For further documentation and the full list of available matcher and filters check out https://docs.datadoghq.com/logs/processing/parsing
pub fn parse_grok_rules(
    patterns: &[String],
    aliases: BTreeMap<String, String>,
) -> Result<Vec<GrokRule>, Error> {
    Ok(patterns
        .iter()
        .filter(|&r| !r.is_empty())
        .map(|r| {
            parse_pattern(r, &mut GrokRuleParseContext::new(aliases.clone())).unwrap_or_else(|_| {
                parse_pattern(
                    "failed pattern replacement",
                    &mut GrokRuleParseContext::new(aliases.clone()),
                )
                .expect("replacement wasn't parsed")
            })
        })
        .collect::<Vec<GrokRule>>())
}

///
/// Parses alias definitions.
///
/// # Arguments
///
/// - `name` - the name of the alias
/// - `definition` - the definition of the alias
/// - `context` - the context required to parse the current grok rule
fn parse_alias(
    name: &str,
    definition: &str,
    context: &mut GrokRuleParseContext,
) -> Result<(), Error> {
    // track circular dependencies
    if context.alias_stack.iter().any(|a| a == name) {
        return Err(Error::CircularDependencyInAliasDefinition(
            context.alias_stack.first().unwrap().to_string(),
        ));
    } else {
        context.alias_stack.push(name.to_string());
    }

    parse_grok_rule(definition, context)?;

    context.alias_stack.pop();

    Ok(())
}

///
/// Parses pattern definitions.
///
/// # Arguments
///
/// - `pattern` - the definition of the pattern
/// - `context` - the context required to parse the current grok rule
/// - `grok` - an instance of Grok parser
fn parse_pattern(pattern: &str, context: &mut GrokRuleParseContext) -> Result<GrokRule, Error> {
    parse_grok_rule(pattern, context)?;
    let mut pattern = String::new();
    // \A, \z - parses from the beginning to the end of string, not line(until \n)
    pattern.push_str(r#"\A"#);
    pattern.push_str(&context.regex);
    pattern.push_str(r#"\z"#);

    // our regex engine(onig) uses (?m) mode modifier instead of (?s) to make the dot match all characters
    pattern = pattern.replace("(?s)", "(?m)").replace("(?-s)", "(?-m)");

    // compile pattern
    let pattern = Arc::new(
        Regex::new(&pattern).map_err(|e| Error::InvalidGrokExpression(pattern, e.to_string()))?,
    );

    Ok(GrokRule {
        pattern,
        fields: context.fields.clone(),
    })
}

/// Parses a given rule to a pure grok pattern with a set of post-processing filters.
///
/// # Arguments
///
/// - `rule` - the definition of a grok rule(can be a pattern or an alias)
/// - `aliases` - all aliases and their definitions
/// - `context` - the context required to parse the current grok rule
fn parse_grok_rule(rule: &str, context: &mut GrokRuleParseContext) -> Result<(), Error> {
    lazy_static! {
        static ref GROK_PATTERN_RE: onig::Regex =
            onig::Regex::new(r#"%\{(?:[^"\}]|(?<!\\)"(?:\\"|[^"])*(?<!\\)")+\}"#).unwrap();
    }
    let mut regex_i = 0;
    for (start, end) in GROK_PATTERN_RE.find_iter(rule) {
        context.append_regex(&rule[regex_i..start]);
        regex_i = end;
        let pattern = parse_grok_pattern(&rule[start..end])
            .map_err(|e| Error::InvalidGrokExpression(rule[start..end].to_string(), e))?;
        resolve_grok_pattern(&pattern, context)?;
    }
    context.append_regex(&rule[regex_i..]);

    Ok(())
}

/// Converts each rule to a pure grok rule:
///  - strips filters and collects them to apply later
///  - replaces references to aliases with their definitions
///  - replaces match functions with corresponding regex groups.
///
/// # Arguments
///
/// - `pattern` - a parsed grok pattern
/// - `context` - the context required to parse the current grok rule
fn resolve_grok_pattern(
    pattern: &GrokPattern,
    context: &mut GrokRuleParseContext,
) -> Result<(), Error> {
    let grok_alias = pattern
        .destination
        .as_ref()
        .map(|_| context.generate_grok_compliant_name());
    match pattern {
        GrokPattern {
            destination:
                Some(Destination {
                    path,
                    filter_fn: Some(filter),
                }),
            ..
        } => {
            context.register_grok_field(
                grok_alias.as_ref().expect("grok alias is not defined"),
                GrokField {
                    lookup: path.clone(),
                    filters: vec![GrokFilter::try_from(filter)?],
                },
            );
        }
        GrokPattern {
            destination:
                Some(Destination {
                    path,
                    filter_fn: None,
                }),
            ..
        } => {
            context.register_grok_field(
                grok_alias.as_ref().expect("grok alias is not defined"),
                GrokField {
                    lookup: path.clone(),
                    filters: vec![],
                },
            );
        }
        _ => {}
    }

    let match_name = &pattern.match_fn.name;
    match context.aliases.get(match_name).cloned() {
        Some(alias_def) => match &grok_alias {
            Some(grok_alias) => {
                context.append_regex("(?P<");
                context.append_regex(grok_alias);
                context.append_regex(">");
                parse_alias(match_name, &alias_def, context)?;
                context.append_regex(")");
            }
            None => {
                parse_alias(match_name, &alias_def, context)?;
            }
        },
        None if match_name == "regex" || match_name == "date" || match_name == "boolean" => {
            // these patterns will be converted to named capture groups e.g. (?<http.status_code>[0-9]{3})
            match &grok_alias {
                Some(grok_alias) => {
                    context.append_regex("(?P<");
                    context.append_regex(grok_alias);
                    context.append_regex(">");
                }
                None => {
                    context.append_regex("(?:"); // non-capturing group
                }
            }
            resolves_match_function(grok_alias, pattern, context)?;
            context.append_regex(")");
        }
        None => {
            // these will be converted to "pure" grok patterns %{PATTERN:DESTINATION} but without filters
            if let Some(grok_alias) = &grok_alias {
                context.append_regex("(?P<");
                context.append_regex(grok_alias);
            } else {
                context.append_regex("(?:");
            }
            context.append_regex(">");
            resolves_match_function(grok_alias.clone(), pattern, context)?;
            context.append_regex(")");
        }
    }

    Ok(())
}

/// Process a match function from a given pattern:
/// - returns a grok expression(a grok pattern or a regular expression) corresponding to a given match function
/// - some match functions(e.g. number) implicitly introduce a filter to be applied to an extracted value - stores it to `fields`.
fn resolves_match_function(
    grok_alias: Option<String>,
    pattern: &ast::GrokPattern,
    context: &mut GrokRuleParseContext,
) -> Result<(), Error> {
    let match_fn = &pattern.match_fn;
    match match_fn.name.as_ref() {
        "regex" => match match_fn.args.as_ref() {
            Some(args) if !args.is_empty() => {
                if let ast::FunctionArgument::Arg(Value::Bytes(ref b)) = args[0] {
                    context.append_regex(&String::from_utf8_lossy(b));
                    return Ok(());
                }
                Err(Error::InvalidFunctionArguments(match_fn.name.clone()))
            }
            _ => Err(Error::InvalidFunctionArguments(match_fn.name.clone())),
        },
        "integer" => {
            if let Some(grok_alias) = &grok_alias {
                context.register_filter(grok_alias, GrokFilter::Integer);
            }
            context.append_grok_pattern("integerStr")?;
            Ok(())
        }
        "integerExt" => {
            if let Some(grok_alias) = &grok_alias {
                context.register_filter(grok_alias, GrokFilter::IntegerExt);
            }
            context.append_grok_pattern("integerExtStr")?;
            Ok(())
        }
        "number" => {
            if let Some(grok_alias) = &grok_alias {
                context.register_filter(grok_alias, GrokFilter::Number);
            }
            context.append_grok_pattern("numberStr")?;
            Ok(())
        }
        "numberExt" => {
            if let Some(grok_alias) = &grok_alias {
                context.register_filter(grok_alias, GrokFilter::NumberExt);
            }
            context.append_grok_pattern("numberExtStr")?;
            Ok(())
        }
        "date" => {
            return match match_fn.args.as_ref() {
                Some(args) if !args.is_empty() && args.len() <= 2 => {
                    if let ast::FunctionArgument::Arg(Value::Bytes(b)) = &args[0] {
                        let format = String::from_utf8_lossy(b);
                        let result = date::time_format_to_regex(&format, true)
                            .map_err(|_e| Error::InvalidFunctionArguments(match_fn.name.clone()))?;
                        let mut regext_opt = None;
                        if result.tz_captured {
                            regext_opt = Some(regex::Regex::new(&result.regex).map_err(|error| {
                                error!(message = "Error compiling regex", regex = %result.regex, %error);
                                Error::InvalidFunctionArguments(match_fn.name.clone())
                            })?);
                        }
                        let strp_format = date::convert_time_format(&format).map_err(|error| {
                            error!(message = "Error compiling regex", regex = %result.regex, %error);
                            Error::InvalidFunctionArguments(match_fn.name.clone())
                        })?;
                        let mut target_tz = None;
                        if args.len() == 2 {
                            if let ast::FunctionArgument::Arg(Value::Bytes(b)) = &args[1] {
                                let tz = String::from_utf8_lossy(b);
                                date::parse_timezone(&tz).map_err(|error| {
                                    error!(message = "Invalid(unrecognized) timezone", %error);
                                    Error::InvalidFunctionArguments(match_fn.name.clone())
                                })?;
                                target_tz = Some(tz.to_string());
                            }
                        }
                        let filter = GrokFilter::Date(DateFilter {
                            original_format: format.to_string(),
                            strp_format,
                            regex_with_tz: regext_opt,
                            target_tz,
                            tz_aware: result.with_tz,
                        });
                        let result =
                            date::time_format_to_regex(&format, false).map_err(|error| {
                                error!(message = "Invalid time format", format = %format, %error);
                                Error::InvalidFunctionArguments(match_fn.name.clone())
                            })?;
                        if let Some(grok_alias) = &grok_alias {
                            context.register_filter(grok_alias, filter);
                        }
                        context.append_regex(&result.regex);
                        return Ok(());
                    }
                    Err(Error::InvalidFunctionArguments(match_fn.name.clone()))
                }
                _ => Err(Error::InvalidFunctionArguments(match_fn.name.clone())),
            };
        }
        // otherwise just add it as is, it should be a known grok pattern
        grok_pattern_name => {
            context.append_grok_pattern(grok_pattern_name)?;
            Ok(())
        }
    }
}

// test some tricky cases here, more high-level tests are in parse_grok
#[cfg(test)]
mod tests {
    use shared::btreemap;

    use super::*;

    #[test]
    fn supports_escaped_quotes() {
        let rules = parse_grok_rules(
            &[r#"%{notSpace:field:nullIf("with \"escaped\" quotes")}"#.to_string()],
            btreemap! {},
        )
        .expect("couldn't parse rules");
        assert!(matches!(
            &rules[0]
                .fields
                .iter().next()
                .expect("invalid grok pattern").1
            .filters[0],
            GrokFilter::NullIf(v) if *v == r#"with "escaped" quotes"#
        ));
    }
}

include!(concat!(env!("OUT_DIR"), "/patterns.rs"));
fn initialize_grok() -> HashMap<String, String> {
    // let mut grok = grok::Grok::with_patterns();
    let mut res = HashMap::new();
    // // Insert Datadog grok patterns.
    for &(key, value) in PATTERNS {
        res.insert(String::from(key), String::from(value));
    }
    res
}
