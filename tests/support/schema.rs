//! Checks a document against a file under `schemas/`. tests/schemas.rs includes
//! this to check what the binary prints, and the unit tests of the outputs a
//! test cannot drive from outside reach it as `crate::schemas::test_support`.

// Each target that includes this uses part of it.
#![allow(dead_code)]

use jsonschema::{Draft, Validator};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas")
}

pub fn load(file: &str) -> Value {
    let path = dir().join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

/// Refuses a schema that does not conform to the 2020-12 metaschema.
pub fn compile(schema: &Value) -> Validator {
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .build(schema)
        .unwrap_or_else(|e| panic!("{e}"))
}

pub fn errors(validator: &Validator, doc: &Value) -> Vec<String> {
    match validator.validate(doc) {
        Ok(()) => vec![],
        Err(found) => found.map(|e| format!("{}: {e}", e.instance_path)).collect(),
    }
}

/// `schema` with its open parts closed, which is how a test notices a field or
/// a value nobody wrote down. A published schema must leave objects open and
/// open value sets unlisted, or a consumer validating with it would reject what
/// a later minor is allowed to write. So here, and only here, every object
/// described by `properties` takes no others, and an `examples` list is the
/// whole set. An explicit `additionalProperties: true` stays: that part of the
/// document is left undescribed on purpose.
///
/// `allOf`, `if` and `then` hold only conditions here, and closing one would
/// break it. A subschema with `$ref` is the referenced object plus a narrowing.
pub fn strict(schema: &Value) -> Value {
    fn close(schema: &mut Value) {
        let Value::Object(map) = schema else { return };
        if map.contains_key("properties") && !map.contains_key("$ref") {
            map.entry("additionalProperties").or_insert(json!(false));
        }
        if let Some(Value::Array(known)) = map.get("examples").cloned() {
            let mut values = known;
            let nullable = map
                .get("type")
                .and_then(Value::as_array)
                .is_some_and(|types| types.contains(&json!("null")));
            if nullable {
                values.push(Value::Null);
            }
            map.insert("enum".into(), Value::Array(values));
        }
        for keyword in ["properties", "$defs"] {
            if let Some(Value::Object(children)) = map.get_mut(keyword) {
                children.values_mut().for_each(close);
            }
        }
        if let Some(items) = map.get_mut("items") {
            close(items);
        }
        if let Some(Value::Array(branches)) = map.get_mut("oneOf") {
            branches.iter_mut().for_each(close);
        }
    }
    let mut strict = schema.clone();
    close(&mut strict);
    strict
}

/// `doc` with a field no schema mentions added to every object in it, as a
/// later minor may do anywhere.
pub fn with_unknown_fields(doc: &Value) -> Value {
    match doc {
        Value::Object(map) => {
            let mut out: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), with_unknown_fields(v)))
                .collect();
            out.insert(
                "x_added_in_a_later_minor".into(),
                json!({ "nested": [1, "two", null] }),
            );
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(with_unknown_fields).collect()),
        other => other.clone(),
    }
}

/// `doc`, which real code wrote, against `file` three ways:
///
/// - as published, which is what a consumer runs
/// - with [`strict`], so a field or a value the file does not list fails here
///   rather than drifting out of the documentation
/// - as published with [`with_unknown_fields`], the promise that a consumer's
///   validator keeps passing when a minor adds a field
pub fn check(file: &str, doc: &Value) {
    let schema = load(file);
    let published = compile(&schema);
    let found = errors(&published, doc);
    assert!(found.is_empty(), "{file}: {found:#?}\n{doc:#}");
    let found = errors(&compile(&strict(&schema)), doc);
    assert!(
        found.is_empty(),
        "{file}: undocumented field or value, so list it in the schema: {found:#?}\n{doc:#}"
    );
    let found = errors(&published, &with_unknown_fields(doc));
    assert!(
        found.is_empty(),
        "{file}: the schema refuses an added field: {found:#?}"
    );
}

/// The file refuses `doc`, so the checks above are not vacuous.
pub fn assert_rejected(file: &str, doc: &Value, what: &str) {
    assert!(
        !errors(&compile(&load(file)), doc).is_empty(),
        "{file} accepted {what}"
    );
}
