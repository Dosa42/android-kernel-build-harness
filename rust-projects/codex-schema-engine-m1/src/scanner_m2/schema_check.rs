use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

#[derive(Debug, Clone)]
pub(crate) struct SchemaCheck {
    pub valid: bool,
    pub errors: Vec<String>,
}

pub(crate) fn validate_config(value: &TomlValue) -> SchemaCheck {
    let root: JsonValue = match serde_json::from_str(crate::schema::CODEX_SCHEMA) {
        Ok(value) => value,
        Err(error) => {
            return SchemaCheck {
                valid: false,
                errors: vec![format!("embedded config-schema.json is invalid JSON: {error}")],
            }
        }
    };

    let instance = match serde_json::to_value(value) {
        Ok(value) => value,
        Err(error) => {
            return SchemaCheck {
                valid: false,
                errors: vec![format!("could not convert TOML value for schema validation: {error}")],
            }
        }
    };

    let mut errors = Vec::new();
    validate_node(&root, &instance, &root, "$", &mut errors);
    SchemaCheck {
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_node(
    schema: &JsonValue,
    instance: &JsonValue,
    root: &JsonValue,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(schema_object) = schema.as_object() else {
        if schema == &JsonValue::Bool(false) {
            errors.push(format!("{path}: schema rejects this value"));
        }
        return;
    };

    if let Some(reference) = schema_object.get("$ref").and_then(JsonValue::as_str) {
        match resolve_ref(root, reference) {
            Some(target) => validate_node(target, instance, root, path, errors),
            None => errors.push(format!("{path}: unresolved schema reference {reference}")),
        }
        return;
    }

    if let Some(all_of) = schema_object.get("allOf").and_then(JsonValue::as_array) {
        for branch in all_of {
            validate_node(branch, instance, root, path, errors);
        }
    }

    if let Some(any_of) = schema_object.get("anyOf").and_then(JsonValue::as_array) {
        if !matches_any_branch(any_of, instance, root, path) {
            errors.push(format!("{path}: value does not match any allowed schema branch"));
            return;
        }
    }

    if let Some(one_of) = schema_object.get("oneOf").and_then(JsonValue::as_array) {
        let matches = one_of
            .iter()
            .filter(|branch| branch_matches(branch, instance, root, path))
            .count();
        if matches != 1 {
            errors.push(format!(
                "{path}: value must match exactly one schema branch, matched {matches}"
            ));
            return;
        }
    }

    if let Some(expected_type) = schema_object.get("type").and_then(JsonValue::as_str) {
        if !type_matches(expected_type, instance) {
            errors.push(format!(
                "{path}: expected JSON type {expected_type}, found {}",
                json_type_name(instance)
            ));
            return;
        }
    }

    if let Some(values) = schema_object.get("enum").and_then(JsonValue::as_array) {
        if !values.iter().any(|value| value == instance) {
            errors.push(format!("{path}: value is not one of the allowed enum values"));
            return;
        }
    }

    validate_number_constraints(schema_object, instance, path, errors);
    validate_string_constraints(schema_object, instance, path, errors);

    if let Some(object) = instance.as_object() {
        validate_object(schema_object, object, root, path, errors);
    }

    if let Some(array) = instance.as_array() {
        if let Some(item_schema) = schema_object.get("items") {
            for (index, item) in array.iter().enumerate() {
                validate_node(
                    item_schema,
                    item,
                    root,
                    &format!("{path}[{index}]"),
                    errors,
                );
            }
        }
    }
}

fn validate_object(
    schema: &serde_json::Map<String, JsonValue>,
    object: &serde_json::Map<String, JsonValue>,
    root: &JsonValue,
    path: &str,
    errors: &mut Vec<String>,
) {
    if let Some(required) = schema.get("required").and_then(JsonValue::as_array) {
        for key in required.iter().filter_map(JsonValue::as_str) {
            if !object.contains_key(key) {
                errors.push(format!("{path}: missing required property `{key}`"));
            }
        }
    }

    let properties = schema.get("properties").and_then(JsonValue::as_object);
    for (key, value) in object {
        let child_path = property_path(path, key);
        if let Some(property_schema) = properties.and_then(|properties| properties.get(key)) {
            validate_node(property_schema, value, root, &child_path, errors);
            continue;
        }

        match schema.get("additionalProperties") {
            Some(JsonValue::Bool(false)) => {
                errors.push(format!("{child_path}: unknown configuration field"));
            }
            Some(JsonValue::Object(_)) => {
                validate_node(
                    schema.get("additionalProperties").expect("checked above"),
                    value,
                    root,
                    &child_path,
                    errors,
                );
            }
            _ => {}
        }
    }
}

fn validate_number_constraints(
    schema: &serde_json::Map<String, JsonValue>,
    instance: &JsonValue,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(number) = instance.as_f64() else {
        return;
    };

    if let Some(minimum) = schema.get("minimum").and_then(JsonValue::as_f64) {
        if number < minimum {
            errors.push(format!("{path}: number {number} is below minimum {minimum}"));
        }
    }
    if let Some(maximum) = schema.get("maximum").and_then(JsonValue::as_f64) {
        if number > maximum {
            errors.push(format!("{path}: number {number} is above maximum {maximum}"));
        }
    }

    if let Some(format) = schema.get("format").and_then(JsonValue::as_str) {
        match format {
            "uint" | "uint16" | "uint32" | "uint64" if number < 0.0 => {
                errors.push(format!("{path}: {format} cannot be negative"));
            }
            "uint16" if number > u16::MAX as f64 => {
                errors.push(format!("{path}: value exceeds uint16 range"));
            }
            "uint32" if number > u32::MAX as f64 => {
                errors.push(format!("{path}: value exceeds uint32 range"));
            }
            "int32" if number < i32::MIN as f64 || number > i32::MAX as f64 => {
                errors.push(format!("{path}: value exceeds int32 range"));
            }
            _ => {}
        }
    }
}

fn validate_string_constraints(
    schema: &serde_json::Map<String, JsonValue>,
    instance: &JsonValue,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(value) = instance.as_str() else {
        return;
    };
    let length = value.chars().count() as u64;

    if let Some(minimum) = schema.get("minLength").and_then(JsonValue::as_u64) {
        if length < minimum {
            errors.push(format!("{path}: string length {length} is below {minimum}"));
        }
    }
    if let Some(maximum) = schema.get("maxLength").and_then(JsonValue::as_u64) {
        if length > maximum {
            errors.push(format!("{path}: string length {length} exceeds {maximum}"));
        }
    }

    if schema.get("pattern").and_then(JsonValue::as_str) == Some("^[a-zA-Z0-9_-]+$")
        && (value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
    {
        errors.push(format!(
            "{path}: string does not match ^[a-zA-Z0-9_-]+$"
        ));
    }
}

fn matches_any_branch(branches: &[JsonValue], instance: &JsonValue, root: &JsonValue, path: &str) -> bool {
    branches
        .iter()
        .any(|branch| branch_matches(branch, instance, root, path))
}

fn branch_matches(schema: &JsonValue, instance: &JsonValue, root: &JsonValue, path: &str) -> bool {
    let mut branch_errors = Vec::new();
    validate_node(schema, instance, root, path, &mut branch_errors);
    branch_errors.is_empty()
}

fn resolve_ref<'a>(root: &'a JsonValue, reference: &str) -> Option<&'a JsonValue> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn type_matches(expected: &str, value: &JsonValue) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn json_type_name(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(number) if number.is_i64() || number.is_u64() => "integer",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

fn property_path(parent: &str, key: &str) -> String {
    if key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        format!("{parent}.{key}")
    } else {
        format!("{parent}[{key:?}]")
    }
}

#[cfg(test)]
mod tests {
    use super::validate_config;
    use toml::Value as TomlValue;

    #[test]
    fn accepts_minimal_empty_config() {
        let value: TomlValue = "".parse().expect("empty TOML document");
        let result = validate_config(&value);
        assert!(result.valid, "{:?}", result.errors);
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let value: TomlValue = "definitely_not_a_codex_key = true"
            .parse()
            .expect("test TOML");
        let result = validate_config(&value);
        assert!(!result.valid);
    }
}
