use eframe::egui::{text::LayoutJob, Color32, FontId, TextFormat};

pub static CODEX_SCHEMA: &str = include_str!("../assets/config-schema.json");

pub fn line_count() -> usize {
    CODEX_SCHEMA.lines().count()
}

pub fn byte_count() -> usize {
    CODEX_SCHEMA.len()
}

pub fn syntax_job() -> LayoutJob {
    let mut job = LayoutJob::default();
    let font = FontId::monospace(11.0);
    let default = TextFormat {
        font_id: font.clone(),
        color: Color32::from_rgb(190, 195, 205),
        ..Default::default()
    };
    let string = TextFormat {
        font_id: font.clone(),
        color: Color32::from_rgb(125, 211, 167),
        ..Default::default()
    };
    let key = TextFormat {
        font_id: font.clone(),
        color: Color32::from_rgb(138, 180, 248),
        ..Default::default()
    };
    let literal = TextFormat {
        font_id: font.clone(),
        color: Color32::from_rgb(246, 193, 119),
        ..Default::default()
    };

    let bytes = CODEX_SCHEMA.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let b = bytes[i];
                i += 1;
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    break;
                }
            }
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let fmt = if j < bytes.len() && bytes[j] == b':' { key.clone() } else { string.clone() };
            job.append(&CODEX_SCHEMA[start..i], 0.0, fmt);
            continue;
        }

        let start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        let segment = &CODEX_SCHEMA[start..i];
        let mut rest = segment;
        while !rest.is_empty() {
            let next = ["true", "false", "null"]
                .iter()
                .filter_map(|needle| rest.find(needle).map(|pos| (pos, *needle)))
                .min_by_key(|(pos, _)| *pos);
            match next {
                Some((pos, needle)) => {
                    if pos > 0 {
                        job.append(&rest[..pos], 0.0, default.clone());
                    }
                    job.append(needle, 0.0, literal.clone());
                    rest = &rest[pos + needle.len()..];
                }
                None => {
                    job.append(rest, 0.0, default.clone());
                    break;
                }
            }
        }
    }

    job.wrap.max_width = f32::INFINITY;
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_schema_is_exact_expected_document() {
        let parsed: serde_json::Value = serde_json::from_str(CODEX_SCHEMA).expect("embedded schema must be valid JSON");
        assert_eq!(parsed.get("title").and_then(|v| v.as_str()), Some("ConfigToml"));
        assert_eq!(line_count(), 6212);
        assert_eq!(byte_count(), 181805);
    }
}
