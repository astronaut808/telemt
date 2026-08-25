use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::error::{ProxyError, Result};

pub(super) fn normalize_config_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

pub(super) fn hash_rendered_snapshot(rendered: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    rendered.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn preprocess_includes(
    content: &str,
    base_dir: &Path,
    depth: u8,
    source_files: &mut BTreeSet<PathBuf>,
    source_contents: &mut BTreeMap<PathBuf, String>,
    source_overrides: &BTreeMap<PathBuf, String>,
) -> Result<String> {
    if depth > 10 {
        return Err(ProxyError::Config("Include depth > 10".into()));
    }
    let mut output = String::with_capacity(content.len());
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("include") {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let path_str = rest.trim().trim_matches('"');
                let resolved = base_dir.join(path_str);
                let normalized = normalize_config_path(&resolved);
                source_files.insert(normalized.clone());
                let included = source_overrides
                    .get(&normalized)
                    .cloned()
                    .map(Ok)
                    .unwrap_or_else(|| std::fs::read_to_string(&resolved))
                    .map_err(|e| ProxyError::Config(e.to_string()))?;
                source_contents.insert(normalized, included.clone());
                let included_dir = resolved.parent().unwrap_or(base_dir);
                output.push_str(&preprocess_includes(
                    &included,
                    included_dir,
                    depth + 1,
                    source_files,
                    source_contents,
                    source_overrides,
                )?);
                output.push('\n');
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    Ok(output)
}
