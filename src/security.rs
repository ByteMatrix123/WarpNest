use std::{fs, path::Path};

const SECRET_PATTERNS: &[&str] = &["secret", "token", "private_key", "registration_material"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityWarning {
    FilePermissionsTooBroad { path: String },
}

pub fn redact_sensitive(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if SECRET_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
    {
        "[redacted]".to_string()
    } else {
        input.to_string()
    }
}

pub fn file_permission_warnings(path: impl AsRef<Path>) -> Vec<SecurityWarning> {
    file_permission_warnings_impl(path.as_ref())
}

#[cfg(unix)]
fn file_permission_warnings_impl(path: &Path) -> Vec<SecurityWarning> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = fs::metadata(path) else {
        return Vec::new();
    };
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        vec![SecurityWarning::FilePermissionsTooBroad {
            path: path.display().to_string(),
        }]
    } else {
        Vec::new()
    }
}

#[cfg(not(unix))]
fn file_permission_warnings_impl(_path: &Path) -> Vec<SecurityWarning> {
    Vec::new()
}
