//! Merging the generated profile into Codex's `config.toml`, keeping every
//! other key, comment and table as the user wrote it.

use anyhow::{Result, bail};
use toml_edit::{DocumentMut, Item, Table, value};

use super::{Generated, PROFILE};

/// Set `default_permissions`, replace `[permissions.moat]` and turn on the
/// network proxy that enforces its domain rules. Returns whether anything
/// changed.
pub fn apply(doc: &mut DocumentMut, generated: &Generated) -> Result<bool> {
    let before = doc.to_string();
    doc.insert("default_permissions", value(PROFILE));
    let permissions = table_at(doc.as_table_mut(), "permissions")?;
    permissions.insert(PROFILE, Item::Table(generated.profile.clone()));
    let features = table_at(doc.as_table_mut(), "features")?;
    match features.get_mut("network_proxy") {
        // `[features.network_proxy]` with its own settings: keep them, enable it.
        Some(Item::Table(proxy)) => {
            proxy.insert("enabled", value(true));
        }
        _ => {
            features.insert("network_proxy", value(true));
        }
    }
    Ok(doc.to_string() != before)
}

/// The table at `key`, created implicit (no header of its own) when missing.
fn table_at<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    let item = parent.entry(key).or_insert_with(|| {
        let mut table = Table::new();
        table.set_implicit(true);
        Item::Table(table)
    });
    match item {
        Item::Table(table) => Ok(table),
        _ => bail!("`{key}` in the Codex config is not a table"),
    }
}
