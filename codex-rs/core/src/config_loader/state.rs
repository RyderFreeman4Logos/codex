use crate::config_loader::ConfigRequirements;
use crate::config_loader::ConfigRequirementsToml;

use super::fingerprint::record_origins;
use super::fingerprint::version_for_toml;
use super::merge::merge_toml_values;
use codex_app_server_protocol::ConfigLayer;
use codex_app_server_protocol::ConfigLayerMetadata;
use codex_app_server_protocol::ConfigLayerSource;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::path::PathBuf;
use toml::Value as TomlValue;

/// LoaderOverrides overrides managed configuration inputs (primarily for tests).
#[derive(Debug, Default, Clone)]
pub struct LoaderOverrides {
    pub managed_config_path: Option<PathBuf>,
    //TODO(gt): Add a macos_ prefix to this field and remove the target_os check.
    #[cfg(target_os = "macos")]
    pub managed_preferences_base64: Option<String>,
    pub macos_managed_config_requirements_base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigLayerEntry {
    pub name: ConfigLayerSource,
    pub config: TomlValue,
    pub version: String,
    pub disabled_reason: Option<String>,
}

impl ConfigLayerEntry {
    pub fn new(name: ConfigLayerSource, config: TomlValue) -> Self {
        let version = version_for_toml(&config);
        Self {
            name,
            config,
            version,
            disabled_reason: None,
        }
    }

    pub fn new_disabled(
        name: ConfigLayerSource,
        config: TomlValue,
        disabled_reason: impl Into<String>,
    ) -> Self {
        let version = version_for_toml(&config);
        Self {
            name,
            config,
            version,
            disabled_reason: Some(disabled_reason.into()),
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.disabled_reason.is_some()
    }

    pub fn metadata(&self) -> ConfigLayerMetadata {
        ConfigLayerMetadata {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }

    pub fn as_layer(&self) -> ConfigLayer {
        ConfigLayer {
            name: self.name.clone(),
            version: self.version.clone(),
            config: serde_json::to_value(&self.config).unwrap_or(JsonValue::Null),
            disabled_reason: self.disabled_reason.clone(),
        }
    }

    // Get the `.codex/` folder associated with this config layer, if any.
    pub fn config_folder(&self) -> Option<AbsolutePathBuf> {
        match &self.name {
            ConfigLayerSource::Mdm { .. } => None,
            ConfigLayerSource::System { file } => file.parent(),
            ConfigLayerSource::User { file } => file.parent(),
            ConfigLayerSource::Project { dot_codex_folder } => Some(dot_codex_folder.clone()),
            ConfigLayerSource::SessionFlags => None,
            ConfigLayerSource::LegacyManagedConfigTomlFromFile { .. } => None,
            ConfigLayerSource::LegacyManagedConfigTomlFromMdm => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLayerStackOrdering {
    LowestPrecedenceFirst,
    HighestPrecedenceFirst,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigLayerStack {
    /// Layers are listed from lowest precedence (base) to highest (top), so
    /// later entries in the Vec override earlier ones.
    layers: Vec<ConfigLayerEntry>,

    /// Index into [layers] of the user config layer, if any.
    user_layer_index: Option<usize>,

    /// Constraints that must be enforced when deriving a [Config] from the
    /// layers.
    requirements: ConfigRequirements,

    /// Raw requirements data as loaded from requirements.toml/MDM/legacy
    /// sources. This preserves the original allow-lists so they can be
    /// surfaced via APIs.
    requirements_toml: ConfigRequirementsToml,
}

impl ConfigLayerStack {
    pub fn new(
        layers: Vec<ConfigLayerEntry>,
        requirements: ConfigRequirements,
        requirements_toml: ConfigRequirementsToml,
    ) -> std::io::Result<Self> {
        let user_layer_index = verify_layer_ordering(&layers)?;
        Ok(Self {
            layers,
            user_layer_index,
            requirements,
            requirements_toml,
        })
    }

    /// Returns the user config layer, if any.
    pub fn get_user_layer(&self) -> Option<&ConfigLayerEntry> {
        self.user_layer_index
            .and_then(|index| self.layers.get(index))
    }

    pub fn requirements(&self) -> &ConfigRequirements {
        &self.requirements
    }

    pub fn requirements_toml(&self) -> &ConfigRequirementsToml {
        &self.requirements_toml
    }

    /// Creates a new [ConfigLayerStack] using the specified values to inject a
    /// "user layer" into the stack. If such a layer already exists, it is
    /// replaced; otherwise, it is inserted into the stack at the appropriate
    /// position based on precedence rules.
    pub fn with_user_config(&self, config_toml: &AbsolutePathBuf, user_config: TomlValue) -> Self {
        let user_layer = ConfigLayerEntry::new(
            ConfigLayerSource::User {
                file: config_toml.clone(),
            },
            user_config,
        );

        let mut layers = self.layers.clone();
        match self.user_layer_index {
            Some(index) => {
                layers[index] = user_layer;
                Self {
                    layers,
                    user_layer_index: self.user_layer_index,
                    requirements: self.requirements.clone(),
                    requirements_toml: self.requirements_toml.clone(),
                }
            }
            None => {
                let user_layer_index = match layers
                    .iter()
                    .position(|layer| layer.name.precedence() > user_layer.name.precedence())
                {
                    Some(index) => {
                        layers.insert(index, user_layer);
                        index
                    }
                    None => {
                        layers.push(user_layer);
                        layers.len() - 1
                    }
                };
                Self {
                    layers,
                    user_layer_index: Some(user_layer_index),
                    requirements: self.requirements.clone(),
                    requirements_toml: self.requirements_toml.clone(),
                }
            }
        }
    }

    pub fn effective_config(&self) -> TomlValue {
        let mut merged = TomlValue::Table(toml::map::Map::new());
        for layer in self.get_layers(ConfigLayerStackOrdering::LowestPrecedenceFirst, false) {
            merge_toml_values(&mut merged, &layer.config);
        }
        merged
    }

    /// Returns the effective hooks configuration with proper append-merge semantics.
    ///
    /// Unlike other config fields that use last-wins merging, hooks from all layers
    /// are concatenated (global hooks run first, then project, then local).
    pub fn effective_hooks_config(&self) -> crate::hooks::config::HooksConfigToml {
        use crate::hooks::config::HooksConfigToml;

        let mut merged = HooksConfigToml::default();
        for layer in self.get_layers(ConfigLayerStackOrdering::LowestPrecedenceFirst, false) {
            if let Some(hooks_table) = layer.config.as_table().and_then(|t| t.get("hooks")) {
                // Try to deserialize the hooks section from this layer
                if let Ok(layer_hooks) = hooks_table.clone().try_into::<HooksConfigToml>() {
                    merged.merge_from(layer_hooks);
                }
            }
        }
        merged
    }

    pub fn origins(&self) -> HashMap<String, ConfigLayerMetadata> {
        let mut origins = HashMap::new();
        let mut path = Vec::new();

        for layer in self.get_layers(ConfigLayerStackOrdering::LowestPrecedenceFirst, false) {
            record_origins(&layer.config, &layer.metadata(), &mut path, &mut origins);
        }

        origins
    }

    /// Returns the highest-precedence to lowest-precedence layers, so
    /// `ConfigLayerSource::SessionFlags` would be first, if present.
    pub fn layers_high_to_low(&self) -> Vec<&ConfigLayerEntry> {
        self.get_layers(ConfigLayerStackOrdering::HighestPrecedenceFirst, false)
    }

    /// Returns the highest-precedence to lowest-precedence layers, so
    /// `ConfigLayerSource::SessionFlags` would be first, if present.
    pub fn get_layers(
        &self,
        ordering: ConfigLayerStackOrdering,
        include_disabled: bool,
    ) -> Vec<&ConfigLayerEntry> {
        let mut layers: Vec<&ConfigLayerEntry> = self
            .layers
            .iter()
            .filter(|layer| include_disabled || !layer.is_disabled())
            .collect();
        if ordering == ConfigLayerStackOrdering::HighestPrecedenceFirst {
            layers.reverse();
        }
        layers
    }
}

/// Ensures precedence ordering of config layers is correct. Returns the index
/// of the user config layer, if any (at most one should exist).
fn verify_layer_ordering(layers: &[ConfigLayerEntry]) -> std::io::Result<Option<usize>> {
    if !layers.iter().map(|layer| &layer.name).is_sorted() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config layers are not in correct precedence order",
        ));
    }

    // The previous check ensured `layers` is sorted by precedence, so now we
    // further verify that:
    // 1. There is at most one user config layer.
    // 2. Project layers are ordered from root to cwd.
    let mut user_layer_index: Option<usize> = None;
    let mut previous_project_dot_codex_folder: Option<&AbsolutePathBuf> = None;
    for (index, layer) in layers.iter().enumerate() {
        if matches!(layer.name, ConfigLayerSource::User { .. }) {
            if user_layer_index.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "multiple user config layers found",
                ));
            }
            user_layer_index = Some(index);
        }

        if let ConfigLayerSource::Project {
            dot_codex_folder: current_project_dot_codex_folder,
        } = &layer.name
        {
            if let Some(previous) = previous_project_dot_codex_folder {
                let Some(parent) = previous.as_path().parent() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "project layer has no parent directory",
                    ));
                };
                if previous == current_project_dot_codex_folder
                    || !current_project_dot_codex_folder
                        .as_path()
                        .ancestors()
                        .any(|ancestor| ancestor == parent)
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "project layers are not ordered from root to cwd",
                    ));
                }
            }
            previous_project_dot_codex_folder = Some(current_project_dot_codex_folder);
        }
    }

    Ok(user_layer_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::config::{CommandSpec, HooksConfigToml, MatcherGroupToml};
    use codex_app_server_protocol::ConfigLayerSource;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_effective_hooks_config_merges_layers() {
        // Create global config layer with one pre_tool_use hook
        let global_hooks = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./global-hook.sh".to_string()])),
                timeout: 600,
                matcher: Some("^Bash$".to_string()),
                commands: Vec::new(),
            }],
            ..Default::default()
        };
        let mut global_config = toml::map::Map::new();
        global_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&global_hooks).unwrap(),
        );
        let global_layer = ConfigLayerEntry::new(
            ConfigLayerSource::User {
                file: AbsolutePathBuf::from_absolute_path("/home/user/.codex/config.toml")
                    .unwrap(),
            },
            TomlValue::Table(global_config),
        );

        // Create project config layer with another pre_tool_use hook and a post_tool_use hook
        let project_hooks = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./project-hook.sh".to_string()])),
                timeout: 600,
                matcher: Some("^Read$".to_string()),
                commands: Vec::new(),
            }],
            post_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./post-hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };
        let mut project_config = toml::map::Map::new();
        project_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&project_hooks).unwrap(),
        );
        let project_layer = ConfigLayerEntry::new(
            ConfigLayerSource::Project {
                dot_codex_folder: AbsolutePathBuf::from_absolute_path("/home/user/project/.codex").unwrap(),
            },
            TomlValue::Table(project_config),
        );

        // Build config layer stack
        let stack = ConfigLayerStack::new(
            vec![global_layer, project_layer],
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Get effective hooks config
        let effective_hooks = stack.effective_hooks_config();

        // Verify that hooks were appended, not overwritten
        assert_eq!(
            effective_hooks.pre_tool_use.len(),
            2,
            "pre_tool_use should have hooks from both layers"
        );
        assert_eq!(
            effective_hooks.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./global-hook.sh".to_string()])),
            "First hook should be from global layer"
        );
        assert_eq!(
            effective_hooks.pre_tool_use[1].command,
            Some(CommandSpec::Argv(vec!["./project-hook.sh".to_string()])),
            "Second hook should be from project layer"
        );

        // Verify post_tool_use only has project's hook
        assert_eq!(
            effective_hooks.post_tool_use.len(),
            1,
            "post_tool_use should only have project's hook"
        );
        assert_eq!(
            effective_hooks.post_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./post-hook.sh".to_string()]))
        );
    }

    #[test]
    fn test_effective_hooks_config_disable_all_hooks() {
        // Global layer with hooks but no disable flag
        let global_hooks = HooksConfigToml {
            disable_all_hooks: false,
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./global-hook.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };
        let mut global_config = toml::map::Map::new();
        global_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&global_hooks).unwrap(),
        );
        let global_layer = ConfigLayerEntry::new(
            ConfigLayerSource::User {
                file: AbsolutePathBuf::from_absolute_path("/home/user/.codex/config.toml")
                    .unwrap(),
            },
            TomlValue::Table(global_config),
        );

        // Project layer disables all hooks
        let project_hooks = HooksConfigToml {
            disable_all_hooks: true,
            ..Default::default()
        };
        let mut project_config = toml::map::Map::new();
        project_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&project_hooks).unwrap(),
        );
        let project_layer = ConfigLayerEntry::new(
            ConfigLayerSource::Project {
                dot_codex_folder: AbsolutePathBuf::from_absolute_path("/home/user/project/.codex").unwrap(),
            },
            TomlValue::Table(project_config),
        );

        let stack = ConfigLayerStack::new(
            vec![global_layer, project_layer],
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let effective_hooks = stack.effective_hooks_config();

        // disable_all_hooks should be true (logical OR)
        assert!(
            effective_hooks.disable_all_hooks,
            "disable_all_hooks should be true when any layer sets it"
        );

        // Hooks should still be present (disable flag affects execution, not config)
        assert_eq!(
            effective_hooks.pre_tool_use.len(),
            1,
            "Hooks should still be merged even when disabled"
        );
    }

    #[test]
    fn test_effective_hooks_config_empty_layers() {
        // Create a layer without hooks section
        let mut config = toml::map::Map::new();
        config.insert("model".to_string(), TomlValue::String("claude-4".into()));
        let layer = ConfigLayerEntry::new(
            ConfigLayerSource::User {
                file: AbsolutePathBuf::from_absolute_path("/home/user/.codex/config.toml")
                    .unwrap(),
            },
            TomlValue::Table(config),
        );

        let stack =
            ConfigLayerStack::new(vec![layer], Default::default(), Default::default()).unwrap();

        let effective_hooks = stack.effective_hooks_config();

        // Should return default (empty) hooks config
        assert_eq!(effective_hooks, HooksConfigToml::default());
    }

    #[test]
    fn test_effective_hooks_config_three_layers_order() {
        // System layer (lowest precedence)
        let system_hooks = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./system.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };
        let mut system_config = toml::map::Map::new();
        system_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&system_hooks).unwrap(),
        );
        let system_layer = ConfigLayerEntry::new(
            ConfigLayerSource::System {
                file: AbsolutePathBuf::from_absolute_path("/etc/codex/config.toml").unwrap(),
            },
            TomlValue::Table(system_config),
        );

        // Project layer
        let project_hooks = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./project.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };
        let mut project_config = toml::map::Map::new();
        project_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&project_hooks).unwrap(),
        );
        let project_layer = ConfigLayerEntry::new(
            ConfigLayerSource::Project {
                dot_codex_folder: AbsolutePathBuf::from_absolute_path("/home/user/project/.codex").unwrap(),
            },
            TomlValue::Table(project_config),
        );

        // Session flags layer (highest precedence)
        let local_hooks = HooksConfigToml {
            pre_tool_use: vec![MatcherGroupToml {
                command: Some(CommandSpec::Argv(vec!["./local.sh".to_string()])),
                timeout: 600,
                matcher: None,
                commands: Vec::new(),
            }],
            ..Default::default()
        };
        let mut local_config = toml::map::Map::new();
        local_config.insert(
            "hooks".to_string(),
            TomlValue::try_from(&local_hooks).unwrap(),
        );
        let local_layer = ConfigLayerEntry::new(
            ConfigLayerSource::SessionFlags,
            TomlValue::Table(local_config),
        );

        let stack = ConfigLayerStack::new(
            vec![system_layer, project_layer, local_layer],
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let effective_hooks = stack.effective_hooks_config();

        // Hooks should be in order: system, project, local (lowest to highest precedence)
        assert_eq!(effective_hooks.pre_tool_use.len(), 3);
        assert_eq!(
            effective_hooks.pre_tool_use[0].command,
            Some(CommandSpec::Argv(vec!["./system.sh".to_string()]))
        );
        assert_eq!(
            effective_hooks.pre_tool_use[1].command,
            Some(CommandSpec::Argv(vec!["./project.sh".to_string()]))
        );
        assert_eq!(
            effective_hooks.pre_tool_use[2].command,
            Some(CommandSpec::Argv(vec!["./local.sh".to_string()]))
        );
    }
}
