use crate::public_warp_adapter::PublicWarpAdapterConfig;
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path};
use uuid::Uuid;

#[derive(Debug)]
pub struct StateStore {
    connection: Connection,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoredWarpInstance {
    pub instance_id: String,
    pub group: String,
    pub label: Option<String>,
    pub enabled: bool,
    pub last_observed_exit_ip: Option<String>,
    pub pool_membership_preference: PoolMembershipPreference,
    pub lifecycle_state: InstanceLifecycleState,
    raw_registration_material: String,
    pub adapter_config: PublicWarpAdapterConfig,
    pub recent_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolMembershipPreference {
    Serving,
    Standby,
    Failed,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceLifecycleState {
    Registered,
    Mock,
    Disabled,
}

impl StateStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create State Store directory {}",
                    parent.display()
                )
            })?;
        }

        let connection = Connection::open(path)
            .with_context(|| format!("failed to open State Store {}", path.display()))?;
        let store = Self { connection };
        store
            .migrate()
            .context("failed to initialize State Store")?;
        Ok(store)
    }

    pub fn upsert_instance(&self, instance: &StoredWarpInstance) -> Result<()> {
        self.connection.execute(
            r#"
            insert into warp_instances (
                instance_id,
                instance_group,
                label,
                enabled,
                last_observed_exit_ip,
                pool_membership_preference,
                lifecycle_state,
                registration_material,
                adapter_kind,
                adapter_config_version,
                adapter_config,
                recent_error
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            on conflict(instance_id) do update set
                instance_group = excluded.instance_group,
                label = excluded.label,
                enabled = excluded.enabled,
                last_observed_exit_ip = excluded.last_observed_exit_ip,
                pool_membership_preference = excluded.pool_membership_preference,
                lifecycle_state = excluded.lifecycle_state,
                registration_material = excluded.registration_material,
                adapter_kind = excluded.adapter_kind,
                adapter_config_version = excluded.adapter_config_version,
                adapter_config = excluded.adapter_config,
                recent_error = excluded.recent_error
            "#,
            params![
                instance.instance_id,
                instance.group,
                instance.label,
                instance.enabled,
                instance.last_observed_exit_ip,
                instance.pool_membership_preference.as_str(),
                instance.lifecycle_state.as_str(),
                instance.raw_registration_material,
                instance.adapter_config.kind,
                instance.adapter_config.version,
                instance.adapter_config.config_json(),
                instance.recent_error,
            ],
        )?;
        Ok(())
    }

    pub fn list_instances(&self) -> Result<Vec<StoredWarpInstance>> {
        let mut statement = self.connection.prepare(
            r#"
            select
                instance_id,
                instance_group,
                label,
                enabled,
                last_observed_exit_ip,
                pool_membership_preference,
                lifecycle_state,
                registration_material,
                adapter_kind,
                adapter_config_version,
                adapter_config,
                recent_error
            from warp_instances
            order by instance_id
            "#,
        )?;

        let instances = statement
            .query_map([], |row| {
                let pool_membership: String = row.get(5)?;
                let lifecycle_state: String = row.get(6)?;
                let adapter_config_version: i64 = row.get(9)?;
                let adapter_config_version =
                    u16::try_from(adapter_config_version).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            9,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                let adapter_config = PublicWarpAdapterConfig::from_storage(
                    row.get::<_, String>(8)?,
                    adapter_config_version,
                    row.get::<_, String>(10)?,
                )
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        10,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            error.to_string(),
                        )),
                    )
                })?;

                Ok(StoredWarpInstance {
                    instance_id: row.get(0)?,
                    group: row.get(1)?,
                    label: row.get(2)?,
                    enabled: row.get(3)?,
                    last_observed_exit_ip: row.get(4)?,
                    pool_membership_preference: PoolMembershipPreference::from_str(
                        &pool_membership,
                    ),
                    lifecycle_state: InstanceLifecycleState::from_str(&lifecycle_state),
                    raw_registration_material: row.get(7)?,
                    adapter_config,
                    recent_error: row.get(11)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(instances)
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            r#"
            create table if not exists warp_instances (
                instance_id text primary key not null,
                instance_group text not null,
                label text,
                enabled integer not null,
                last_observed_exit_ip text,
                pool_membership_preference text not null,
                lifecycle_state text not null,
                registration_material text not null,
                adapter_kind text not null default 'mock',
                adapter_config_version integer not null default 1,
                adapter_config text not null default '{}',
                recent_error text,
                created_at text not null default current_timestamp,
                updated_at text not null default current_timestamp
            );
            "#,
        )?;

        let user_version: i64 = self
            .connection
            .query_row("pragma user_version", [], |row| row.get(0))?;
        if user_version < 2 {
            self.migrate_to_v2()?;
        }
        self.connection.pragma_update(None, "user_version", 2)?;
        Ok(())
    }

    fn migrate_to_v2(&self) -> Result<()> {
        let mut columns = self
            .connection
            .prepare("pragma table_info(warp_instances)")?;
        let column_names = columns
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if !column_names.iter().any(|column| column == "adapter_kind") {
            self.connection.execute_batch(
                r#"
                alter table warp_instances
                    add column adapter_kind text not null default 'mock';
                "#,
            )?;
        }
        if !column_names
            .iter()
            .any(|column| column == "adapter_config_version")
        {
            self.connection.execute_batch(
                r#"
                alter table warp_instances
                    add column adapter_config_version integer not null default 1;
                "#,
            )?;
        }
        if !column_names.iter().any(|column| column == "adapter_config") {
            self.connection.execute_batch(
                r#"
                alter table warp_instances
                    add column adapter_config text not null default '{}';
                "#,
            )?;
        }

        Ok(())
    }
}

impl StoredWarpInstance {
    pub fn new_mock(
        group: impl Into<String>,
        last_observed_exit_ip: Option<&str>,
        pool_membership_preference: PoolMembershipPreference,
        lifecycle_state: InstanceLifecycleState,
        registration_material: impl Into<String>,
    ) -> Self {
        Self::new_with_adapter(
            group,
            last_observed_exit_ip,
            pool_membership_preference,
            lifecycle_state,
            registration_material,
            PublicWarpAdapterConfig::mock(),
        )
    }

    pub fn new_with_adapter(
        group: impl Into<String>,
        last_observed_exit_ip: Option<&str>,
        pool_membership_preference: PoolMembershipPreference,
        lifecycle_state: InstanceLifecycleState,
        raw_registration_material: impl Into<String>,
        adapter_config: PublicWarpAdapterConfig,
    ) -> Self {
        Self {
            instance_id: Uuid::new_v4().to_string(),
            group: group.into(),
            label: None,
            enabled: true,
            last_observed_exit_ip: last_observed_exit_ip.map(ToOwned::to_owned),
            pool_membership_preference,
            lifecycle_state,
            raw_registration_material: raw_registration_material.into(),
            adapter_config,
            recent_error: None,
        }
    }

    pub fn redacted_registration_material(&self) -> &'static str {
        "[redacted]"
    }

    pub fn raw_registration_material(&self) -> &str {
        &self.raw_registration_material
    }
}

impl fmt::Debug for StoredWarpInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredWarpInstance")
            .field("instance_id", &self.instance_id)
            .field("group", &self.group)
            .field("label", &self.label)
            .field("enabled", &self.enabled)
            .field("last_observed_exit_ip", &self.last_observed_exit_ip)
            .field(
                "pool_membership_preference",
                &self.pool_membership_preference,
            )
            .field("lifecycle_state", &self.lifecycle_state)
            .field(
                "raw_registration_material",
                &self.redacted_registration_material(),
            )
            .field("adapter_config", &self.adapter_config)
            .field("recent_error", &self.recent_error)
            .finish()
    }
}

impl PoolMembershipPreference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Serving => "serving",
            Self::Standby => "standby",
            Self::Failed => "failed",
            Self::Disabled => "disabled",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "serving" => Self::Serving,
            "standby" => Self::Standby,
            "failed" => Self::Failed,
            "disabled" => Self::Disabled,
            _ => Self::Failed,
        }
    }
}

impl InstanceLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Mock => "mock",
            Self::Disabled => "disabled",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "registered" => Self::Registered,
            "mock" => Self::Mock,
            "disabled" => Self::Disabled,
            _ => Self::Disabled,
        }
    }
}
