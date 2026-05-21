use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug)]
pub struct StateStore {
    connection: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWarpInstance {
    pub instance_id: String,
    pub group: String,
    pub label: Option<String>,
    pub enabled: bool,
    pub last_observed_exit_ip: Option<String>,
    pub pool_membership_preference: PoolMembershipPreference,
    pub lifecycle_state: InstanceLifecycleState,
    registration_material: String,
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
                recent_error
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            on conflict(instance_id) do update set
                instance_group = excluded.instance_group,
                label = excluded.label,
                enabled = excluded.enabled,
                last_observed_exit_ip = excluded.last_observed_exit_ip,
                pool_membership_preference = excluded.pool_membership_preference,
                lifecycle_state = excluded.lifecycle_state,
                registration_material = excluded.registration_material,
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
                instance.registration_material,
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
                recent_error
            from warp_instances
            order by instance_id
            "#,
        )?;

        let instances = statement
            .query_map([], |row| {
                let pool_membership: String = row.get(5)?;
                let lifecycle_state: String = row.get(6)?;

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
                    registration_material: row.get(7)?,
                    recent_error: row.get(8)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(instances)
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            r#"
            pragma user_version = 1;

            create table if not exists warp_instances (
                instance_id text primary key not null,
                instance_group text not null,
                label text,
                enabled integer not null,
                last_observed_exit_ip text,
                pool_membership_preference text not null,
                lifecycle_state text not null,
                registration_material text not null,
                recent_error text,
                created_at text not null default current_timestamp,
                updated_at text not null default current_timestamp
            );
            "#,
        )?;
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
        Self {
            instance_id: Uuid::new_v4().to_string(),
            group: group.into(),
            label: None,
            enabled: true,
            last_observed_exit_ip: last_observed_exit_ip.map(ToOwned::to_owned),
            pool_membership_preference,
            lifecycle_state,
            registration_material: registration_material.into(),
            recent_error: None,
        }
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
