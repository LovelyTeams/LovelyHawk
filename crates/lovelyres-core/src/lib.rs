#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! UI-agnostic services and security boundaries for LovelyRes.
//!
//! This crate deliberately has no dependency on any UI runtime.

pub mod ai;
pub mod apache_capability;
pub mod apache_config;
pub mod apache_runtime;
pub mod apache_visual;
pub mod audit;
pub mod baseline;
pub mod batch;
pub mod command_findings;
pub mod command_workbench;
pub mod compliance;
pub mod configuration_goal;
pub mod connections;
pub mod crypto;
pub mod database;
pub mod database_config;
pub mod database_config_inventory;
pub mod database_config_runtime;
pub mod database_config_schema;
mod database_config_schema_domestic;
mod database_config_schema_open;
pub mod database_config_sources;
pub mod detection;
pub mod docker;
pub mod domain;
pub mod error;
pub mod events;
pub mod file_analysis;
pub mod firewall;
pub mod haproxy_config;
pub mod integrity;
pub mod investigation;
pub mod java;
pub mod kubernetes;
pub mod line_config_visual;
pub mod log_analysis;
pub mod mariadb_config;
pub mod middleware;
pub mod middleware_document;
pub mod mongodb_config;
pub mod mysql_config;
pub mod net_guard;
pub mod nginx_config;
pub mod nginx_visual;
pub mod operations;
pub mod packet_capture;
pub mod path_guard;
pub mod postgres_auth_schema;
pub mod postgresql_config;
pub mod redis_config;
pub mod report;
pub mod services;
pub mod settings;
pub mod sftp;
pub mod shell_escape;
pub mod snapshot;
pub mod ssh;
pub mod ssh_compat;
pub mod store;
pub mod structured_config_visual;
mod structured_gcware;
mod structured_sequoia_csv;
mod structured_xml;
mod structured_yaml;
pub mod system_info;
pub mod target;
pub mod tomcat_config;
pub mod types;

pub use error::{
    CoreError, CoreResult, SshHostRole, SshKeyboardInteractiveChallenge,
    SshKeyboardInteractivePrompt,
};
pub use services::BackendServices;
pub use store::PortableStore;
