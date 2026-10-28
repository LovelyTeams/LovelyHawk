//! Scoped catalog ACL observations. No object data or routine bodies are read.
use crate::postgresql_role_graph::{OrdinaryRoleContext, RoleGraph};
use crate::{
    CoreError, CoreResult,
    postgresql_access::{AccessUnavailable, decode, scalar},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const MAX_JSON: usize = 400 * 1024;
const MAX_PUBLIC: usize = 393216;
const PERMISSIONS: &str = include_str!("postgresql_objects_permissions.sql");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectSection {
    Database,
    Schemas,
    Relations,
    Columns,
    Routines,
    Types,
    Languages,
    Tablespaces,
    ForeignWrappers,
    ForeignServers,
    LargeObjects,
    Parameters,
    Defaults,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectFilter {
    All,
    Public,
    Delegated,
    SecurityDefiner,
    UnfixedDefiner,
}
impl ObjectSection {
    pub const ALL: [Self; 13] = [
        Self::Database,
        Self::Schemas,
        Self::Relations,
        Self::Columns,
        Self::Routines,
        Self::Types,
        Self::Languages,
        Self::Tablespaces,
        Self::ForeignWrappers,
        Self::ForeignServers,
        Self::LargeObjects,
        Self::Parameters,
        Self::Defaults,
    ];
    fn sql(self) -> &'static str {
        match self {
            Self::Database => include_str!("postgresql_objects_database.sql"),
            Self::Schemas => include_str!("postgresql_objects_schemas.sql"),
            Self::Relations => include_str!("postgresql_objects_relations.sql"),
            Self::Columns => include_str!("postgresql_objects_columns.sql"),
            Self::Routines => include_str!("postgresql_objects_routines.sql"),
            Self::Types => include_str!("postgresql_objects_types.sql"),
            Self::Languages => include_str!("postgresql_objects_languages.sql"),
            Self::Tablespaces => include_str!("postgresql_objects_tablespaces.sql"),
            Self::ForeignWrappers => include_str!("postgresql_objects_foreign_wrappers.sql"),
            Self::ForeignServers => include_str!("postgresql_objects_foreign_servers.sql"),
            Self::LargeObjects => include_str!("postgresql_objects_large_objects.sql"),
            Self::Parameters => include_str!("postgresql_objects_parameters.sql"),
            Self::Defaults => include_str!("postgresql_objects_defaults.sql"),
        }
    }
    fn limit(self) -> usize {
        match self {
            Self::Database | Self::Languages | Self::ForeignWrappers => 128,
            Self::Schemas | Self::ForeignServers | Self::Defaults => 512,
            Self::Tablespaces => 256,
            Self::Parameters => 1024,
            _ => 2048,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectPrivilege {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
    Create,
    Connect,
    Temporary,
    Execute,
    Usage,
    Set,
    #[serde(rename = "ALTER SYSTEM")]
    AlterSystem,
    Maintain,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AclSource {
    BuiltinDefault,
    Explicit,
    FutureGlobal,
    FutureSchema,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    grantor_oid: u32,
    grantee_oid: u32,
    privileges: Vec<ObjectPrivilege>,
    grant_options: Vec<ObjectPrivilege>,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ObjectDetail {
    Database {
        allow_connections: bool,
        is_template: bool,
    },
    Schema {
        session_temporary: bool,
        other_temporary: bool,
    },
    Relation {
        relation_kind: String,
        row_security: bool,
        force_row_security: bool,
    },
    Column {
        relation_kind: String,
        row_security: bool,
        force_row_security: bool,
    },
    Routine {
        routine_kind: String,
        language_oid: u32,
        argument_type_oids: Vec<u32>,
        security_definer: bool,
        fixed_search_path: bool,
    },
    Type {
        type_kind: String,
        object_owner_oid: u32,
        acl_type_oid: u32,
        acl_type_name: String,
    },
    Language {
        trusted: bool,
    },
    Tablespace,
    ForeignWrapper,
    ForeignServer,
    LargeObject,
    Parameter,
    Default {
        object_type: String,
    },
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObjectRow {
    oid: u32,
    sub_id: u16,
    #[serde(deserialize_with = "required_option")]
    name: Option<String>,
    owner_oid: u32,
    #[serde(deserialize_with = "required_option")]
    namespace_oid: Option<u32>,
    detail: ObjectDetail,
    acl_source: AclSource,
    acl: Vec<Grant>,
}
impl ObjectRow {
    fn key(&self) -> (u32, u16) {
        (self.oid, self.sub_id)
    }
    fn rights(&self, major: u16) -> Vec<ObjectPrivilege> {
        use ObjectPrivilege::*;
        match &self.detail {
            ObjectDetail::Database { .. } => vec![Create, Connect, Temporary],
            ObjectDetail::Schema { .. } => vec![Usage, Create],
            ObjectDetail::Relation { relation_kind, .. } if relation_kind == "S" => {
                vec![Select, Update, Usage]
            }
            ObjectDetail::Relation { .. } => {
                let mut rights = vec![
                    Select, Insert, Update, Delete, Truncate, References, Trigger,
                ];
                if major >= 17 {
                    rights.push(Maintain);
                }
                rights
            }
            ObjectDetail::Column { .. } => vec![Select, Insert, Update, References],
            ObjectDetail::Routine { .. } => vec![Execute],
            ObjectDetail::Type { .. }
            | ObjectDetail::Language { .. }
            | ObjectDetail::ForeignWrapper
            | ObjectDetail::ForeignServer => vec![Usage],
            ObjectDetail::Tablespace => vec![Create],
            ObjectDetail::LargeObject => vec![Select, Update],
            ObjectDetail::Parameter => vec![Set, AlterSystem],
            ObjectDetail::Default { object_type } => match object_type.as_str() {
                "r" => {
                    let mut rights = vec![
                        Select, Insert, Update, Delete, Truncate, References, Trigger,
                    ];
                    if major >= 17 {
                        rights.push(Maintain);
                    }
                    rights
                }
                "S" => vec![Select, Update, Usage],
                "f" => vec![Execute],
                "T" => vec![Usage],
                "n" => vec![Usage, Create],
                _ => vec![],
            },
        }
    }
    fn valid(&self, section: ObjectSection, major: u16) -> bool {
        let detail = match (&self.detail, section) {
            (ObjectDetail::Database { .. }, ObjectSection::Database)
            | (ObjectDetail::Schema { .. }, ObjectSection::Schemas)
            | (ObjectDetail::Language { .. }, ObjectSection::Languages)
            | (ObjectDetail::Tablespace, ObjectSection::Tablespaces)
            | (ObjectDetail::ForeignWrapper, ObjectSection::ForeignWrappers)
            | (ObjectDetail::ForeignServer, ObjectSection::ForeignServers)
            | (ObjectDetail::LargeObject, ObjectSection::LargeObjects)
            | (ObjectDetail::Parameter, ObjectSection::Parameters) => true,
            (ObjectDetail::Relation { relation_kind, .. }, ObjectSection::Relations) => {
                ["r", "p", "v", "m", "f", "S"].contains(&relation_kind.as_str())
            }
            (ObjectDetail::Column { relation_kind, .. }, ObjectSection::Columns) => {
                ["r", "p", "v", "m", "f"].contains(&relation_kind.as_str())
            }
            (
                ObjectDetail::Routine {
                    routine_kind,
                    language_oid,
                    argument_type_oids,
                    ..
                },
                ObjectSection::Routines,
            ) => {
                ["f", "p", "a", "w"].contains(&routine_kind.as_str())
                    && *language_oid > 0
                    && argument_type_oids.len() <= 100
                    && argument_type_oids.iter().all(|n| *n > 0)
            }
            (
                ObjectDetail::Type {
                    type_kind,
                    object_owner_oid,
                    acl_type_oid,
                    acl_type_name,
                },
                ObjectSection::Types,
            ) => {
                ["b", "c", "d", "e", "p", "r", "m"].contains(&type_kind.as_str())
                    && *object_owner_oid > 0
                    && *acl_type_oid > 0
                    && text(acl_type_name, 256)
            }
            (ObjectDetail::Default { object_type }, ObjectSection::Defaults) => {
                ["r", "S", "f", "T", "n"].contains(&object_type.as_str())
            }
            _ => false,
        };
        let names = if matches!(
            section,
            ObjectSection::LargeObjects | ObjectSection::Defaults
        ) {
            self.name.is_none()
        } else {
            self.name.as_ref().is_some_and(|s| text(s, 256))
        };
        let namespace = if matches!(
            section,
            ObjectSection::Relations
                | ObjectSection::Columns
                | ObjectSection::Routines
                | ObjectSection::Types
        ) {
            self.namespace_oid.is_some_and(|n| n > 0)
        } else if section == ObjectSection::Defaults {
            self.namespace_oid.is_none_or(|n| n > 0)
        } else {
            self.namespace_oid.is_none()
        };
        let source = if section == ObjectSection::Defaults {
            self.acl_source
                == if self.namespace_oid.is_none() {
                    AclSource::FutureGlobal
                } else {
                    AclSource::FutureSchema
                }
        } else {
            matches!(
                self.acl_source,
                AclSource::BuiltinDefault | AclSource::Explicit
            ) && (section != ObjectSection::Columns || self.acl_source == AclSource::Explicit)
        };
        let rights = self.rights(major);
        detail
            && names
            && namespace
            && source
            && self.oid > 0
            && self.owner_oid > 0
            && if section == ObjectSection::Columns {
                self.sub_id > 0 && self.sub_id <= 32767
            } else {
                self.sub_id == 0
            }
            && self.acl.len() <= 128
            && self.acl.windows(2).all(|p| {
                (p[0].grantor_oid, p[0].grantee_oid) < (p[1].grantor_oid, p[1].grantee_oid)
            })
            && self.acl.iter().all(|g| {
                g.grantor_oid > 0
                    && !g.privileges.is_empty()
                    && g.privileges.len() <= rights.len()
                    && g.privileges.iter().all(|p| rights.contains(p))
                    && unique(&g.privileges)
                    && unique(&g.grant_options)
                    && g.grant_options.iter().all(|p| g.privileges.contains(p))
                    && (g.grantee_oid != 0 || g.grant_options.is_empty())
            })
    }
    fn public_rights(&self) -> BTreeSet<ObjectPrivilege> {
        self.acl
            .iter()
            .filter(|g| g.grantee_oid == 0)
            .flat_map(|g| g.privileges.iter().copied())
            .collect()
    }
    fn delegated(&self) -> bool {
        self.acl
            .iter()
            .any(|g| g.grantee_oid != self.owner_oid && !g.grant_options.is_empty())
    }
    fn security_definer(&self) -> bool {
        matches!(
            self.detail,
            ObjectDetail::Routine {
                security_definer: true,
                ..
            }
        )
    }
    fn unfixed_definer(&self) -> bool {
        matches!(
            self.detail,
            ObjectDetail::Routine {
                security_definer: true,
                fixed_search_path: false,
                ..
            }
        )
    }
}
fn text(value: &str, cap: usize) -> bool {
    !value.is_empty() && value.len() <= cap && !value.chars().any(char::is_control)
}
fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
fn fingerprint<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(Zeroizing::new))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    overflow: bool,
    omitted_defaults: u32,
    rows: Vec<ObjectRow>,
    #[serde(deserialize_with = "fingerprint")]
    fingerprint: Option<Zeroizing<String>>,
}
struct Reading {
    rows: Vec<ObjectRow>,
    omitted: u32,
    fingerprint: Option<Zeroizing<String>>,
    reason: Option<AccessUnavailable>,
}
impl Reading {
    fn unavailable(reason: AccessUnavailable) -> Self {
        Self {
            rows: vec![],
            omitted: 0,
            fingerprint: None,
            reason: Some(reason),
        }
    }
    fn parse(
        bytes: Zeroizing<Vec<u8>>,
        section: ObjectSection,
        major: u16,
    ) -> Result<Self, AccessUnavailable> {
        let value: Envelope = decode(bytes)?;
        if value.overflow {
            return Err(if value.rows.is_empty() && value.fingerprint.is_none() {
                AccessUnavailable::LimitExceeded
            } else {
                AccessUnavailable::InvalidOutput
            });
        }
        if value.rows.len() > section.limit()
            || serde_json::to_vec(&value.rows)
                .map_err(|_| AccessUnavailable::InvalidOutput)?
                .len()
                > MAX_PUBLIC
            || value.rows.iter().any(|r| !r.valid(section, major))
            || !value.rows.windows(2).all(|p| p[0].key() < p[1].key())
            || value.fingerprint.as_ref().is_none_or(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || value.omitted_defaults != 0
                && !matches!(
                    section,
                    ObjectSection::Routines | ObjectSection::Types | ObjectSection::Columns
                )
        {
            return Err(AccessUnavailable::InvalidOutput);
        }
        Ok(Self {
            rows: value.rows,
            omitted: value.omitted_defaults,
            fingerprint: value.fingerprint,
            reason: None,
        })
    }
}
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Permissions {
    database: bool,
    schemas: bool,
    relations: bool,
    columns: bool,
    routines: bool,
    types: bool,
    languages: bool,
    tablespaces: bool,
    foreign_wrappers: bool,
    foreign_servers: bool,
    large_objects: bool,
    parameters: bool,
    defaults: bool,
    functions: bool,
}
impl Permissions {
    fn allows(&self, section: ObjectSection) -> bool {
        self.functions
            && match section {
                ObjectSection::Database => self.database,
                ObjectSection::Schemas => self.schemas,
                ObjectSection::Relations => self.relations,
                ObjectSection::Columns => self.columns,
                ObjectSection::Routines => self.routines,
                ObjectSection::Types => self.types,
                ObjectSection::Languages => self.languages,
                ObjectSection::Tablespaces => self.tablespaces,
                ObjectSection::ForeignWrappers => self.foreign_wrappers,
                ObjectSection::ForeignServers => self.foreign_servers,
                ObjectSection::LargeObjects => self.large_objects,
                ObjectSection::Parameters => self.parameters,
                ObjectSection::Defaults => self.defaults,
            }
    }
}
pub(crate) struct ObjectReading {
    permissions: Result<Permissions, AccessUnavailable>,
    sections: BTreeMap<ObjectSection, Reading>,
}
pub(crate) async fn read(client: &tokio_postgres::Client, major: u16) -> ObjectReading {
    let permissions: Result<Permissions, _> =
        scalar(client, PERMISSIONS, 4096).await.and_then(decode);
    let mut sections = BTreeMap::new();
    for section in ObjectSection::ALL {
        let reading = match &permissions {
            Err(reason) => Reading::unavailable(*reason),
            Ok(p) if !p.allows(section) => {
                Reading::unavailable(AccessUnavailable::PermissionDenied)
            }
            Ok(_) => match scalar(client, section.sql(), MAX_JSON * 2 + 1)
                .await
                .and_then(|bytes| Reading::parse(bytes, section, major))
            {
                Ok(reading) => reading,
                Err(reason) => Reading::unavailable(reason),
            },
        };
        sections.insert(section, reading);
    }
    ObjectReading {
        permissions,
        sections,
    }
}
#[derive(Clone)]
struct Collection {
    rows: Vec<ObjectRow>,
    omitted: u32,
    reason: Option<AccessUnavailable>,
}
#[derive(Clone)]
pub struct PostgresqlObjectReview {
    sections: BTreeMap<ObjectSection, Collection>,
}
impl std::fmt::Debug for PostgresqlObjectReview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresqlObjectReview")
            .field("summary", &self.summary())
            .finish()
    }
}
impl PostgresqlObjectReview {
    pub(crate) fn unavailable(reason: AccessUnavailable) -> Self {
        Self {
            sections: ObjectSection::ALL
                .into_iter()
                .map(|s| {
                    (
                        s,
                        Collection {
                            rows: vec![],
                            omitted: 0,
                            reason: Some(reason),
                        },
                    )
                })
                .collect(),
        }
    }
    pub(crate) fn finish(mut before: ObjectReading, mut after: ObjectReading) -> Self {
        if before.permissions != after.permissions {
            return Self::unavailable(AccessUnavailable::Changed);
        }
        let sections = ObjectSection::ALL
            .into_iter()
            .map(|section| {
                let first = before.sections.remove(&section).expect("all sections");
                let second = after.sections.remove(&section).expect("all sections");
                let reason = first.reason.or(second.reason).or_else(|| {
                    (first.rows != second.rows
                        || first.fingerprint != second.fingerprint
                        || first.omitted != second.omitted)
                        .then_some(AccessUnavailable::Changed)
                });
                (
                    section,
                    Collection {
                        rows: if reason.is_none() {
                            second.rows
                        } else {
                            vec![]
                        },
                        omitted: second.omitted,
                        reason,
                    },
                )
            })
            .collect();
        Self { sections }
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::to_value(self.sections.iter().map(|(section,c)| {
            let summary=if let Some(reason)=c.reason { serde_json::json!({"state":"unavailable","reason":reason,"total":null,"omittedDefaults":null,"publicObjects":null,"delegatedObjects":null,"securityDefiners":null,"unfixedDefiners":null}) }
            else { serde_json::json!({"state":"available","reason":null,"total":c.rows.len(),"omittedDefaults":c.omitted,"publicObjects":c.rows.iter().filter(|r| !r.public_rights().is_empty()).count(),"delegatedObjects":c.rows.iter().filter(|r| r.delegated()).count(),"securityDefiners":c.rows.iter().filter(|r| r.security_definer()).count(),"unfixedDefiners":c.rows.iter().filter(|r| r.unfixed_definer()).count()}) };
            (*section,summary)
        }).collect::<BTreeMap<_,_>>()).expect("finite summary")
    }
    pub fn case_summary(&self) -> String {
        let mut out = String::from(
            "对象授权：目录 ACL 与静态来源；未读取业务数据/函数正文，未验证实际操作。\n",
        );
        for (section, c) in &self.sections {
            let name = serde_json::to_value(section).expect("section");
            let name = name.as_str().expect("section string");
            if let Some(reason) = c.reason {
                out.push_str(&format!(
                    "  {name}：未取得（{}）\n",
                    serde_json::to_value(reason)
                        .expect("reason")
                        .as_str()
                        .expect("reason string")
                ));
            } else {
                out.push_str(&format!("  {name}：{} 对象，PUBLIC {}，转授权 {}，定义者权限 {}（未固定搜索路径 {}），范围外默认项 {}\n",c.rows.len(),c.rows.iter().filter(|r| !r.public_rights().is_empty()).count(),c.rows.iter().filter(|r| r.delegated()).count(),c.rows.iter().filter(|r| r.security_definer()).count(),c.rows.iter().filter(|r| r.unfixed_definer()).count(),c.omitted));
            }
        }
        out
    }
    fn row(&self, section: ObjectSection, oid: u32, sub_id: u16) -> Option<&ObjectRow> {
        let collection = self.sections.get(&section)?;
        if collection.reason.is_some() {
            return None;
        }
        collection.rows.iter().find(|r| r.key() == (oid, sub_id))
    }
    fn metadata(&self, row: &ObjectRow, names: &BTreeMap<u32, &str>) -> serde_json::Value {
        let namespace = row
            .namespace_oid
            .and_then(|oid| self.row(ObjectSection::Schemas, oid, 0))
            .and_then(|r| r.name.as_ref());
        let parent = if row.sub_id != 0 {
            self.row(ObjectSection::Relations, row.oid, 0)
                .and_then(|r| r.name.as_ref())
        } else {
            None
        };
        serde_json::json!({"oid":row.oid,"subId":row.sub_id,"name":row.name,"ownerOid":row.owner_oid,"ownerName":names.get(&row.owner_oid),
            "namespaceOid":row.namespace_oid,"namespaceName":namespace,"parentName":parent,"detail":row.detail,"aclSource":row.acl_source,
            "catalogWriteRestricted":protected_catalog(row),"grantCount":row.acl.len(),"publicPrivileges":row.public_rights(),"delegated":row.delegated()})
    }
    pub(crate) fn page(
        &self,
        section: ObjectSection,
        query: &str,
        filter: ObjectFilter,
        offset: usize,
        names: &BTreeMap<u32, &str>,
    ) -> CoreResult<serde_json::Value> {
        if query.len() > 128 || query.chars().any(char::is_control) || offset > 2048 {
            return Err(invalid());
        }
        let collection = self.sections.get(&section).ok_or_else(invalid)?;
        if collection.reason.is_some() {
            return Err(invalid());
        }
        let query_folded = query.to_lowercase();
        let matching: Vec<_> = collection
            .rows
            .iter()
            .filter(|r| {
                let selected = match filter {
                    ObjectFilter::All => true,
                    ObjectFilter::Public => !r.public_rights().is_empty(),
                    ObjectFilter::Delegated => r.delegated(),
                    ObjectFilter::SecurityDefiner => r.security_definer(),
                    ObjectFilter::UnfixedDefiner => r.unfixed_definer(),
                };
                let namespace = r
                    .namespace_oid
                    .and_then(|oid| self.row(ObjectSection::Schemas, oid, 0))
                    .and_then(|n| n.name.as_deref());
                let parent = (r.sub_id != 0)
                    .then(|| self.row(ObjectSection::Relations, r.oid, 0))
                    .flatten()
                    .and_then(|r| r.name.as_deref());
                selected
                    && (query_folded.is_empty()
                        || [
                            r.name.as_deref(),
                            names.get(&r.owner_oid).copied(),
                            namespace,
                            parent,
                        ]
                        .into_iter()
                        .flatten()
                        .any(|s| s.to_lowercase().contains(&query_folded))
                        || r.oid.to_string() == query_folded)
            })
            .collect();
        Ok(
            serde_json::json!({"section":section,"query":query,"filter":filter,"offset":offset,"total":collection.rows.len(),"matched":matching.len(),"rows":matching.iter().skip(offset).take(50).map(|r|self.metadata(r,names)).collect::<Vec<_>>()}),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn detail(
        &self,
        section: ObjectSection,
        oid: u32,
        sub_id: u16,
        role_oid: Option<u32>,
        names: &BTreeMap<u32, &str>,
        graph: Option<&RoleGraph>,
        major: u16,
    ) -> CoreResult<serde_json::Value> {
        let row = self.row(section, oid, sub_id).ok_or_else(invalid)?;
        if section == ObjectSection::Defaults && role_oid.is_some() {
            return Err(invalid());
        }
        let context = role_oid
            .map(|oid| {
                graph
                    .and_then(|g| g.ordinary_context(oid))
                    .ok_or_else(invalid)
            })
            .transpose()?;
        let parent = (section == ObjectSection::Columns)
            .then(|| self.row(ObjectSection::Relations, oid, 0))
            .flatten();
        let grants = self.grants(
            &row.acl,
            names,
            context.as_ref(),
            section == ObjectSection::Defaults,
        );
        let parent_grants = parent
            .map(|p| self.grants(&p.acl, names, context.as_ref(), false))
            .unwrap_or_default();
        let analysis = context.as_ref().map(|context| {
            self.analysis(
                row,
                parent,
                section,
                context,
                graph.expect("selected context"),
                major,
            )
        });
        Ok(
            serde_json::json!({"section":section,"oid":oid,"subId":sub_id,"roleOid":role_oid,"object":self.metadata(row,names),"grants":grants,"tableGrants":parent_grants,
            "role":context.as_ref().map(|c|&c.source),"analysis":analysis}),
        )
    }
    fn grants(
        &self,
        grants: &[Grant],
        names: &BTreeMap<u32, &str>,
        context: Option<&OrdinaryRoleContext>,
        future: bool,
    ) -> Vec<serde_json::Value> {
        grants.iter().map(|g|serde_json::json!({"grantorOid":g.grantor_oid,"grantorName":names.get(&g.grantor_oid),"granteeOid":g.grantee_oid,"granteeName":if g.grantee_oid==0 {Some("PUBLIC")} else {names.get(&g.grantee_oid).copied()},
            "privileges":g.privileges,"grantOptions":g.grant_options,"via":if future {"future-default"} else if g.grantee_oid==0 {"public"} else {context.map_or("not-selected",|c|if reach(c,g.grantee_oid)!="unreachable" || names.contains_key(&g.grantee_oid) {reach(c,g.grantee_oid)} else {"unknown-role"})}})).collect()
    }
    fn analysis(
        &self,
        row: &ObjectRow,
        parent: Option<&ObjectRow>,
        section: ObjectSection,
        context: &OrdinaryRoleContext,
        graph: &RoleGraph,
        major: u16,
    ) -> serde_json::Value {
        let unavailable = |reason| serde_json::json!({"state":"unavailable","reason":reason,"currentPrivileges":null,"currentGrantOptions":null,"additionalAfterSet":null,"additionalGrantOptionsAfterSet":null,"ownerVia":null,"schemaUsage":null,"implicit":[]});
        if section == ObjectSection::Columns && parent.is_none() {
            return unavailable("table-unavailable");
        }
        let database = graph.database();
        if self
            .row(ObjectSection::Database, database.oid, 0)
            .is_none_or(|r| {
                r.owner_oid != database.owner_oid
                    || r.name.as_deref() != Some(database.name.as_str())
            })
        {
            return unavailable("database-context");
        }
        let temporary = |r: &ObjectRow| {
            matches!(
                r.detail,
                ObjectDetail::Schema {
                    session_temporary: true,
                    ..
                } | ObjectDetail::Schema {
                    other_temporary: true,
                    ..
                }
            )
        };
        if temporary(row)
            || row
                .namespace_oid
                .and_then(|oid| self.row(ObjectSection::Schemas, oid, 0))
                .is_some_and(temporary)
        {
            return unavailable("temporary-namespace");
        }
        let known = |r: &ObjectRow| {
            graph.role(r.owner_oid).is_some()
                && r.acl.iter().all(|g| {
                    graph.role(g.grantor_oid).is_some()
                        && (g.grantee_oid == 0 || graph.role(g.grantee_oid).is_some())
                })
        };
        if !known(row) || parent.is_some_and(|p| !known(p)) {
            return unavailable("unknown-role");
        }
        let rights = row.rights(major);
        let mut current = BTreeSet::new();
        let mut options = BTreeSet::new();
        let mut later = BTreeSet::new();
        let mut later_options = BTreeSet::new();
        for (grant, from_table) in row
            .acl
            .iter()
            .map(|g| (g, section != ObjectSection::Columns))
            .chain(
                parent
                    .into_iter()
                    .flat_map(|p| p.acl.iter().map(|g| (g, true))),
            )
        {
            let via = if grant.grantee_oid == 0 {
                "public"
            } else {
                reach(context, grant.grantee_oid)
            };
            let (privileges, grant_options) = if matches!(via, "public" | "self" | "inherit") {
                (&mut current, &mut options)
            } else if via == "after-set" {
                (&mut later, &mut later_options)
            } else {
                continue;
            };
            privileges.extend(grant.privileges.iter().copied().filter(|p| {
                rights.contains(p)
                    && (!from_table
                        || !protected_catalog(row)
                        || !catalog_write(*p)
                        || if via == "after-set" {
                            context.set_superuser.is_some()
                        } else {
                            context.source.superuser
                        })
            }));
            grant_options.extend(
                grant
                    .grant_options
                    .iter()
                    .copied()
                    .filter(|p| rights.contains(p)),
            );
        }
        let owner_via = if context.source.superuser {
            "superuser"
        } else {
            reach(context, row.owner_oid)
        };
        if matches!(owner_via, "self" | "inherit" | "superuser") {
            options.extend(rights.iter().copied());
        } else if owner_via == "after-set" {
            later_options.extend(rights.iter().copied());
        }
        let mut implicit = vec![];
        if context.source.superuser {
            current.extend(rights.iter().copied());
            implicit.push(serde_json::json!({"sourceOid":context.source.oid,"sourceName":context.source.name,"via":"superuser","privileges":rights}));
        }
        if let Some(oid) = context.set_superuser {
            later.extend(rights.iter().copied());
            later_options.extend(rights.iter().copied());
            implicit.push(serde_json::json!({"sourceOid":oid,"sourceName":graph.role(oid).expect("graph role").name,"via":"superuser-after-set","privileges":rights}));
        }
        for (oid, name) in [
            (6181, "pg_read_all_data"),
            (6182, "pg_write_all_data"),
            (6337, "pg_maintain"),
        ] {
            if graph.role(oid).is_none_or(|r| r.name != name) {
                continue;
            }
            let privileges: Vec<_> = builtin_rights(row, oid, major)
                .into_iter()
                .filter(|p| {
                    !protected_catalog(row)
                        || !catalog_write(*p)
                        || context.source.superuser
                        || reach(context, oid) == "after-set" && context.set_superuser.is_some()
                })
                .collect();
            let via = reach(context, oid);
            if privileges.is_empty() || !matches!(via, "self" | "inherit" | "after-set") {
                continue;
            }
            if via == "after-set" {
                later.extend(privileges.iter().copied());
            } else {
                current.extend(privileges.iter().copied());
            }
            implicit.push(serde_json::json!({"sourceOid":oid,"sourceName":name,"via":via,"privileges":privileges}));
        }
        let schema_usage = row.namespace_oid.map(|oid| {
            self.row(ObjectSection::Schemas, oid, 0).and_then(|schema| {
                if !known(schema) {
                    return None;
                }
                let current_usage = context.source.superuser
                    || schema.acl.iter().any(|g| {
                        g.privileges.contains(&ObjectPrivilege::Usage)
                            && (g.grantee_oid == 0 || context.inherited.contains(&g.grantee_oid))
                    })
                    || [6181, 6182]
                        .iter()
                        .any(|oid| context.inherited.contains(oid));
                Some(current_usage)
            })
        });
        serde_json::json!({"state":"available","reason":null,"currentPrivileges":current,"currentGrantOptions":options,
            "additionalAfterSet":later.difference(&current).copied().collect::<Vec<_>>(),"additionalGrantOptionsAfterSet":later_options.difference(&options).copied().collect::<Vec<_>>(),
            "ownerVia":owner_via,"schemaUsage":schema_usage.flatten(),"implicit":implicit})
    }
}
fn protected_catalog(row: &ObjectRow) -> bool {
    matches!(&row.detail,ObjectDetail::Relation {relation_kind,..}|ObjectDetail::Column {relation_kind,..} if relation_kind!="v" && (row.oid<12000 || row.namespace_oid==Some(99)))
}
fn catalog_write(privilege: ObjectPrivilege) -> bool {
    matches!(
        privilege,
        ObjectPrivilege::Insert
            | ObjectPrivilege::Update
            | ObjectPrivilege::Delete
            | ObjectPrivilege::Truncate
            | ObjectPrivilege::Usage
    )
}
fn reach(context: &OrdinaryRoleContext, oid: u32) -> &'static str {
    if oid == context.source.oid {
        "self"
    } else if context.inherited.contains(&oid) {
        "inherit"
    } else if context.after_set.contains(&oid) {
        "after-set"
    } else {
        "unreachable"
    }
}
fn builtin_rights(row: &ObjectRow, oid: u32, major: u16) -> Vec<ObjectPrivilege> {
    use ObjectPrivilege::*;
    let candidate = match (&row.detail, oid) {
        (ObjectDetail::Schema { .. }, 6181 | 6182) => vec![Usage],
        (ObjectDetail::Relation { .. } | ObjectDetail::Column { .. }, 6181) => vec![Select],
        (ObjectDetail::Relation { .. } | ObjectDetail::Column { .. }, 6182) => {
            vec![Insert, Update, Delete]
        }
        (ObjectDetail::Relation { relation_kind, .. }, 6337)
            if major >= 17 && relation_kind != "S" =>
        {
            vec![Maintain]
        }
        _ => vec![],
    };
    let rights = row.rights(major);
    candidate
        .into_iter()
        .filter(|p| rights.contains(p))
        .collect()
}
fn invalid() -> CoreError {
    CoreError::validation(
        "PostgreSQL object ACL",
        "对象授权结果无法核对，请重新读取数据库状态。",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgresql_role_graph::{DatabaseContext, Membership, Role};
    use serde_json::{Value, json};
    fn encode(value: Value) -> Zeroizing<Vec<u8>> {
        let mut bytes = serde_json::to_vec(&value)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        bytes.push('\n');
        Zeroizing::new(bytes.into_bytes())
    }
    fn envelope(rows: Value) -> Value {
        json!({"overflow":false,"omittedDefaults":0,"rows":rows,"fingerprint":"a".repeat(64)})
    }
    fn row() -> Value {
        json!({"oid":18000,"subId":0,"name":"accounts","ownerOid":1,"namespaceOid":2200,"detail":{"kind":"relation","relationKind":"r","rowSecurity":true,"forceRowSecurity":false},"aclSource":"explicit","acl":[]})
    }
    fn graph() -> RoleGraph {
        let mut roles: Vec<_> = [1, 2, 3, 4, 5, 6, 6171, 6181, 6182]
            .into_iter()
            .map(|oid| Role {
                oid,
                name: match oid {
                    6171 => "pg_database_owner".into(),
                    6181 => "pg_read_all_data".into(),
                    6182 => "pg_write_all_data".into(),
                    _ => format!("role_{oid}"),
                },
                can_login: true,
                superuser: oid == 5,
                create_role: false,
                create_database: false,
                replication: false,
                bypass_rls: false,
            })
            .collect();
        roles.sort_by_key(|r| r.oid);
        let grants = [
            (2, 3, true, false),
            (2, 4, false, true),
            (6, 5, false, true),
        ]
        .into_iter()
        .enumerate()
        .map(
            |(i, (member_oid, role_oid, inherit_option, set_option))| Membership {
                oid: i as u32 + 1,
                role_oid,
                member_oid,
                grantor_oid: 1,
                admin_option: false,
                inherit_option,
                set_option,
            },
        )
        .collect::<Vec<_>>();
        RoleGraph::build(
            roles,
            &grants,
            DatabaseContext {
                oid: 5,
                name: "postgres".into(),
                owner_oid: 1,
            },
        )
        .unwrap()
    }
    fn review(rows: Vec<(ObjectSection, Value)>) -> PostgresqlObjectReview {
        let mut review = PostgresqlObjectReview::unavailable(AccessUnavailable::PermissionDenied);
        let database: ObjectRow=serde_json::from_value(json!({"oid":5,"subId":0,"name":"postgres","ownerOid":1,"namespaceOid":null,"detail":{"kind":"database","allowConnections":true,"isTemplate":false},"aclSource":"explicit","acl":[]})).unwrap();
        review.sections.insert(
            ObjectSection::Database,
            Collection {
                rows: vec![database],
                omitted: 0,
                reason: None,
            },
        );
        for (section, value) in rows {
            review.sections.insert(
                section,
                Collection {
                    rows: vec![serde_json::from_value(value).unwrap()],
                    omitted: 0,
                    reason: None,
                },
            );
        }
        review
    }
    fn grant(grantee: u32, rights: Vec<ObjectPrivilege>) -> Grant {
        Grant {
            grantor_oid: 1,
            grantee_oid: grantee,
            privileges: rights,
            grant_options: vec![],
        }
    }
    #[test]
    fn catalog_records_reject_missing_secret_and_wrong_privilege_fields() {
        let base = row();
        assert!(
            Reading::parse(
                encode(envelope(json!([base.clone()]))),
                ObjectSection::Relations,
                16
            )
            .is_ok()
        );
        for key in base.as_object().unwrap().keys() {
            let mut partial = base.clone();
            partial.as_object_mut().unwrap().remove(key);
            assert!(
                Reading::parse(
                    encode(envelope(json!([partial]))),
                    ObjectSection::Relations,
                    16
                )
                .is_err()
            );
        }
        for key in ["body", "serverOptions", "privateSettings", "password"] {
            let mut secret = base.clone();
            secret[key] = json!("do-not-export");
            assert!(
                Reading::parse(
                    encode(envelope(json!([secret]))),
                    ObjectSection::Relations,
                    16
                )
                .is_err()
            );
        }
        let mut maintenance = base.clone();
        maintenance["acl"] =
            serde_json::to_value(vec![grant(2, vec![ObjectPrivilege::Maintain])]).unwrap();
        assert!(
            Reading::parse(
                encode(envelope(json!([maintenance.clone()]))),
                ObjectSection::Relations,
                16
            )
            .is_err()
        );
        assert!(
            Reading::parse(
                encode(envelope(json!([maintenance]))),
                ObjectSection::Relations,
                17
            )
            .is_ok()
        );
        let mut public_option = base;
        let mut g = grant(0, vec![ObjectPrivilege::Select]);
        g.grant_options = vec![ObjectPrivilege::Select];
        public_option["acl"] = serde_json::to_value(vec![g]).unwrap();
        assert!(
            Reading::parse(
                encode(envelope(json!([public_option]))),
                ObjectSection::Relations,
                16
            )
            .is_err()
        );
    }
    #[test]
    fn owner_can_regrant_without_already_holding_revoked_ordinary_privileges() {
        let review = review(vec![(ObjectSection::Relations, row())]);
        let graph = graph();
        let detail = review
            .detail(
                ObjectSection::Relations,
                18000,
                0,
                Some(1),
                &BTreeMap::new(),
                Some(&graph),
                16,
            )
            .unwrap();
        assert_eq!(detail["analysis"]["currentPrivileges"], json!([]));
        assert_eq!(
            detail["analysis"]["currentGrantOptions"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(detail["analysis"]["ownerVia"], "self");
        assert!(detail["analysis"]["schemaUsage"].is_null());
        let superuser = review
            .detail(
                ObjectSection::Relations,
                18000,
                0,
                Some(5),
                &BTreeMap::new(),
                Some(&graph),
                16,
            )
            .unwrap();
        assert_eq!(
            superuser["analysis"]["currentPrivileges"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        let later = review
            .detail(
                ObjectSection::Relations,
                18000,
                0,
                Some(6),
                &BTreeMap::new(),
                Some(&graph),
                16,
            )
            .unwrap();
        assert_eq!(
            later["analysis"]["additionalAfterSet"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(
            later["analysis"]["implicit"][0]["via"],
            "superuser-after-set"
        );
    }
    #[test]
    fn column_analysis_combines_table_grants_and_keeps_switching_separate() {
        let mut table = row();
        table["acl"] = serde_json::to_value(vec![grant(3, vec![ObjectPrivilege::Select])]).unwrap();
        let mut column = row();
        column["subId"] = json!(1);
        column["name"] = json!("balance");
        column["detail"]["kind"] = json!("column");
        column["acl"] =
            serde_json::to_value(vec![grant(4, vec![ObjectPrivilege::Update])]).unwrap();
        let review = review(vec![
            (ObjectSection::Relations, table),
            (ObjectSection::Columns, column),
        ]);
        let graph = graph();
        let detail = review
            .detail(
                ObjectSection::Columns,
                18000,
                1,
                Some(2),
                &BTreeMap::new(),
                Some(&graph),
                16,
            )
            .unwrap();
        assert_eq!(detail["analysis"]["currentPrivileges"], json!(["SELECT"]));
        assert_eq!(detail["analysis"]["additionalAfterSet"], json!(["UPDATE"]));
        assert_eq!(detail["grants"][0]["via"], "after-set");
        assert_eq!(detail["tableGrants"][0]["via"], "inherit");
        assert_eq!(detail["object"]["detail"]["rowSecurity"], true);
        let mut missing = PostgresqlObjectReview::unavailable(AccessUnavailable::PermissionDenied);
        missing.sections.insert(
            ObjectSection::Database,
            review.sections[&ObjectSection::Database].clone(),
        );
        assert_eq!(
            missing.analysis(
                review.row(ObjectSection::Columns, 18000, 1).unwrap(),
                None,
                ObjectSection::Columns,
                &graph.ordinary_context(2).unwrap(),
                &graph,
                16
            )["reason"],
            "table-unavailable"
        );
    }
    #[test]
    fn defaults_are_future_scoped_and_untrusted_catalog_text_stays_out_of_debug_and_cases() {
        let default = json!({"oid":18001,"subId":0,"name":null,"ownerOid":1,"namespaceOid":null,"detail":{"kind":"default","objectType":"f"},"aclSource":"future-global","acl":[]});
        assert!(
            Reading::parse(
                encode(envelope(json!([default.clone()]))),
                ObjectSection::Defaults,
                16
            )
            .is_ok()
        );
        let mut wrong = default.clone();
        wrong["aclSource"] = json!("builtin-default");
        assert!(
            Reading::parse(
                encode(envelope(json!([wrong]))),
                ObjectSection::Defaults,
                16
            )
            .is_err()
        );
        let mut named = row();
        named["name"] = json!("sensitive-looking-object-name");
        let review = review(vec![
            (ObjectSection::Defaults, default),
            (ObjectSection::Relations, named),
        ]);
        assert!(
            review
                .detail(
                    ObjectSection::Defaults,
                    18001,
                    0,
                    Some(1),
                    &BTreeMap::new(),
                    Some(&graph()),
                    16
                )
                .is_err()
        );
        assert!(!review.case_summary().contains("sensitive-looking"));
        assert!(!format!("{review:?}").contains("sensitive-looking"));
    }

    #[test]
    fn protected_table_writes_do_not_remove_explicit_column_grants_or_grant_options() {
        let mut table = row();
        table["oid"] = json!(1259);
        table["namespaceOid"] = json!(11);
        let mut g = grant(3, vec![ObjectPrivilege::Update]);
        g.grant_options = vec![ObjectPrivilege::Update];
        table["acl"] = serde_json::to_value(vec![g]).unwrap();
        let mut column = table.clone();
        column["subId"] = json!(1);
        column["detail"]["kind"] = json!("column");
        let review = review(vec![
            (ObjectSection::Relations, table),
            (ObjectSection::Columns, column),
        ]);
        let graph = graph();
        let table = review
            .detail(
                ObjectSection::Relations,
                1259,
                0,
                Some(2),
                &BTreeMap::new(),
                Some(&graph),
                16,
            )
            .unwrap();
        assert_eq!(table["analysis"]["currentPrivileges"], json!([]));
        assert_eq!(table["analysis"]["currentGrantOptions"], json!(["UPDATE"]));
        assert_eq!(table["object"]["catalogWriteRestricted"], true);
        let column = review
            .detail(
                ObjectSection::Columns,
                1259,
                1,
                Some(2),
                &BTreeMap::new(),
                Some(&graph),
                16,
            )
            .unwrap();
        assert_eq!(column["analysis"]["currentPrivileges"], json!(["UPDATE"]));
    }
    #[test]
    fn temporary_context_and_unknown_references_do_not_become_negative_privilege_results() {
        let mut unknown = row();
        unknown["ownerOid"] = json!(999);
        let review_unknown = review(vec![(ObjectSection::Relations, unknown)]);
        let graph = graph();
        assert_eq!(
            review_unknown
                .detail(
                    ObjectSection::Relations,
                    18000,
                    0,
                    Some(2),
                    &BTreeMap::new(),
                    Some(&graph),
                    16
                )
                .unwrap()["analysis"]["reason"],
            "unknown-role"
        );
        let schema = json!({"oid":2200,"subId":0,"name":"pg_temp_7","ownerOid":1,"namespaceOid":null,"detail":{"kind":"schema","sessionTemporary":false,"otherTemporary":true},"aclSource":"explicit","acl":[]});
        let review_temp = review(vec![
            (ObjectSection::Schemas, schema),
            (ObjectSection::Relations, row()),
        ]);
        assert_eq!(
            review_temp
                .detail(
                    ObjectSection::Relations,
                    18000,
                    0,
                    Some(2),
                    &BTreeMap::new(),
                    Some(&graph),
                    16
                )
                .unwrap()["analysis"]["reason"],
            "temporary-namespace"
        );
    }
    #[test]
    fn private_only_changes_invalidate_one_catalog_without_exposing_its_fingerprint() {
        let reading = |fingerprint: &str| ObjectReading {
            permissions: Err(AccessUnavailable::QueryFailed),
            sections: ObjectSection::ALL
                .into_iter()
                .map(|section| {
                    let rows = if section == ObjectSection::Relations {
                        json!([row()])
                    } else {
                        json!([])
                    };
                    let mut value = envelope(rows);
                    value["fingerprint"] = json!(if section == ObjectSection::Relations {
                        fingerprint.repeat(64)
                    } else {
                        "a".repeat(64)
                    });
                    (section, Reading::parse(encode(value), section, 16).unwrap())
                })
                .collect(),
        };
        let review = PostgresqlObjectReview::finish(reading("a"), reading("b"));
        assert_eq!(review.summary()["relations"]["reason"], "changed");
        assert_eq!(review.summary()["schemas"]["state"], "available");
        assert!(!review.case_summary().contains(&"b".repeat(64)));
        assert!(
            review
                .page(
                    ObjectSection::Relations,
                    "",
                    ObjectFilter::All,
                    0,
                    &BTreeMap::new()
                )
                .is_err()
        );
    }
}
