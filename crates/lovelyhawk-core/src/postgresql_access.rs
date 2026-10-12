//! Bounded current-file diagnostics and direct role attributes, not loaded policy.
//! Authentication option values and password verifiers never leave PostgreSQL.
use crate::{
    CoreError, CoreResult,
    database_config::DatabaseConfigProduct,
    database_config_schema::DatabaseConfigVersion,
    postgres_auth_schema::{
        POSTGRESQL_HBA_ARTIFACT_KEY, PostgresAuthSchema, PostgresAuthSchemaTarget,
        PostgresHbaMethodLookup, PostgresHbaOptionLookup, postgres_auth_schema,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, fmt, net::IpAddr};
use zeroize::Zeroizing;

const MAX_JSON: usize = 400 * 1024;
const MAX_PUBLIC_ROWS: usize = 393216;
const PERMISSIONS: &str = include_str!("postgresql_access_permissions.sql");
const HBA: &str = include_str!("postgresql_access_hba.sql");
const IDENT: &str = include_str!("postgresql_access_ident.sql");
const ROLES: &str = include_str!("postgresql_access_roles.sql");
const MEMBERSHIPS: &str = include_str!("postgresql_access_memberships.sql");
const DATABASE: &str = include_str!("postgresql_access_database.sql");
use crate::postgresql_role_graph::{
    DatabaseContext, Membership, Role, RoleAccessMode, RoleGraph, RoleGraphSummary,
    RoleGraphUnavailable,
};
const PRIVATE_ROLES: &str = include_str!("postgresql_access_roles_private.sql");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AccessSection {
    Hba,
    Ident,
    Roles,
    Memberships,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AccessUnavailable {
    PermissionDenied,
    QueryFailed,
    InvalidOutput,
    LimitExceeded,
    Changed,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum AccessFinding {
    ServerIssue,
    Trust,
    PasswordTransport,
    Md5Rule,
    BroadSource,
    UnknownMethod,
    UnknownOption,
    LoginSuperuser,
    LoginBypassrls,
    LoginCreaterole,
    LoginReplication,
    Md5Verifier,
    PasswordExpired,
    UnrecognizedVerifier,
    MembershipAdmin,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum PasswordKind {
    None,
    Md5,
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    Unrecognized,
    Unavailable,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HbaRow {
    #[serde(deserialize_with = "required_option")]
    rule_number: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    file_name: Option<String>,
    #[serde(deserialize_with = "required_option")]
    line_number: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    connection_type: Option<String>,
    #[serde(deserialize_with = "required_option")]
    databases: Option<Vec<String>>,
    #[serde(deserialize_with = "required_option")]
    users: Option<Vec<String>>,
    #[serde(deserialize_with = "required_option")]
    address: Option<String>,
    #[serde(deserialize_with = "required_option")]
    netmask: Option<String>,
    #[serde(deserialize_with = "required_option")]
    method: Option<String>,
    option_names: Vec<String>,
    has_issue: bool,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentRow {
    #[serde(deserialize_with = "required_option")]
    map_number: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    file_name: Option<String>,
    #[serde(deserialize_with = "required_option")]
    line_number: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    map_name: Option<String>,
    #[serde(deserialize_with = "required_option")]
    system_user: Option<String>,
    #[serde(deserialize_with = "required_option")]
    database_user: Option<String>,
    has_issue: bool,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleRow {
    oid: u32,
    name: String,
    can_login: bool,
    superuser: bool,
    inherit: bool,
    create_role: bool,
    create_database: bool,
    replication: bool,
    bypass_rls: bool,
    connection_limit: i32,
    #[serde(deserialize_with = "required_option")]
    password_expires_at: Option<String>,
    password_expired: bool,
    password_kind: PasswordKind,
}

trait AccessRecord: DeserializeOwned + Serialize + PartialEq + Clone {
    const LIMIT: usize;
    fn valid(&self, passwords: bool) -> bool;
    fn findings(&self, schema: &PostgresAuthSchema) -> Vec<AccessFinding>;
    fn matches(&self, query: &str) -> bool;
    fn order(&self) -> Option<u32>;
}
fn text(s: &str, maximum: usize) -> bool {
    !s.is_empty() && s.len() <= maximum && !s.chars().any(char::is_control)
}
fn optional_text(s: &Option<String>, maximum: usize) -> bool {
    s.as_ref().is_none_or(|s| text(s, maximum))
}
fn line(n: Option<u32>) -> bool {
    n.is_none_or(|n| n > 0 && n <= i32::MAX as u32)
}
fn array(a: &Option<Vec<String>>) -> bool {
    a.as_ref()
        .is_none_or(|a| !a.is_empty() && a.len() <= 64 && a.iter().all(|s| text(s, 4096)))
}
fn contains(s: &str, q: &str) -> bool {
    s.to_lowercase().contains(q)
}
impl AccessRecord for HbaRow {
    const LIMIT: usize = 512;
    fn order(&self) -> Option<u32> {
        self.rule_number
    }
    fn valid(&self, _: bool) -> bool {
        line(self.rule_number)
            && line(self.line_number)
            && optional_text(&self.file_name, 2048)
            && optional_text(&self.connection_type, 32)
            && array(&self.databases)
            && array(&self.users)
            && optional_text(&self.address, 4096)
            && optional_text(&self.netmask, 64)
            && optional_text(&self.method, 64)
            && self.option_names.len() <= 64
            && self
                .option_names
                .iter()
                .all(|s| text(s, 128) && !s.contains('='))
            && (self.has_issue
                || self.rule_number.is_some()
                    && self.file_name.is_some()
                    && self.line_number.is_some()
                    && self.connection_type.is_some()
                    && self.databases.is_some()
                    && self.users.is_some()
                    && self.method.is_some())
    }
    fn findings(&self, schema: &PostgresAuthSchema) -> Vec<AccessFinding> {
        use AccessFinding::*;
        let mut findings = Vec::new();
        if self.has_issue {
            findings.push(ServerIssue);
        }
        if let Some(method) = self.method.as_deref() {
            if !matches!(
                schema.lookup_hba_method(method),
                Ok(PostgresHbaMethodLookup::Known(_))
            ) {
                findings.push(UnknownMethod);
            }
            match method {
                "trust" => findings.push(Trust),
                "md5" => findings.push(Md5Rule),
                "password"
                    if matches!(
                        self.connection_type.as_deref(),
                        Some("host" | "hostnossl" | "hostnogssenc")
                    ) =>
                {
                    findings.push(PasswordTransport)
                }
                _ => {}
            }
            // The view loses quote flags. Do not infer wildcard semantics from
            // literal "all", database/user selectors, or reconstructed tokens.
            if method != "reject"
                && self
                    .connection_type
                    .as_deref()
                    .is_some_and(|t| t != "local")
                && let (Some(Ok(ip)), Some(Ok(mask))) = (
                    self.address.as_ref().map(|s| s.parse::<IpAddr>()),
                    self.netmask.as_ref().map(|s| s.parse::<IpAddr>()),
                )
                && ip.is_ipv4() == mask.is_ipv4()
                && mask.is_unspecified()
            {
                findings.push(BroadSource);
            }
        }
        if self.option_names.iter().any(|s| {
            // hbafuncs.c in PG 16-18 emits LDAP's derived search scope here.
            // This diagnostic field is NOT an accepted raw pg_hba.conf option.
            let view_derived = self.method.as_deref() == Some("ldap") && s == "ldapscope";
            !view_derived
                && !matches!(
                    schema.lookup_hba_option(s),
                    Ok(PostgresHbaOptionLookup::Known(_))
                )
        }) {
            findings.push(UnknownOption);
        }
        findings
    }
    fn matches(&self, q: &str) -> bool {
        [
            &self.file_name,
            &self.connection_type,
            &self.address,
            &self.method,
        ]
        .into_iter()
        .flatten()
        .any(|s| contains(s, q))
            || [&self.databases, &self.users]
                .into_iter()
                .flatten()
                .flatten()
                .any(|s| contains(s, q))
    }
}
impl AccessRecord for IdentRow {
    const LIMIT: usize = 512;
    fn order(&self) -> Option<u32> {
        self.map_number
    }
    fn valid(&self, _: bool) -> bool {
        line(self.map_number)
            && line(self.line_number)
            && optional_text(&self.file_name, 2048)
            && [&self.map_name, &self.system_user, &self.database_user]
                .iter()
                .all(|s| optional_text(s, 4096))
            && (self.has_issue
                || self.map_number.is_some()
                    && self.file_name.is_some()
                    && self.line_number.is_some()
                    && self.map_name.is_some()
                    && self.system_user.is_some()
                    && self.database_user.is_some())
    }
    fn findings(&self, _: &PostgresAuthSchema) -> Vec<AccessFinding> {
        if self.has_issue {
            vec![AccessFinding::ServerIssue]
        } else {
            vec![]
        }
    }
    fn matches(&self, q: &str) -> bool {
        [
            &self.file_name,
            &self.map_name,
            &self.system_user,
            &self.database_user,
        ]
        .into_iter()
        .flatten()
        .any(|s| contains(s, q))
    }
}
impl AccessRecord for RoleRow {
    const LIMIT: usize = 1024;
    fn order(&self) -> Option<u32> {
        Some(self.oid)
    }
    fn valid(&self, passwords: bool) -> bool {
        self.oid > 0
            && text(&self.name, 256)
            && self.connection_limit >= -1
            && optional_text(&self.password_expires_at, 128)
            && (!self.password_expired || self.password_expires_at.is_some())
            && (self.password_kind != PasswordKind::Unavailable) == passwords
    }
    fn findings(&self, _: &PostgresAuthSchema) -> Vec<AccessFinding> {
        use AccessFinding::*;
        let mut findings = Vec::new();
        for (applies, code) in [
            (self.can_login && self.superuser, LoginSuperuser),
            (self.can_login && self.bypass_rls, LoginBypassrls),
            (self.can_login && self.create_role, LoginCreaterole),
            (self.can_login && self.replication, LoginReplication),
            (self.password_kind == PasswordKind::Md5, Md5Verifier),
            (self.can_login && self.password_expired, PasswordExpired),
            (
                self.password_kind == PasswordKind::Unrecognized,
                UnrecognizedVerifier,
            ),
        ] {
            if applies {
                findings.push(code);
            }
        }
        findings
    }
    fn matches(&self, q: &str) -> bool {
        contains(&self.name, q)
    }
}

impl AccessRecord for Membership {
    const LIMIT: usize = 2048;
    fn order(&self) -> Option<u32> {
        Some(self.oid)
    }
    fn valid(&self, _: bool) -> bool {
        [self.oid, self.role_oid, self.member_oid, self.grantor_oid]
            .iter()
            .all(|n| *n > 0)
            && self.role_oid != self.member_oid
    }
    fn findings(&self, _: &PostgresAuthSchema) -> Vec<AccessFinding> {
        if self.admin_option {
            vec![AccessFinding::MembershipAdmin]
        } else {
            vec![]
        }
    }
    fn matches(&self, q: &str) -> bool {
        [self.oid, self.role_oid, self.member_oid, self.grantor_oid]
            .iter()
            .any(|n| n.to_string().contains(q))
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Permissions {
    hba: bool,
    ident: bool,
    roles: bool,
    passwords: bool,
    memberships: bool,
    database: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    overflow: bool,
    rows: Vec<T>,
    #[serde(deserialize_with = "read_fingerprint")]
    fingerprint: Option<Zeroizing<String>>,
}
struct Reading<T> {
    rows: Vec<T>,
    fingerprint: Option<Zeroizing<String>>,
    reason: Option<AccessUnavailable>,
}
impl<T> Reading<T> {
    fn unavailable(reason: AccessUnavailable) -> Self {
        Self {
            rows: vec![],
            fingerprint: None,
            reason: Some(reason),
        }
    }
}
fn read_fingerprint<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(Zeroizing::new))
}
fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
pub(crate) fn decode<T: DeserializeOwned>(
    encoded: Zeroizing<Vec<u8>>,
) -> Result<T, AccessUnavailable> {
    let encoded = encoded
        .strip_suffix(b"\n")
        .ok_or(AccessUnavailable::InvalidOutput)?;
    if encoded.len() > MAX_JSON * 2 || encoded.len() % 2 != 0 {
        return Err(AccessUnavailable::InvalidOutput);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(encoded.len() / 2));
    for pair in encoded.chunks_exact(2) {
        bytes.push(
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or(AccessUnavailable::InvalidOutput)?,
        );
    }
    serde_json::from_slice(&bytes).map_err(|_| AccessUnavailable::InvalidOutput)
}
fn parse<T: AccessRecord>(
    encoded: Zeroizing<Vec<u8>>,
    passwords: bool,
) -> Result<Reading<T>, AccessUnavailable> {
    let wire: Envelope<T> = decode(encoded)?;
    if wire.overflow {
        return if wire.rows.is_empty() && wire.fingerprint.is_none() {
            Err(AccessUnavailable::LimitExceeded)
        } else {
            Err(AccessUnavailable::InvalidOutput)
        };
    }
    if wire.rows.len() > T::LIMIT
        || serde_json::to_vec(&wire.rows)
            .map_err(|_| AccessUnavailable::InvalidOutput)?
            .len()
            > MAX_PUBLIC_ROWS
        || !wire.rows.iter().all(|r| r.valid(passwords))
        || !wire
            .rows
            .windows(2)
            .all(|pair| match (pair[0].order(), pair[1].order()) {
                (Some(a), Some(b)) => a < b,
                (None, Some(_)) => false,
                _ => true,
            })
        || wire.fingerprint.as_ref().is_none_or(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return Err(AccessUnavailable::InvalidOutput);
    }
    Ok(Reading {
        rows: wire.rows,
        fingerprint: wire.fingerprint,
        reason: None,
    })
}
pub(crate) async fn scalar(
    client: &tokio_postgres::Client,
    query: &'static str,
    bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, AccessUnavailable> {
    crate::postgresql_native::collect_tsv(client, query, 1, 1, bytes)
        .await
        .map_err(|_| AccessUnavailable::QueryFailed)
}
async fn reading<T: AccessRecord>(
    client: &tokio_postgres::Client,
    query: &'static str,
    allowed: bool,
    passwords: bool,
) -> Reading<T> {
    if !allowed {
        return Reading::unavailable(AccessUnavailable::PermissionDenied);
    }
    match scalar(client, query, MAX_JSON * 2 + 1)
        .await
        .and_then(|s| parse(s, passwords))
    {
        Ok(reading) => reading,
        Err(reason) => Reading::unavailable(reason),
    }
}

#[derive(Clone, Serialize)]
struct Row<T> {
    #[serde(flatten)]
    fields: T,
    findings: Vec<AccessFinding>,
}
#[derive(Clone)]
struct Section<T> {
    rows: Vec<Row<T>>,
    reason: Option<AccessUnavailable>,
}
impl<T: AccessRecord> Section<T> {
    fn finish(before: Reading<T>, after: Reading<T>, schema: &PostgresAuthSchema) -> Self {
        let reason = before.reason.or(after.reason).or_else(|| {
            (before.fingerprint != after.fingerprint || before.rows != after.rows)
                .then_some(AccessUnavailable::Changed)
        });
        Self {
            rows: if reason.is_none() {
                after
                    .rows
                    .into_iter()
                    .map(|fields| Row {
                        findings: fields.findings(schema),
                        fields,
                    })
                    .collect()
            } else {
                vec![]
            },
            reason,
        }
    }
    fn unavailable(reason: AccessUnavailable) -> Self {
        Self {
            rows: vec![],
            reason: Some(reason),
        }
    }
    fn summary(&self) -> AccessSectionSummary {
        let mut findings = BTreeMap::new();
        for row in &self.rows {
            for code in &row.findings {
                *findings.entry(*code).or_insert(0) += 1;
            }
        }
        AccessSectionSummary {
            state: if self.reason.is_none() {
                "available"
            } else {
                "unavailable"
            },
            reason: self.reason,
            total: self.reason.is_none().then_some(self.rows.len()),
            flagged: self
                .reason
                .is_none()
                .then(|| self.rows.iter().filter(|r| !r.findings.is_empty()).count()),
            findings: findings
                .into_iter()
                .map(|(code, count)| FindingCount { code, count })
                .collect(),
        }
    }
    fn page(&self, query: &str, offset: usize) -> CoreResult<serde_json::Value> {
        if self.reason.is_some() {
            return Err(invalid());
        }
        let q = query.to_lowercase();
        let matching: Vec<_> = self
            .rows
            .iter()
            .filter(|r| q.is_empty() || r.fields.matches(&q))
            .collect();
        Ok(
            serde_json::json!({"query":query,"offset":offset,"matched":matching.len(),"total":self.rows.len(),"rows":matching.into_iter().skip(offset).take(50).collect::<Vec<_>>()}),
        )
    }
}
#[derive(Debug, Serialize)]
pub struct FindingCount {
    code: AccessFinding,
    count: usize,
}
#[derive(Debug, Serialize)]
pub struct AccessSectionSummary {
    state: &'static str,
    reason: Option<AccessUnavailable>,
    total: Option<usize>,
    flagged: Option<usize>,
    findings: Vec<FindingCount>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresqlAccessSummary {
    hba: AccessSectionSummary,
    ident: AccessSectionSummary,
    roles: AccessSectionSummary,
    memberships: AccessSectionSummary,
    role_graph: RoleGraphSummary,
    objects: serde_json::Value,
    password_classification: bool,
}
#[derive(Clone)]
pub struct PostgresqlAccessReview {
    hba: Section<HbaRow>,
    ident: Section<IdentRow>,
    roles: Section<RoleRow>,
    memberships: Section<Membership>,
    graph: Result<RoleGraph, RoleGraphUnavailable>,
    objects: crate::postgresql_objects::PostgresqlObjectReview,
    major: u16,
    passwords: bool,
}
impl fmt::Debug for PostgresqlAccessReview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresqlAccessReview")
            .field("summary", &self.summary())
            .finish()
    }
}
impl PostgresqlAccessReview {
    fn unavailable(reason: AccessUnavailable) -> Self {
        Self {
            hba: Section::unavailable(reason),
            ident: Section::unavailable(reason),
            roles: Section::unavailable(reason),
            memberships: Section::unavailable(reason),
            graph: Err(RoleGraphUnavailable::RolesUnavailable),
            objects: crate::postgresql_objects::PostgresqlObjectReview::unavailable(reason),
            major: 0,
            passwords: false,
        }
    }
    pub fn summary(&self) -> PostgresqlAccessSummary {
        PostgresqlAccessSummary {
            hba: self.hba.summary(),
            ident: self.ident.summary(),
            roles: self.roles.summary(),
            memberships: self.memberships.summary(),
            role_graph: self
                .graph
                .as_ref()
                .map_or_else(|r| RoleGraphSummary::unavailable(*r), RoleGraph::summary),
            objects: self.objects.summary(),
            password_classification: self.passwords && self.roles.reason.is_none(),
        }
    }
    pub fn page(
        &self,
        section: AccessSection,
        query: &str,
        offset: usize,
    ) -> CoreResult<serde_json::Value> {
        if query.len() > 128
            || query.chars().any(char::is_control)
            || offset
                > if section == AccessSection::Memberships {
                    2048
                } else {
                    1024
                }
        {
            return Err(invalid());
        }
        let mut result = match section {
            AccessSection::Hba => self.hba.page(query, offset),
            AccessSection::Ident => self.ident.page(query, offset),
            AccessSection::Roles => self.roles.page(query, offset),
            AccessSection::Memberships => self.membership_page(query, offset),
        }?;
        result["section"] = serde_json::to_value(section).map_err(|_| invalid())?;
        Ok(result)
    }
    pub fn object_page(
        &self,
        section: crate::postgresql_objects::ObjectSection,
        query: &str,
        filter: crate::postgresql_objects::ObjectFilter,
        offset: usize,
    ) -> CoreResult<serde_json::Value> {
        let names = self
            .roles
            .rows
            .iter()
            .map(|r| (r.fields.oid, r.fields.name.as_str()))
            .collect();
        self.objects.page(section, query, filter, offset, &names)
    }
    pub fn object_detail(
        &self,
        section: crate::postgresql_objects::ObjectSection,
        oid: u32,
        sub_id: u16,
        role_oid: Option<u32>,
    ) -> CoreResult<serde_json::Value> {
        let names = self
            .roles
            .rows
            .iter()
            .map(|r| (r.fields.oid, r.fields.name.as_str()))
            .collect();
        self.objects.detail(
            section,
            oid,
            sub_id,
            role_oid,
            &names,
            self.graph.as_ref().ok(),
            self.major,
        )
    }
    pub fn role_page(
        &self,
        oid: u32,
        mode: RoleAccessMode,
        query: &str,
        offset: usize,
    ) -> CoreResult<serde_json::Value> {
        self.graph
            .as_ref()
            .map_err(|_| invalid())?
            .page(oid, mode, query, offset)
    }
    fn membership_page(&self, query: &str, offset: usize) -> CoreResult<serde_json::Value> {
        if self.memberships.reason.is_some() {
            return Err(invalid());
        }
        let names: BTreeMap<_, _> = self
            .roles
            .rows
            .iter()
            .map(|r| (r.fields.oid, r.fields.name.as_str()))
            .collect();
        let q = query.to_lowercase();
        let matching: Vec<_> = self
            .memberships
            .rows
            .iter()
            .filter(|r| {
                r.fields.matches(&q)
                    || [r.fields.member_oid, r.fields.role_oid, r.fields.grantor_oid]
                        .iter()
                        .any(|oid| names.get(oid).is_some_and(|name| contains(name, &q)))
            })
            .collect();
        let rows: Vec<_> = matching
            .iter()
            .skip(offset)
            .take(50)
            .map(|r| {
                let mut row = serde_json::to_value(r).expect("bounded membership");
                for (key, oid) in [
                    ("memberName", r.fields.member_oid),
                    ("roleName", r.fields.role_oid),
                    ("grantorName", r.fields.grantor_oid),
                ] {
                    row[key] = serde_json::json!(names.get(&oid));
                }
                row
            })
            .collect();
        Ok(
            serde_json::json!({"query":query,"offset":offset,"matched":matching.len(),"total":self.memberships.rows.len(),"rows":rows}),
        )
    }
    pub fn case_summary(&self) -> String {
        let mut out = String::from(
            "访问诊断：HBA/ident 为当前文件视图，未证明加载生效；角色含直接属性与静态成员关系。\n",
        );
        for (name, summary) in [
            ("HBA", self.hba.summary()),
            ("ident", self.ident.summary()),
            ("角色", self.roles.summary()),
            ("成员授权", self.memberships.summary()),
        ] {
            if let Some(reason) = summary.reason {
                let reason = match reason {
                    AccessUnavailable::PermissionDenied => "权限不足",
                    AccessUnavailable::QueryFailed => "查询失败",
                    AccessUnavailable::InvalidOutput => "输出无法核对",
                    AccessUnavailable::LimitExceeded => "超过读取上限",
                    AccessUnavailable::Changed => "读取期间变化",
                };
                out.push_str(&format!("{name}：未取得（{reason}）\n"));
            } else {
                out.push_str(&format!(
                    "{name}：{} 项；需复核 {} 项\n",
                    summary.total.unwrap_or(0),
                    summary.flagged.unwrap_or(0)
                ));
                for finding in summary.findings {
                    // Closed codes and counts only, never rule text or identities.
                    out.push_str(&format!(
                        "  {}：{}\n",
                        serde_json::to_value(finding.code)
                            .expect("finite code")
                            .as_str()
                            .expect("string enum"),
                        finding.count
                    ));
                }
            }
        }
        out.push_str(&self.graph.as_ref().map_or_else(
            |reason| {
                format!(
                    "角色路径：未能分析（{}）。\n",
                    match reason {
                        RoleGraphUnavailable::RolesUnavailable => "角色数据缺失",
                        RoleGraphUnavailable::MembershipsUnavailable => "成员关系缺失",
                        RoleGraphUnavailable::DatabaseUnavailable => "当前数据库归属无法核对",
                        RoleGraphUnavailable::InvalidGraph => "关系无法核对",
                    }
                )
            },
            RoleGraph::case_summary,
        ));
        out.push_str(&self.objects.case_summary());
        out.push_str(if self.summary().password_classification {
            "口令存储标识：已分类，未保留校验值。\n"
        } else {
            "口令存储标识：未取得。\n"
        });
        out
    }
}
fn invalid() -> CoreError {
    CoreError::validation(
        "PostgreSQL access diagnostics",
        "访问诊断结果无法核实，请重新读取并检查该项状态。",
    )
}

pub(crate) async fn read(
    client: &tokio_postgres::Client,
    version: DatabaseConfigVersion,
    database_identity: (u32, &str),
) -> PostgresqlAccessReview {
    let Ok(schema) = postgres_auth_schema(PostgresAuthSchemaTarget {
        product: DatabaseConfigProduct::PostgreSql,
        version,
        artifact_key: POSTGRESQL_HBA_ARTIFACT_KEY,
    }) else {
        return PostgresqlAccessReview::unavailable(AccessUnavailable::InvalidOutput);
    };
    let before: Permissions = match scalar(client, PERMISSIONS, 1024).await.and_then(decode) {
        Ok(p) => p,
        Err(reason) => return PostgresqlAccessReview::unavailable(reason),
    };
    let role_query = if before.passwords {
        PRIVATE_ROLES
    } else {
        ROLES
    };
    let database_before = database_context(client, before.database, database_identity).await;
    let memberships_before = reading(client, MEMBERSHIPS, before.memberships, false).await;
    let hba_before = reading(client, HBA, before.hba, false).await;
    let ident_before = reading(client, IDENT, before.ident, false).await;
    let roles_before = reading(client, role_query, before.roles, before.passwords).await;
    let objects_before = crate::postgresql_objects::read(client, version.major()).await;
    let objects_after = crate::postgresql_objects::read(client, version.major()).await;
    let hba_after = reading(client, HBA, before.hba, false).await;
    let ident_after = reading(client, IDENT, before.ident, false).await;
    let roles_after = reading(client, role_query, before.roles, before.passwords).await;
    let memberships_after = reading(client, MEMBERSHIPS, before.memberships, false).await;
    let database_after = database_context(client, before.database, database_identity).await;
    let after: Permissions = match scalar(client, PERMISSIONS, 1024).await.and_then(decode) {
        Ok(p) => p,
        Err(reason) => return PostgresqlAccessReview::unavailable(reason),
    };
    if before != after {
        return PostgresqlAccessReview::unavailable(AccessUnavailable::Changed);
    }
    let roles: Section<RoleRow> = Section::finish(roles_before, roles_after, schema);
    let memberships: Section<Membership> =
        Section::finish(memberships_before, memberships_after, schema);
    let graph = if roles.reason.is_some() {
        Err(RoleGraphUnavailable::RolesUnavailable)
    } else if memberships.reason.is_some() {
        Err(RoleGraphUnavailable::MembershipsUnavailable)
    } else if database_before.is_err() || database_before != database_after {
        Err(RoleGraphUnavailable::DatabaseUnavailable)
    } else {
        RoleGraph::build(
            roles
                .rows
                .iter()
                .map(|r| Role {
                    oid: r.fields.oid,
                    name: r.fields.name.clone(),
                    can_login: r.fields.can_login,
                    superuser: r.fields.superuser,
                    create_role: r.fields.create_role,
                    create_database: r.fields.create_database,
                    replication: r.fields.replication,
                    bypass_rls: r.fields.bypass_rls,
                })
                .collect(),
            &memberships
                .rows
                .iter()
                .map(|r| r.fields.clone())
                .collect::<Vec<_>>(),
            database_after.expect("checked context"),
        )
        .ok_or(RoleGraphUnavailable::InvalidGraph)
    };
    PostgresqlAccessReview {
        hba: Section::finish(hba_before, hba_after, schema),
        ident: Section::finish(ident_before, ident_after, schema),
        roles,
        memberships,
        graph,
        objects: crate::postgresql_objects::PostgresqlObjectReview::finish(
            objects_before,
            objects_after,
        ),
        major: version.major(),
        passwords: before.passwords,
    }
}

async fn database_context(
    client: &tokio_postgres::Client,
    allowed: bool,
    identity: (u32, &str),
) -> Result<DatabaseContext, AccessUnavailable> {
    if !allowed {
        return Err(AccessUnavailable::PermissionDenied);
    }
    let context: DatabaseContext = decode(scalar(client, DATABASE, 8192).await?)?;
    if !context.valid(identity) {
        return Err(AccessUnavailable::InvalidOutput);
    }
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn encode(value: Value) -> Zeroizing<Vec<u8>> {
        let mut out: String = serde_json::to_vec(&value)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        out.push('\n');
        Zeroizing::new(out.into_bytes())
    }
    fn envelope(rows: Value) -> Value {
        json!({"overflow":false,"rows":rows,"fingerprint":"a".repeat(64)})
    }
    fn hba() -> Value {
        json!({"ruleNumber":1,"fileName":"/srv/pg/hba.conf","lineNumber":2,"connectionType":"host",
            "databases":["all"],"users":["all"],"address":"0.0.0.0","netmask":"0.0.0.0","method":"trust","optionNames":[],"hasIssue":false})
    }
    fn role() -> Value {
        json!({"oid":1,"name":"review","canLogin":true,"superuser":false,"inherit":true,"createRole":false,
            "createDatabase":false,"replication":false,"bypassRls":false,"connectionLimit":-1,
            "passwordExpiresAt":null,"passwordExpired":false,"passwordKind":"unavailable"})
    }
    fn schema() -> PostgresAuthSchema {
        *postgres_auth_schema(PostgresAuthSchemaTarget {
            product: DatabaseConfigProduct::PostgreSql,
            version: DatabaseConfigVersion::new(16, 15, 0),
            artifact_key: POSTGRESQL_HBA_ARTIFACT_KEY,
        })
        .unwrap()
    }
    #[test]
    fn private_changes_invalidate_publicly_identical_rows_and_never_serialize() {
        let first = envelope(json!([hba()]));
        let mut second = first.clone();
        second["fingerprint"] = json!("b".repeat(64));
        let changed = Section::<HbaRow>::finish(
            parse(encode(first.clone()), false).unwrap(),
            parse(encode(second), false).unwrap(),
            &schema(),
        );
        assert_eq!(changed.reason, Some(AccessUnavailable::Changed));
        assert!(changed.page("", 0).is_err());
        let hba = Section::finish(
            parse(encode(first.clone()), false).unwrap(),
            parse(encode(first), false).unwrap(),
            &schema(),
        );
        let review = PostgresqlAccessReview {
            objects: crate::postgresql_objects::PostgresqlObjectReview::unavailable(
                AccessUnavailable::PermissionDenied,
            ),
            major: 16,
            memberships: Section::unavailable(AccessUnavailable::PermissionDenied),
            graph: Err(RoleGraphUnavailable::RolesUnavailable),
            hba,
            ident: Section::unavailable(AccessUnavailable::PermissionDenied),
            roles: Section::unavailable(AccessUnavailable::QueryFailed),
            passwords: false,
        };
        let page = review.page(AccessSection::Hba, "hba", 0).unwrap();
        assert_eq!(page["matched"], 1);
        let summary = serde_json::to_string(&review.summary()).unwrap();
        assert_eq!(review.summary().hba.flagged, Some(1));
        for out in [
            page.to_string(),
            summary,
            format!("{review:?}"),
            review.case_summary(),
        ] {
            assert!(!out.contains("fingerprint"));
            assert!(!out.contains(&"a".repeat(64)));
        }
        assert!(!review.case_summary().contains("/srv/pg"));
        assert!(review.page(AccessSection::Hba, "\0", 0).is_err());
        assert!(review.page(AccessSection::Hba, "", 1025).is_err());
    }
    #[test]
    fn diagnostics_do_not_infer_loaded_policy_from_flattened_selectors() {
        use AccessFinding::*;
        let mut row = hba();
        let found = serde_json::from_value::<HbaRow>(row.clone())
            .unwrap()
            .findings(&schema());
        assert_eq!(found, [Trust, BroadSource]);
        row["address"] = json!("all");
        row["netmask"] = Value::Null;
        row["method"] = json!("md5");
        assert_eq!(
            serde_json::from_value::<HbaRow>(row.clone())
                .unwrap()
                .findings(&schema()),
            [Md5Rule]
        );
        row["method"] = json!("password");
        assert_eq!(
            serde_json::from_value::<HbaRow>(row.clone())
                .unwrap()
                .findings(&schema()),
            [PasswordTransport]
        );
        for transport in ["hostssl", "hostgssenc", "local"] {
            row["connectionType"] = json!(transport);
            assert!(
                serde_json::from_value::<HbaRow>(row.clone())
                    .unwrap()
                    .findings(&schema())
                    .is_empty()
            );
        }
        row["method"] = json!("ldap");
        row["optionNames"] = json!(["ldapscope"]);
        assert!(
            serde_json::from_value::<HbaRow>(row.clone())
                .unwrap()
                .findings(&schema())
                .is_empty()
        );
        assert_eq!(
            schema().lookup_hba_option("ldapscope"),
            Ok(PostgresHbaOptionLookup::TargetDependent)
        );
        row["method"] = json!("md5");
        assert!(
            serde_json::from_value::<HbaRow>(row.clone())
                .unwrap()
                .findings(&schema())
                .contains(&UnknownOption)
        );
        row["method"] = json!("oauth");
        row["hasIssue"] = json!(true);
        row["optionNames"] = json!(["future_option"]);
        assert_eq!(
            serde_json::from_value::<HbaRow>(row)
                .unwrap()
                .findings(&schema()),
            [ServerIssue, UnknownMethod, UnknownOption]
        );
    }
    #[test]
    fn malformed_secret_fields_limits_and_duplicate_records_are_refused() {
        let mut row = hba();
        row["options"] = json!(["ldapbindpasswd=PrivateCanary"]);
        assert!(parse::<HbaRow>(encode(envelope(json!([row]))), false).is_err());
        for (key, value) in [
            ("optionNames", json!(["ldapbindpasswd=PrivateCanary"])),
            ("method", json!("x\0")),
            ("ruleNumber", json!(0)),
            ("databases", json!([])),
        ] {
            let mut row = hba();
            row[key] = value;
            assert!(parse::<HbaRow>(encode(envelope(json!([row]))), false).is_err());
        }
        for key in hba().as_object().unwrap().keys() {
            let mut row = hba();
            row.as_object_mut().unwrap().remove(key);
            assert!(parse::<HbaRow>(encode(envelope(json!([row]))), false).is_err());
        }
        assert!(parse::<HbaRow>(encode(envelope(json!([hba(), hba()]))), false).is_err());
        assert!(parse::<RoleRow>(encode(envelope(json!([role(), role()]))), false).is_err());
        assert_eq!(
            parse::<HbaRow>(
                encode(json!({"overflow":true,"rows":[],"fingerprint":null})),
                false
            )
            .err(),
            Some(AccessUnavailable::LimitExceeded)
        );
        assert_eq!(
            parse::<HbaRow>(
                encode(json!({"overflow":true,"rows":[hba()],"fingerprint":null})),
                false
            )
            .err(),
            Some(AccessUnavailable::InvalidOutput)
        );
        let mut rows = Vec::new();
        for n in 1..=513 {
            let mut row = hba();
            row["ruleNumber"] = json!(n);
            rows.push(row);
        }
        assert!(parse::<HbaRow>(encode(envelope(json!(rows))), false).is_err());
    }
    #[test]
    fn role_classification_requires_observed_permissions_and_expiry_is_scoped() {
        let mut row = role();
        assert!(parse::<RoleRow>(encode(envelope(json!([row.clone()]))), false).is_ok());
        assert!(parse::<RoleRow>(encode(envelope(json!([row.clone()]))), true).is_err());
        row["passwordKind"] = json!("none");
        assert!(
            serde_json::from_value::<RoleRow>(row.clone())
                .unwrap()
                .findings(&schema())
                .is_empty()
        );
        assert!(parse::<RoleRow>(encode(envelope(json!([row.clone()]))), false).is_err());
        row["passwordKind"] = json!("scram-sha-256");
        let scram = parse::<RoleRow>(encode(envelope(json!([row.clone()]))), true).unwrap();
        assert_eq!(
            serde_json::to_value(&scram.rows[0]).unwrap()["passwordKind"],
            "scram-sha-256"
        );
        row["superuser"] = json!(true);
        row["passwordKind"] = json!("md5");
        row["passwordExpiresAt"] = json!("2000-01-01 00:00:00+00");
        row["passwordExpired"] = json!(true);
        assert_eq!(
            serde_json::from_value::<RoleRow>(row.clone())
                .unwrap()
                .findings(&schema()),
            [
                AccessFinding::LoginSuperuser,
                AccessFinding::Md5Verifier,
                AccessFinding::PasswordExpired
            ]
        );
        row["canLogin"] = json!(false);
        assert_eq!(
            serde_json::from_value::<RoleRow>(row.clone())
                .unwrap()
                .findings(&schema()),
            [AccessFinding::Md5Verifier]
        );
        row["passwordExpiresAt"] = Value::Null;
        assert!(parse::<RoleRow>(encode(envelope(json!([row]))), true).is_err());
    }
    #[test]
    fn membership_reads_require_every_flag_and_detect_private_changes() {
        let membership = json!({"oid":10,"roleOid":2,"memberOid":1,"grantorOid":3,"adminOption":true,"inheritOption":false,"setOption":true});
        let first = envelope(json!([membership.clone()]));
        assert!(parse::<Membership>(encode(first.clone()), false).is_ok());
        for key in membership.as_object().unwrap().keys() {
            let mut partial = membership.clone();
            partial.as_object_mut().unwrap().remove(key);
            assert!(parse::<Membership>(encode(envelope(json!([partial]))), false).is_err());
        }
        let mut secret = membership.clone();
        secret["password"] = json!("must-not-export");
        assert!(parse::<Membership>(encode(envelope(json!([secret]))), false).is_err());
        let mut changed = first.clone();
        changed["fingerprint"] = json!("b".repeat(64));
        let section = Section::<Membership>::finish(
            parse(encode(first), false).unwrap(),
            parse(encode(changed), false).unwrap(),
            &schema(),
        );
        assert_eq!(section.reason, Some(AccessUnavailable::Changed));
        assert!(section.page("", 0).is_err());
        let database = DatabaseContext {
            oid: 5,
            name: "postgres".into(),
            owner_oid: 10,
        };
        assert!(database.valid((5, "postgres")));
        assert!(!database.valid((6, "postgres")));
        assert!(!database.valid((5, "other")));
    }
}
