//! Versioned static semantics for native PostgreSQL authentication files.
//!
//! This module consumes already-tokenized records. It deliberately does not
//! lex lines, expand `include` directives, read target files, resolve names,
//! or claim that a required build/runtime capability exists. A statically
//! valid result therefore remains narrower than PostgreSQL's own target-side
//! validation through `pg_hba_file_rules` or `pg_ident_file_mappings`.

use std::{fmt, net::IpAddr};

use url::Url;
use zeroize::Zeroizing;

use crate::database_config::{DatabaseConfigProduct, artifact_by_key};
use crate::database_config_schema::DatabaseConfigVersion;

pub const POSTGRESQL_HBA_ARTIFACT_KEY: &str = "postgresql-hba";
pub const POSTGRESQL_IDENT_ARTIFACT_KEY: &str = "postgresql-ident";
pub const MAX_POSTGRES_AUTH_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_POSTGRES_AUTH_METHOD_BYTES: usize = 64;
pub const MAX_POSTGRES_AUTH_OPTION_NAME_BYTES: usize = 128;
pub const MAX_POSTGRES_AUTH_OPTION_VALUE_BYTES: usize = 16 * 1024;
pub const MAX_POSTGRES_AUTH_OPTIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PostgresAuthMajorVersion {
    V16,
    V17,
    V18,
}

impl PostgresAuthMajorVersion {
    pub const fn major(self) -> u16 {
        match self {
            Self::V16 => 16,
            Self::V17 => 17,
            Self::V18 => 18,
        }
    }

    const fn from_database_version(version: DatabaseConfigVersion) -> Option<Self> {
        match version.major() {
            16 => Some(Self::V16),
            17 => Some(Self::V17),
            18 => Some(Self::V18),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresAuthVersionRange {
    pub minimum: PostgresAuthMajorVersion,
    pub maximum: PostgresAuthMajorVersion,
}

impl PostgresAuthVersionRange {
    pub const fn contains(self, version: PostgresAuthMajorVersion) -> bool {
        version.major() >= self.minimum.major() && version.major() <= self.maximum.major()
    }
}

const PG16_TO_PG18: PostgresAuthVersionRange = PostgresAuthVersionRange {
    minimum: PostgresAuthMajorVersion::V16,
    maximum: PostgresAuthMajorVersion::V18,
};
const PG18_ONLY: PostgresAuthVersionRange = PostgresAuthVersionRange {
    minimum: PostgresAuthMajorVersion::V18,
    maximum: PostgresAuthMajorVersion::V18,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresAuthArtifact {
    Hba,
    Ident,
}

impl PostgresAuthArtifact {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Hba => POSTGRESQL_HBA_ARTIFACT_KEY,
            Self::Ident => POSTGRESQL_IDENT_ARTIFACT_KEY,
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        match key {
            POSTGRESQL_HBA_ARTIFACT_KEY => Some(Self::Hba),
            POSTGRESQL_IDENT_ARTIFACT_KEY => Some(Self::Ident),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresAuthSchemaTarget<'a> {
    pub product: DatabaseConfigProduct,
    pub version: DatabaseConfigVersion,
    pub artifact_key: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PostgresAuthSchemaLookupError {
    #[error("only the native PostgreSQL product has a reviewed authentication schema")]
    NativePostgreSqlRequired,
    #[error("the authentication artifact key is not registered")]
    ArtifactUnknown,
    #[error("the exact artifact must be postgresql-hba or postgresql-ident")]
    ExactArtifactRequired,
    #[error("the artifact is not owned by native PostgreSQL")]
    ArtifactProductMismatch,
    #[error("only typed PostgreSQL 16, 17, and 18 versions are reviewed")]
    UnsupportedVersion,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresAuthTargetCapability {
    Ssl,
    GssApi,
    Sspi,
    Pam,
    BsdAuth,
    Ldap,
    OpenLdapUrl,
    OAuth,
    IdentityMap,
    TargetNameResolution,
}

impl PostgresAuthTargetCapability {
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ssl => "postgresql.ssl",
            Self::GssApi => "postgresql.gssapi",
            Self::Sspi => "postgresql.sspi",
            Self::Pam => "postgresql.pam",
            Self::BsdAuth => "postgresql.bsd-auth",
            Self::Ldap => "postgresql.ldap",
            Self::OpenLdapUrl => "postgresql.openldap-url",
            Self::OAuth => "postgresql.oauth",
            Self::IdentityMap => "postgresql.ident-map",
            Self::TargetNameResolution => "postgresql.target-name-resolution",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresHbaAuthMethod {
    Trust,
    Reject,
    ScramSha256,
    Md5,
    Password,
    Gss,
    Sspi,
    Ident,
    Peer,
    Ldap,
    Radius,
    Cert,
    Pam,
    Bsd,
    OAuth,
}

impl PostgresHbaAuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trust => "trust",
            Self::Reject => "reject",
            Self::ScramSha256 => "scram-sha-256",
            Self::Md5 => "md5",
            Self::Password => "password",
            Self::Gss => "gss",
            Self::Sspi => "sspi",
            Self::Ident => "ident",
            Self::Peer => "peer",
            Self::Ldap => "ldap",
            Self::Radius => "radius",
            Self::Cert => "cert",
            Self::Pam => "pam",
            Self::Bsd => "bsd",
            Self::OAuth => "oauth",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "trust" => Some(Self::Trust),
            "reject" => Some(Self::Reject),
            "scram-sha-256" => Some(Self::ScramSha256),
            "md5" => Some(Self::Md5),
            "password" => Some(Self::Password),
            "gss" => Some(Self::Gss),
            "sspi" => Some(Self::Sspi),
            "ident" => Some(Self::Ident),
            "peer" => Some(Self::Peer),
            "ldap" => Some(Self::Ldap),
            "radius" => Some(Self::Radius),
            "cert" => Some(Self::Cert),
            "pam" => Some(Self::Pam),
            "bsd" => Some(Self::Bsd),
            "oauth" => Some(Self::OAuth),
            _ => None,
        }
    }
}

pub const POSTGRES_HBA_METHODS_16_17: &[PostgresHbaAuthMethod] = &[
    PostgresHbaAuthMethod::Trust,
    PostgresHbaAuthMethod::Reject,
    PostgresHbaAuthMethod::ScramSha256,
    PostgresHbaAuthMethod::Md5,
    PostgresHbaAuthMethod::Password,
    PostgresHbaAuthMethod::Gss,
    PostgresHbaAuthMethod::Sspi,
    PostgresHbaAuthMethod::Ident,
    PostgresHbaAuthMethod::Peer,
    PostgresHbaAuthMethod::Ldap,
    PostgresHbaAuthMethod::Radius,
    PostgresHbaAuthMethod::Cert,
    PostgresHbaAuthMethod::Pam,
    PostgresHbaAuthMethod::Bsd,
];

pub const POSTGRES_HBA_METHODS_18: &[PostgresHbaAuthMethod] = &[
    PostgresHbaAuthMethod::Trust,
    PostgresHbaAuthMethod::Reject,
    PostgresHbaAuthMethod::ScramSha256,
    PostgresHbaAuthMethod::Md5,
    PostgresHbaAuthMethod::Password,
    PostgresHbaAuthMethod::Gss,
    PostgresHbaAuthMethod::Sspi,
    PostgresHbaAuthMethod::Ident,
    PostgresHbaAuthMethod::Peer,
    PostgresHbaAuthMethod::Ldap,
    PostgresHbaAuthMethod::Radius,
    PostgresHbaAuthMethod::Cert,
    PostgresHbaAuthMethod::Pam,
    PostgresHbaAuthMethod::Bsd,
    PostgresHbaAuthMethod::OAuth,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresHbaMethodMetadata {
    pub method: PostgresHbaAuthMethod,
    pub versions: PostgresAuthVersionRange,
    pub required_capability: Option<PostgresAuthTargetCapability>,
}

const POSTGRES_HBA_METHOD_METADATA: &[PostgresHbaMethodMetadata] = &[
    method(PostgresHbaAuthMethod::Trust, PG16_TO_PG18, None),
    method(PostgresHbaAuthMethod::Reject, PG16_TO_PG18, None),
    method(PostgresHbaAuthMethod::ScramSha256, PG16_TO_PG18, None),
    method(PostgresHbaAuthMethod::Md5, PG16_TO_PG18, None),
    method(PostgresHbaAuthMethod::Password, PG16_TO_PG18, None),
    method(
        PostgresHbaAuthMethod::Gss,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::GssApi),
    ),
    method(
        PostgresHbaAuthMethod::Sspi,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Sspi),
    ),
    method(PostgresHbaAuthMethod::Ident, PG16_TO_PG18, None),
    method(PostgresHbaAuthMethod::Peer, PG16_TO_PG18, None),
    method(
        PostgresHbaAuthMethod::Ldap,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    method(PostgresHbaAuthMethod::Radius, PG16_TO_PG18, None),
    method(
        PostgresHbaAuthMethod::Cert,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ssl),
    ),
    method(
        PostgresHbaAuthMethod::Pam,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Pam),
    ),
    method(
        PostgresHbaAuthMethod::Bsd,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::BsdAuth),
    ),
    method(
        PostgresHbaAuthMethod::OAuth,
        PG18_ONLY,
        Some(PostgresAuthTargetCapability::OAuth),
    ),
];

const fn method(
    method: PostgresHbaAuthMethod,
    versions: PostgresAuthVersionRange,
    required_capability: Option<PostgresAuthTargetCapability>,
) -> PostgresHbaMethodMetadata {
    PostgresHbaMethodMetadata {
        method,
        versions,
        required_capability,
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresHbaOption {
    Map,
    ClientCert,
    ClientName,
    PamService,
    PamUseHostname,
    LdapUrl,
    LdapTls,
    LdapScheme,
    LdapServer,
    LdapPort,
    LdapBindDn,
    LdapBindPasswd,
    LdapSearchAttribute,
    LdapSearchFilter,
    LdapBaseDn,
    LdapPrefix,
    LdapSuffix,
    KrbRealm,
    IncludeRealm,
    CompatRealm,
    UpnUsername,
    RadiusServers,
    RadiusPorts,
    RadiusSecrets,
    RadiusIdentifiers,
    Issuer,
    Scope,
    Validator,
    DelegateIdentMapping,
}

impl PostgresHbaOption {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Map => "map",
            Self::ClientCert => "clientcert",
            Self::ClientName => "clientname",
            Self::PamService => "pamservice",
            Self::PamUseHostname => "pam_use_hostname",
            Self::LdapUrl => "ldapurl",
            Self::LdapTls => "ldaptls",
            Self::LdapScheme => "ldapscheme",
            Self::LdapServer => "ldapserver",
            Self::LdapPort => "ldapport",
            Self::LdapBindDn => "ldapbinddn",
            Self::LdapBindPasswd => "ldapbindpasswd",
            Self::LdapSearchAttribute => "ldapsearchattribute",
            Self::LdapSearchFilter => "ldapsearchfilter",
            Self::LdapBaseDn => "ldapbasedn",
            Self::LdapPrefix => "ldapprefix",
            Self::LdapSuffix => "ldapsuffix",
            Self::KrbRealm => "krb_realm",
            Self::IncludeRealm => "include_realm",
            Self::CompatRealm => "compat_realm",
            Self::UpnUsername => "upn_username",
            Self::RadiusServers => "radiusservers",
            Self::RadiusPorts => "radiusports",
            Self::RadiusSecrets => "radiussecrets",
            Self::RadiusIdentifiers => "radiusidentifiers",
            Self::Issuer => "issuer",
            Self::Scope => "scope",
            Self::Validator => "validator",
            Self::DelegateIdentMapping => "delegate_ident_mapping",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "map" => Some(Self::Map),
            "clientcert" => Some(Self::ClientCert),
            "clientname" => Some(Self::ClientName),
            "pamservice" => Some(Self::PamService),
            "pam_use_hostname" => Some(Self::PamUseHostname),
            "ldapurl" => Some(Self::LdapUrl),
            "ldaptls" => Some(Self::LdapTls),
            "ldapscheme" => Some(Self::LdapScheme),
            "ldapserver" => Some(Self::LdapServer),
            "ldapport" => Some(Self::LdapPort),
            "ldapbinddn" => Some(Self::LdapBindDn),
            "ldapbindpasswd" => Some(Self::LdapBindPasswd),
            "ldapsearchattribute" => Some(Self::LdapSearchAttribute),
            "ldapsearchfilter" => Some(Self::LdapSearchFilter),
            "ldapbasedn" => Some(Self::LdapBaseDn),
            "ldapprefix" => Some(Self::LdapPrefix),
            "ldapsuffix" => Some(Self::LdapSuffix),
            "krb_realm" => Some(Self::KrbRealm),
            "include_realm" => Some(Self::IncludeRealm),
            "compat_realm" => Some(Self::CompatRealm),
            "upn_username" => Some(Self::UpnUsername),
            "radiusservers" => Some(Self::RadiusServers),
            "radiusports" => Some(Self::RadiusPorts),
            "radiussecrets" => Some(Self::RadiusSecrets),
            "radiusidentifiers" => Some(Self::RadiusIdentifiers),
            "issuer" => Some(Self::Issuer),
            "scope" => Some(Self::Scope),
            "validator" => Some(Self::Validator),
            "delegate_ident_mapping" => Some(Self::DelegateIdentMapping),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaOptionSensitivity {
    Public,
    Secret,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaOptionValueKind {
    Text { allow_empty: bool },
    Boolean01,
    Port,
    Enumeration { values: &'static [&'static str] },
    LdapUrl,
    HttpsUrl,
    OAuthScopeList,
    CommaSeparatedList,
    CommaSeparatedPortList,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresHbaOptionMetadata {
    pub option: PostgresHbaOption,
    pub allowed_methods: &'static [PostgresHbaAuthMethod],
    pub value_kind: PostgresHbaOptionValueKind,
    pub sensitivity: PostgresHbaOptionSensitivity,
    pub versions: PostgresAuthVersionRange,
    pub required_capability: Option<PostgresAuthTargetCapability>,
}

const ALL_HBA_METHODS: &[PostgresHbaAuthMethod] = POSTGRES_HBA_METHODS_18;
const MAP_METHODS: &[PostgresHbaAuthMethod] = &[
    PostgresHbaAuthMethod::Ident,
    PostgresHbaAuthMethod::Peer,
    PostgresHbaAuthMethod::Gss,
    PostgresHbaAuthMethod::Sspi,
    PostgresHbaAuthMethod::Cert,
    PostgresHbaAuthMethod::OAuth,
];
const GSS_OR_SSPI_METHODS: &[PostgresHbaAuthMethod] =
    &[PostgresHbaAuthMethod::Gss, PostgresHbaAuthMethod::Sspi];
const LDAP_METHOD: &[PostgresHbaAuthMethod] = &[PostgresHbaAuthMethod::Ldap];
const RADIUS_METHOD: &[PostgresHbaAuthMethod] = &[PostgresHbaAuthMethod::Radius];
const PAM_METHOD: &[PostgresHbaAuthMethod] = &[PostgresHbaAuthMethod::Pam];
const SSPI_METHOD: &[PostgresHbaAuthMethod] = &[PostgresHbaAuthMethod::Sspi];
const OAUTH_METHOD: &[PostgresHbaAuthMethod] = &[PostgresHbaAuthMethod::OAuth];

const POSTGRES_HBA_OPTION_METADATA: &[PostgresHbaOptionMetadata] = &[
    option(
        PostgresHbaOption::Map,
        MAP_METHODS,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::IdentityMap),
    ),
    option(
        PostgresHbaOption::ClientCert,
        ALL_HBA_METHODS,
        PostgresHbaOptionValueKind::Enumeration {
            values: &["verify-ca", "verify-full"],
        },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ssl),
    ),
    option(
        PostgresHbaOption::ClientName,
        ALL_HBA_METHODS,
        PostgresHbaOptionValueKind::Enumeration {
            values: &["CN", "DN"],
        },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ssl),
    ),
    option(
        PostgresHbaOption::PamService,
        PAM_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Pam),
    ),
    option(
        PostgresHbaOption::PamUseHostname,
        PAM_METHOD,
        PostgresHbaOptionValueKind::Boolean01,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Pam),
    ),
    option(
        PostgresHbaOption::LdapUrl,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::LdapUrl,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::OpenLdapUrl),
    ),
    option(
        PostgresHbaOption::LdapTls,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Boolean01,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapScheme,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Enumeration {
            values: &["ldap", "ldaps"],
        },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapServer,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapPort,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Port,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapBindDn,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapBindPasswd,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: true },
        PostgresHbaOptionSensitivity::Secret,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapSearchAttribute,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapSearchFilter,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapBaseDn,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapPrefix,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: true },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::LdapSuffix,
        LDAP_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: true },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Ldap),
    ),
    option(
        PostgresHbaOption::KrbRealm,
        GSS_OR_SSPI_METHODS,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        None,
    ),
    option(
        PostgresHbaOption::IncludeRealm,
        GSS_OR_SSPI_METHODS,
        PostgresHbaOptionValueKind::Boolean01,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        None,
    ),
    option(
        PostgresHbaOption::CompatRealm,
        SSPI_METHOD,
        PostgresHbaOptionValueKind::Boolean01,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Sspi),
    ),
    option(
        PostgresHbaOption::UpnUsername,
        SSPI_METHOD,
        PostgresHbaOptionValueKind::Boolean01,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        Some(PostgresAuthTargetCapability::Sspi),
    ),
    option(
        PostgresHbaOption::RadiusServers,
        RADIUS_METHOD,
        PostgresHbaOptionValueKind::CommaSeparatedList,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        None,
    ),
    option(
        PostgresHbaOption::RadiusPorts,
        RADIUS_METHOD,
        PostgresHbaOptionValueKind::CommaSeparatedPortList,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        None,
    ),
    option(
        PostgresHbaOption::RadiusSecrets,
        RADIUS_METHOD,
        PostgresHbaOptionValueKind::CommaSeparatedList,
        PostgresHbaOptionSensitivity::Secret,
        PG16_TO_PG18,
        None,
    ),
    option(
        PostgresHbaOption::RadiusIdentifiers,
        RADIUS_METHOD,
        PostgresHbaOptionValueKind::CommaSeparatedList,
        PostgresHbaOptionSensitivity::Public,
        PG16_TO_PG18,
        None,
    ),
    option(
        PostgresHbaOption::Issuer,
        OAUTH_METHOD,
        PostgresHbaOptionValueKind::HttpsUrl,
        PostgresHbaOptionSensitivity::Public,
        PG18_ONLY,
        Some(PostgresAuthTargetCapability::OAuth),
    ),
    option(
        PostgresHbaOption::Scope,
        OAUTH_METHOD,
        PostgresHbaOptionValueKind::OAuthScopeList,
        PostgresHbaOptionSensitivity::Public,
        PG18_ONLY,
        Some(PostgresAuthTargetCapability::OAuth),
    ),
    option(
        PostgresHbaOption::Validator,
        OAUTH_METHOD,
        PostgresHbaOptionValueKind::Text { allow_empty: false },
        PostgresHbaOptionSensitivity::Public,
        PG18_ONLY,
        Some(PostgresAuthTargetCapability::OAuth),
    ),
    option(
        PostgresHbaOption::DelegateIdentMapping,
        OAUTH_METHOD,
        PostgresHbaOptionValueKind::Boolean01,
        PostgresHbaOptionSensitivity::Public,
        PG18_ONLY,
        Some(PostgresAuthTargetCapability::OAuth),
    ),
];

const fn option(
    option: PostgresHbaOption,
    allowed_methods: &'static [PostgresHbaAuthMethod],
    value_kind: PostgresHbaOptionValueKind,
    sensitivity: PostgresHbaOptionSensitivity,
    versions: PostgresAuthVersionRange,
    required_capability: Option<PostgresAuthTargetCapability>,
) -> PostgresHbaOptionMetadata {
    PostgresHbaOptionMetadata {
        option,
        allowed_methods,
        value_kind,
        sensitivity,
        versions,
        required_capability,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaMethodLookup {
    Known(&'static PostgresHbaMethodMetadata),
    UnavailableInVersion(&'static PostgresHbaMethodMetadata),
    VisibleUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaOptionLookup {
    Known(&'static PostgresHbaOptionMetadata),
    UnavailableInVersion(&'static PostgresHbaOptionMetadata),
    TargetDependent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresAuthReference {
    pub title: &'static str,
    pub url: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresAuthSchema {
    pub version: PostgresAuthMajorVersion,
    pub artifact: PostgresAuthArtifact,
    pub references: &'static [PostgresAuthReference],
}

impl PostgresAuthSchema {
    pub const fn methods(&self) -> &'static [PostgresHbaAuthMethod] {
        if !matches!(self.artifact, PostgresAuthArtifact::Hba) {
            return &[];
        }
        match self.version {
            PostgresAuthMajorVersion::V16 | PostgresAuthMajorVersion::V17 => {
                POSTGRES_HBA_METHODS_16_17
            }
            PostgresAuthMajorVersion::V18 => POSTGRES_HBA_METHODS_18,
        }
    }

    pub fn options(&self) -> impl Iterator<Item = &'static PostgresHbaOptionMetadata> + use<'_> {
        let version = self.version;
        let is_hba = matches!(self.artifact, PostgresAuthArtifact::Hba);
        POSTGRES_HBA_OPTION_METADATA
            .iter()
            .filter(move |metadata| is_hba && metadata.versions.contains(version))
    }

    pub fn lookup_hba_method(
        &self,
        name: &str,
    ) -> Result<PostgresHbaMethodLookup, PostgresAuthArtifactError> {
        self.require_artifact(PostgresAuthArtifact::Hba)?;
        let Some(method) = PostgresHbaAuthMethod::parse(name) else {
            return Ok(PostgresHbaMethodLookup::VisibleUnknown);
        };
        let metadata = method_metadata(method);
        if metadata.versions.contains(self.version) {
            Ok(PostgresHbaMethodLookup::Known(metadata))
        } else {
            Ok(PostgresHbaMethodLookup::UnavailableInVersion(metadata))
        }
    }

    pub fn lookup_hba_option(
        &self,
        name: &str,
    ) -> Result<PostgresHbaOptionLookup, PostgresAuthArtifactError> {
        self.require_artifact(PostgresAuthArtifact::Hba)?;
        let Some(option) = PostgresHbaOption::parse(name) else {
            return Ok(PostgresHbaOptionLookup::TargetDependent);
        };
        let metadata = option_metadata(option);
        if metadata.versions.contains(self.version) {
            Ok(PostgresHbaOptionLookup::Known(metadata))
        } else {
            Ok(PostgresHbaOptionLookup::UnavailableInVersion(metadata))
        }
    }

    pub fn validate_hba_record(
        &self,
        record: &PostgresHbaRecordInput<'_>,
    ) -> Result<PostgresAuthValidation, PostgresAuthArtifactError> {
        self.require_artifact(PostgresAuthArtifact::Hba)?;
        Ok(validate_hba_record(self, record))
    }

    pub fn validate_ident_record(
        &self,
        record: &PostgresIdentRecordInput<'_>,
    ) -> Result<PostgresAuthValidation, PostgresAuthArtifactError> {
        self.require_artifact(PostgresAuthArtifact::Ident)?;
        Ok(validate_ident_record(record))
    }

    fn require_artifact(
        &self,
        expected: PostgresAuthArtifact,
    ) -> Result<(), PostgresAuthArtifactError> {
        if self.artifact == expected {
            Ok(())
        } else {
            Err(PostgresAuthArtifactError::WrongArtifact {
                expected,
                actual: self.artifact,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PostgresAuthArtifactError {
    #[error("the validator requires {expected:?}, but the schema is {actual:?}")]
    WrongArtifact {
        expected: PostgresAuthArtifact,
        actual: PostgresAuthArtifact,
    },
}

const PG16_HBA_REFERENCES: &[PostgresAuthReference] = &[PostgresAuthReference {
    title: "PostgreSQL 16: The pg_hba.conf File",
    url: "https://www.postgresql.org/docs/16/auth-pg-hba-conf.html",
}];
const PG17_HBA_REFERENCES: &[PostgresAuthReference] = &[PostgresAuthReference {
    title: "PostgreSQL 17: The pg_hba.conf File",
    url: "https://www.postgresql.org/docs/17/auth-pg-hba-conf.html",
}];
const PG18_HBA_REFERENCES: &[PostgresAuthReference] = &[
    PostgresAuthReference {
        title: "PostgreSQL 18: The pg_hba.conf File",
        url: "https://www.postgresql.org/docs/18/auth-pg-hba-conf.html",
    },
    PostgresAuthReference {
        title: "PostgreSQL 18: OAuth Authorization/Authentication",
        url: "https://www.postgresql.org/docs/18/auth-oauth.html",
    },
];
const PG16_IDENT_REFERENCES: &[PostgresAuthReference] = &[PostgresAuthReference {
    title: "PostgreSQL 16: User Name Maps",
    url: "https://www.postgresql.org/docs/16/auth-username-maps.html",
}];
const PG17_IDENT_REFERENCES: &[PostgresAuthReference] = &[PostgresAuthReference {
    title: "PostgreSQL 17: User Name Maps",
    url: "https://www.postgresql.org/docs/17/auth-username-maps.html",
}];
const PG18_IDENT_REFERENCES: &[PostgresAuthReference] = &[PostgresAuthReference {
    title: "PostgreSQL 18: User Name Maps",
    url: "https://www.postgresql.org/docs/18/auth-username-maps.html",
}];

pub const POSTGRESQL_HBA_16_SCHEMA: PostgresAuthSchema = PostgresAuthSchema {
    version: PostgresAuthMajorVersion::V16,
    artifact: PostgresAuthArtifact::Hba,
    references: PG16_HBA_REFERENCES,
};
pub const POSTGRESQL_HBA_17_SCHEMA: PostgresAuthSchema = PostgresAuthSchema {
    version: PostgresAuthMajorVersion::V17,
    artifact: PostgresAuthArtifact::Hba,
    references: PG17_HBA_REFERENCES,
};
pub const POSTGRESQL_HBA_18_SCHEMA: PostgresAuthSchema = PostgresAuthSchema {
    version: PostgresAuthMajorVersion::V18,
    artifact: PostgresAuthArtifact::Hba,
    references: PG18_HBA_REFERENCES,
};
pub const POSTGRESQL_IDENT_16_SCHEMA: PostgresAuthSchema = PostgresAuthSchema {
    version: PostgresAuthMajorVersion::V16,
    artifact: PostgresAuthArtifact::Ident,
    references: PG16_IDENT_REFERENCES,
};
pub const POSTGRESQL_IDENT_17_SCHEMA: PostgresAuthSchema = PostgresAuthSchema {
    version: PostgresAuthMajorVersion::V17,
    artifact: PostgresAuthArtifact::Ident,
    references: PG17_IDENT_REFERENCES,
};
pub const POSTGRESQL_IDENT_18_SCHEMA: PostgresAuthSchema = PostgresAuthSchema {
    version: PostgresAuthMajorVersion::V18,
    artifact: PostgresAuthArtifact::Ident,
    references: PG18_IDENT_REFERENCES,
};

pub fn postgres_auth_schema(
    target: PostgresAuthSchemaTarget<'_>,
) -> Result<&'static PostgresAuthSchema, PostgresAuthSchemaLookupError> {
    if target.product != DatabaseConfigProduct::PostgreSql {
        return Err(PostgresAuthSchemaLookupError::NativePostgreSqlRequired);
    }
    let registered_artifact = artifact_by_key(target.artifact_key)
        .ok_or(PostgresAuthSchemaLookupError::ArtifactUnknown)?;
    let artifact = PostgresAuthArtifact::from_key(target.artifact_key)
        .ok_or(PostgresAuthSchemaLookupError::ExactArtifactRequired)?;
    if registered_artifact.product != DatabaseConfigProduct::PostgreSql {
        return Err(PostgresAuthSchemaLookupError::ArtifactProductMismatch);
    }
    let version = PostgresAuthMajorVersion::from_database_version(target.version)
        .ok_or(PostgresAuthSchemaLookupError::UnsupportedVersion)?;
    Ok(match (artifact, version) {
        (PostgresAuthArtifact::Hba, PostgresAuthMajorVersion::V16) => &POSTGRESQL_HBA_16_SCHEMA,
        (PostgresAuthArtifact::Hba, PostgresAuthMajorVersion::V17) => &POSTGRESQL_HBA_17_SCHEMA,
        (PostgresAuthArtifact::Hba, PostgresAuthMajorVersion::V18) => &POSTGRESQL_HBA_18_SCHEMA,
        (PostgresAuthArtifact::Ident, PostgresAuthMajorVersion::V16) => &POSTGRESQL_IDENT_16_SCHEMA,
        (PostgresAuthArtifact::Ident, PostgresAuthMajorVersion::V17) => &POSTGRESQL_IDENT_17_SCHEMA,
        (PostgresAuthArtifact::Ident, PostgresAuthMajorVersion::V18) => &POSTGRESQL_IDENT_18_SCHEMA,
    })
}

fn method_metadata(method: PostgresHbaAuthMethod) -> &'static PostgresHbaMethodMetadata {
    POSTGRES_HBA_METHOD_METADATA
        .iter()
        .find(|metadata| metadata.method == method)
        .expect("every typed PostgreSQL HBA method has static metadata")
}

fn option_metadata(option: PostgresHbaOption) -> &'static PostgresHbaOptionMetadata {
    POSTGRES_HBA_OPTION_METADATA
        .iter()
        .find(|metadata| metadata.option == option)
        .expect("every typed PostgreSQL HBA option has static metadata")
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PostgresHbaConnectionType {
    Local,
    Host,
    HostSsl,
    HostNoSsl,
    HostGssEnc,
    HostNoGssEnc,
}

impl PostgresHbaConnectionType {
    pub const fn is_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaAddress<'a> {
    None,
    NameOrCidr(&'a str),
    NumericAndMask { address: &'a str, mask: &'a str },
}

pub struct PostgresHbaRecordInput<'a> {
    pub connection: PostgresHbaConnectionType,
    pub database: &'a str,
    pub user: &'a str,
    pub address: PostgresHbaAddress<'a>,
    pub method: &'a str,
    pub options: &'a [PostgresHbaOptionInput],
}

impl fmt::Debug for PostgresHbaRecordInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address_shape = match self.address {
            PostgresHbaAddress::None => "none",
            PostgresHbaAddress::NameOrCidr(_) => "name-or-cidr",
            PostgresHbaAddress::NumericAndMask { .. } => "numeric-and-mask",
        };
        formatter
            .debug_struct("PostgresHbaRecordInput")
            .field("connection", &self.connection)
            .field("database_bytes", &self.database.len())
            .field("user_bytes", &self.user.len())
            .field("address_shape", &address_shape)
            .field("known_method", &PostgresHbaAuthMethod::parse(self.method))
            .field("method_bytes", &self.method.len())
            .field("options", &self.options)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaSecretOption {
    LdapBindPasswd,
    RadiusSecrets,
}

impl PostgresHbaSecretOption {
    const fn option(self) -> PostgresHbaOption {
        match self {
            Self::LdapBindPasswd => PostgresHbaOption::LdapBindPasswd,
            Self::RadiusSecrets => PostgresHbaOption::RadiusSecrets,
        }
    }
}

enum PostgresHbaRawOptionValue {
    Supplied(Zeroizing<String>),
    SecretPresent,
}

pub struct PostgresHbaOptionInput {
    name: String,
    value: PostgresHbaRawOptionValue,
}

impl fmt::Debug for PostgresHbaOptionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let known_option = PostgresHbaOption::parse(&self.name);
        formatter
            .debug_struct("PostgresHbaOptionInput")
            .field("known_option", &known_option)
            .field("name_bytes", &self.name.len())
            .field("value_presence", &self.value_presence())
            .finish()
    }
}

impl PostgresHbaOptionInput {
    /// Consumes a zeroizing value for every option. This keeps unknown target
    /// extensions and the two known secret options on the same safe boundary.
    pub fn new(
        name: impl Into<String>,
        value: Zeroizing<String>,
    ) -> Result<Self, PostgresHbaOptionInputError> {
        let name = name.into();
        validate_option_input_name(&name)?;
        if value.len() > MAX_POSTGRES_AUTH_OPTION_VALUE_BYTES {
            return Err(PostgresHbaOptionInputError::ValueTooLong);
        }
        Ok(Self {
            name,
            value: PostgresHbaRawOptionValue::Supplied(value),
        })
    }

    /// Represents a secret detected by a caller that intentionally discarded
    /// the raw value. Validation returns only presence-dependent conclusions.
    pub fn secret_present(option: PostgresHbaSecretOption) -> Self {
        Self {
            name: option.option().as_str().to_owned(),
            value: PostgresHbaRawOptionValue::SecretPresent,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn value_presence(&self) -> PostgresHbaOptionValuePresence {
        match self.value {
            PostgresHbaRawOptionValue::Supplied(_) => PostgresHbaOptionValuePresence::Supplied,
            PostgresHbaRawOptionValue::SecretPresent => {
                PostgresHbaOptionValuePresence::SecretPresent
            }
        }
    }

    fn raw_value(&self) -> Option<&str> {
        match &self.value {
            PostgresHbaRawOptionValue::Supplied(value) => Some(value.as_str()),
            PostgresHbaRawOptionValue::SecretPresent => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresHbaOptionValuePresence {
    Supplied,
    SecretPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PostgresHbaOptionInputError {
    #[error("the option name is empty")]
    EmptyName,
    #[error("the option name exceeds the byte limit")]
    NameTooLong,
    #[error("the option name contains whitespace, '=' or a control character")]
    UnsafeName,
    #[error("the option value exceeds the byte limit")]
    ValueTooLong,
}

fn validate_option_input_name(name: &str) -> Result<(), PostgresHbaOptionInputError> {
    if name.is_empty() {
        return Err(PostgresHbaOptionInputError::EmptyName);
    }
    if name.len() > MAX_POSTGRES_AUTH_OPTION_NAME_BYTES {
        return Err(PostgresHbaOptionInputError::NameTooLong);
    }
    if name
        .chars()
        .any(|character| character.is_control() || character.is_whitespace() || character == '=')
    {
        return Err(PostgresHbaOptionInputError::UnsafeName);
    }
    Ok(())
}

pub struct PostgresIdentRecordInput<'a> {
    pub map_name: &'a str,
    pub system_user: &'a str,
    pub database_user: &'a str,
}

impl fmt::Debug for PostgresIdentRecordInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresIdentRecordInput")
            .field("map_name_bytes", &self.map_name.len())
            .field("system_user_bytes", &self.system_user.len())
            .field("database_user_bytes", &self.database_user.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresAuthDiagnosticDisposition {
    Invalid,
    Advisory,
    VisibleUnknown,
    TargetDependent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresAuthValidationStatus {
    StaticValid,
    Advisory,
    TargetDependent,
    VisibleUnknown,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresAuthDiagnosticField {
    Record,
    Connection,
    Database,
    User,
    Address,
    Method,
    Option(usize),
    IdentMapName,
    IdentSystemUser,
    IdentDatabaseUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresAuthOptionValueError {
    Empty,
    InvalidBoolean,
    InvalidPort,
    UnknownEnumerationValue,
    InvalidLdapUrl,
    InvalidHttpsUrl,
    InvalidOAuthScopeList,
    InvalidCommaSeparatedList,
    InvalidCommaSeparatedPortList,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresAuthDiagnosticCode {
    EmptyField,
    FieldTooLong,
    ForbiddenFieldCharacter,
    LocalRecordHasAddress,
    HostRecordMissingAddress,
    InvalidCidrAddress,
    NumericAddressRequiresMask,
    InvalidNumericAddress,
    InvalidNumericMask,
    AddressMaskFamilyMismatch,
    HostNameResolutionNotChecked,
    UnknownMethod,
    MethodUnavailableInVersion(PostgresHbaAuthMethod),
    PeerRequiresLocal,
    CertRequiresHostSsl,
    Md5DeprecatedInPostgres18,
    TooManyOptions,
    UnknownOption,
    OptionUnavailableInVersion(PostgresHbaOption),
    OptionNotAllowedForMethod {
        option: PostgresHbaOption,
        method: PostgresHbaAuthMethod,
    },
    InvalidOptionValue {
        option: PostgresHbaOption,
        error: PostgresAuthOptionValueError,
    },
    ClientCertRequiresHostSsl,
    CertClientCertMustVerifyFull,
    ClientNameRequiresHostSsl,
    ClientNameRequiresCertificateValidation,
    LdapModeRequired,
    LdapSimpleAndSearchModesMixed,
    LdapSearchBaseRequired,
    LdapSearchSelectorsConflict,
    LdapBindCredentialsIncomplete,
    LdapServerRequirementDependsOnTarget,
    RequiredOptionMissing(PostgresHbaOption),
    RadiusCardinalityMismatch {
        option: PostgresHbaOption,
        servers: usize,
        values: usize,
    },
    SecretValueNotInspected(PostgresHbaOption),
    OAuthMapConflictsWithDelegation,
    OAuthValidatorSelectionDependsOnTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresAuthDiagnostic {
    pub disposition: PostgresAuthDiagnosticDisposition,
    pub field: PostgresAuthDiagnosticField,
    pub code: PostgresAuthDiagnosticCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresAuthValidation {
    diagnostics: Vec<PostgresAuthDiagnostic>,
    required_capabilities: Vec<PostgresAuthTargetCapability>,
}

impl PostgresAuthValidation {
    fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
            required_capabilities: Vec::new(),
        }
    }

    pub fn diagnostics(&self) -> &[PostgresAuthDiagnostic] {
        &self.diagnostics
    }

    pub fn required_capabilities(&self) -> &[PostgresAuthTargetCapability] {
        &self.required_capabilities
    }

    pub fn status(&self) -> PostgresAuthValidationStatus {
        if self.has_disposition(PostgresAuthDiagnosticDisposition::Invalid) {
            PostgresAuthValidationStatus::Invalid
        } else if self.has_disposition(PostgresAuthDiagnosticDisposition::VisibleUnknown) {
            PostgresAuthValidationStatus::VisibleUnknown
        } else if self.has_disposition(PostgresAuthDiagnosticDisposition::TargetDependent) {
            PostgresAuthValidationStatus::TargetDependent
        } else if self.has_disposition(PostgresAuthDiagnosticDisposition::Advisory) {
            PostgresAuthValidationStatus::Advisory
        } else {
            PostgresAuthValidationStatus::StaticValid
        }
    }

    pub fn has_invalid(&self) -> bool {
        self.has_disposition(PostgresAuthDiagnosticDisposition::Invalid)
    }

    fn has_disposition(&self, disposition: PostgresAuthDiagnosticDisposition) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.disposition == disposition)
    }

    fn push(
        &mut self,
        disposition: PostgresAuthDiagnosticDisposition,
        field: PostgresAuthDiagnosticField,
        code: PostgresAuthDiagnosticCode,
    ) {
        self.diagnostics.push(PostgresAuthDiagnostic {
            disposition,
            field,
            code,
        });
    }

    fn require(&mut self, capability: PostgresAuthTargetCapability) {
        if !self.required_capabilities.contains(&capability) {
            self.required_capabilities.push(capability);
        }
    }
}

pub fn validate_postgres_hba_record_shape(
    record: &PostgresHbaRecordInput<'_>,
) -> PostgresAuthValidation {
    let mut validation = PostgresAuthValidation::new();
    validate_record_field(
        record.database,
        PostgresAuthDiagnosticField::Database,
        &mut validation,
    );
    validate_record_field(
        record.user,
        PostgresAuthDiagnosticField::User,
        &mut validation,
    );
    validate_method_field(record.method, &mut validation);

    if record.connection.is_local() {
        if !matches!(record.address, PostgresHbaAddress::None) {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                PostgresAuthDiagnosticField::Address,
                PostgresAuthDiagnosticCode::LocalRecordHasAddress,
            );
        }
        return validation;
    }

    match record.address {
        PostgresHbaAddress::None => validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Address,
            PostgresAuthDiagnosticCode::HostRecordMissingAddress,
        ),
        PostgresHbaAddress::NameOrCidr(value) => validate_name_or_cidr(value, &mut validation),
        PostgresHbaAddress::NumericAndMask { address, mask } => {
            validate_numeric_and_mask(address, mask, &mut validation)
        }
    }
    validation
}

fn validate_hba_record(
    schema: &PostgresAuthSchema,
    record: &PostgresHbaRecordInput<'_>,
) -> PostgresAuthValidation {
    let mut validation = validate_postgres_hba_record_shape(record);
    match record.connection {
        PostgresHbaConnectionType::HostSsl => validation.require(PostgresAuthTargetCapability::Ssl),
        PostgresHbaConnectionType::HostGssEnc => {
            validation.require(PostgresAuthTargetCapability::GssApi)
        }
        _ => {}
    }

    let method = match schema.lookup_hba_method(record.method) {
        Ok(PostgresHbaMethodLookup::Known(metadata)) => {
            if let Some(capability) = metadata.required_capability {
                validation.require(capability);
            }
            Some(metadata.method)
        }
        Ok(PostgresHbaMethodLookup::UnavailableInVersion(metadata)) => {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                PostgresAuthDiagnosticField::Method,
                PostgresAuthDiagnosticCode::MethodUnavailableInVersion(metadata.method),
            );
            Some(metadata.method)
        }
        Ok(PostgresHbaMethodLookup::VisibleUnknown) => {
            validation.push(
                PostgresAuthDiagnosticDisposition::VisibleUnknown,
                PostgresAuthDiagnosticField::Method,
                PostgresAuthDiagnosticCode::UnknownMethod,
            );
            None
        }
        Err(_) => unreachable!("HBA artifact was checked before validation"),
    };

    if let Some(method) = method {
        validate_method_connection(schema.version, record.connection, method, &mut validation);
    }
    validate_options(schema, record, method, &mut validation);
    validation
}

fn validate_method_connection(
    version: PostgresAuthMajorVersion,
    connection: PostgresHbaConnectionType,
    method: PostgresHbaAuthMethod,
    validation: &mut PostgresAuthValidation,
) {
    if method == PostgresHbaAuthMethod::Peer && !connection.is_local() {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Method,
            PostgresAuthDiagnosticCode::PeerRequiresLocal,
        );
    }
    if method == PostgresHbaAuthMethod::Cert && connection != PostgresHbaConnectionType::HostSsl {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Method,
            PostgresAuthDiagnosticCode::CertRequiresHostSsl,
        );
    }
    if version == PostgresAuthMajorVersion::V18 && method == PostgresHbaAuthMethod::Md5 {
        validation.push(
            PostgresAuthDiagnosticDisposition::Advisory,
            PostgresAuthDiagnosticField::Method,
            PostgresAuthDiagnosticCode::Md5DeprecatedInPostgres18,
        );
    }
}

fn validate_options(
    schema: &PostgresAuthSchema,
    record: &PostgresHbaRecordInput<'_>,
    method: Option<PostgresHbaAuthMethod>,
    validation: &mut PostgresAuthValidation,
) {
    if record.options.len() > MAX_POSTGRES_AUTH_OPTIONS {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::TooManyOptions,
        );
    }

    for (index, input) in record
        .options
        .iter()
        .take(MAX_POSTGRES_AUTH_OPTIONS)
        .enumerate()
    {
        let field = PostgresAuthDiagnosticField::Option(index);
        let metadata = match schema.lookup_hba_option(input.name()) {
            Ok(PostgresHbaOptionLookup::Known(metadata)) => metadata,
            Ok(PostgresHbaOptionLookup::UnavailableInVersion(metadata)) => {
                validation.push(
                    PostgresAuthDiagnosticDisposition::Invalid,
                    field,
                    PostgresAuthDiagnosticCode::OptionUnavailableInVersion(metadata.option),
                );
                continue;
            }
            Ok(PostgresHbaOptionLookup::TargetDependent) => {
                validation.push(
                    PostgresAuthDiagnosticDisposition::TargetDependent,
                    field,
                    PostgresAuthDiagnosticCode::UnknownOption,
                );
                continue;
            }
            Err(_) => unreachable!("HBA artifact was checked before validation"),
        };
        if let Some(capability) = metadata.required_capability {
            validation.require(capability);
        }
        if let Some(method) = method
            && !metadata.allowed_methods.contains(&method)
        {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                field,
                PostgresAuthDiagnosticCode::OptionNotAllowedForMethod {
                    option: metadata.option,
                    method,
                },
            );
        }
        match input.raw_value() {
            Some(value) => {
                if let Some(error) = validate_option_value(metadata.value_kind, value) {
                    validation.push(
                        PostgresAuthDiagnosticDisposition::Invalid,
                        field,
                        PostgresAuthDiagnosticCode::InvalidOptionValue {
                            option: metadata.option,
                            error,
                        },
                    );
                }
            }
            None if metadata.sensitivity == PostgresHbaOptionSensitivity::Secret => {}
            None => validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                field,
                PostgresAuthDiagnosticCode::InvalidOptionValue {
                    option: metadata.option,
                    error: PostgresAuthOptionValueError::Empty,
                },
            ),
        }
    }

    if let Some(method) = method {
        validate_client_certificate_options(record, method, validation);
        match method {
            PostgresHbaAuthMethod::Ldap => validate_ldap_options(record, validation),
            PostgresHbaAuthMethod::Radius => validate_radius_options(record, validation),
            PostgresHbaAuthMethod::OAuth if schema.version == PostgresAuthMajorVersion::V18 => {
                validate_oauth_options(record, validation)
            }
            _ => {}
        }
    }
}

fn validate_client_certificate_options(
    record: &PostgresHbaRecordInput<'_>,
    method: PostgresHbaAuthMethod,
    validation: &mut PostgresAuthValidation,
) {
    let client_cert = effective_option(record.options, PostgresHbaOption::ClientCert);
    let client_name = effective_option(record.options, PostgresHbaOption::ClientName);
    if client_cert.is_some() && record.connection != PostgresHbaConnectionType::HostSsl {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            option_field(record.options, PostgresHbaOption::ClientCert),
            PostgresAuthDiagnosticCode::ClientCertRequiresHostSsl,
        );
    }
    if method == PostgresHbaAuthMethod::Cert
        && client_cert.is_some_and(|input| input.raw_value() != Some("verify-full"))
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            option_field(record.options, PostgresHbaOption::ClientCert),
            PostgresAuthDiagnosticCode::CertClientCertMustVerifyFull,
        );
    }
    if client_name.is_some() {
        if record.connection != PostgresHbaConnectionType::HostSsl {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                option_field(record.options, PostgresHbaOption::ClientName),
                PostgresAuthDiagnosticCode::ClientNameRequiresHostSsl,
            );
        }
        if method != PostgresHbaAuthMethod::Cert && client_cert.is_none() {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                option_field(record.options, PostgresHbaOption::ClientName),
                PostgresAuthDiagnosticCode::ClientNameRequiresCertificateValidation,
            );
        }
    }
}

fn validate_ldap_options(
    record: &PostgresHbaRecordInput<'_>,
    validation: &mut PostgresAuthValidation,
) {
    let simple = option_present(record.options, PostgresHbaOption::LdapPrefix)
        || option_present(record.options, PostgresHbaOption::LdapSuffix);
    let explicit_search = [
        PostgresHbaOption::LdapBaseDn,
        PostgresHbaOption::LdapBindDn,
        PostgresHbaOption::LdapBindPasswd,
        PostgresHbaOption::LdapSearchAttribute,
        PostgresHbaOption::LdapSearchFilter,
    ]
    .iter()
    .any(|option| option_present(record.options, *option));
    let url_search = effective_option(record.options, PostgresHbaOption::LdapUrl)
        .and_then(PostgresHbaOptionInput::raw_value)
        .and_then(ldap_url_uses_search_mode)
        .unwrap_or(false);
    let search = explicit_search || url_search;

    if simple && search {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::LdapSimpleAndSearchModesMixed,
        );
    } else if !simple && !search {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::LdapModeRequired,
        );
    }
    if search && !option_present(record.options, PostgresHbaOption::LdapBaseDn) && !url_search {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::LdapSearchBaseRequired,
        );
    }
    if option_present(record.options, PostgresHbaOption::LdapSearchAttribute)
        && option_present(record.options, PostgresHbaOption::LdapSearchFilter)
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::LdapSearchSelectorsConflict,
        );
    }
    if option_present(record.options, PostgresHbaOption::LdapBindDn)
        != option_present(record.options, PostgresHbaOption::LdapBindPasswd)
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::LdapBindCredentialsIncomplete,
        );
    }
    if !option_present(record.options, PostgresHbaOption::LdapServer)
        && !option_present(record.options, PostgresHbaOption::LdapUrl)
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::TargetDependent,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::LdapServerRequirementDependsOnTarget,
        );
    }
}

fn validate_radius_options(
    record: &PostgresHbaRecordInput<'_>,
    validation: &mut PostgresAuthValidation,
) {
    let servers = effective_option(record.options, PostgresHbaOption::RadiusServers);
    let secrets = effective_option(record.options, PostgresHbaOption::RadiusSecrets);
    if servers.is_none() {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::RequiredOptionMissing(PostgresHbaOption::RadiusServers),
        );
    }
    if secrets.is_none() {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::RequiredOptionMissing(PostgresHbaOption::RadiusSecrets),
        );
    }

    let server_count = servers
        .and_then(PostgresHbaOptionInput::raw_value)
        .and_then(|value| comma_list_count(value).ok());
    let secret_count = match secrets {
        Some(input) => match input.raw_value() {
            Some(value) => comma_list_count(value).ok(),
            None => {
                validation.push(
                    PostgresAuthDiagnosticDisposition::TargetDependent,
                    option_field(record.options, PostgresHbaOption::RadiusSecrets),
                    PostgresAuthDiagnosticCode::SecretValueNotInspected(
                        PostgresHbaOption::RadiusSecrets,
                    ),
                );
                None
            }
        },
        None => None,
    };
    if let (Some(servers), Some(secrets)) = (server_count, secret_count)
        && secrets != 1
        && secrets != servers
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            option_field(record.options, PostgresHbaOption::RadiusSecrets),
            PostgresAuthDiagnosticCode::RadiusCardinalityMismatch {
                option: PostgresHbaOption::RadiusSecrets,
                servers,
                values: secrets,
            },
        );
    }
    for option in [
        PostgresHbaOption::RadiusPorts,
        PostgresHbaOption::RadiusIdentifiers,
    ] {
        let count = effective_option(record.options, option)
            .and_then(PostgresHbaOptionInput::raw_value)
            .and_then(|value| comma_list_count(value).ok());
        if let (Some(servers), Some(values)) = (server_count, count)
            && values != 1
            && values != servers
        {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                option_field(record.options, option),
                PostgresAuthDiagnosticCode::RadiusCardinalityMismatch {
                    option,
                    servers,
                    values,
                },
            );
        }
    }
}

fn validate_oauth_options(
    record: &PostgresHbaRecordInput<'_>,
    validation: &mut PostgresAuthValidation,
) {
    for required in [PostgresHbaOption::Issuer, PostgresHbaOption::Scope] {
        if !option_present(record.options, required) {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                PostgresAuthDiagnosticField::Record,
                PostgresAuthDiagnosticCode::RequiredOptionMissing(required),
            );
        }
    }
    let delegates = effective_option(record.options, PostgresHbaOption::DelegateIdentMapping)
        .and_then(PostgresHbaOptionInput::raw_value)
        == Some("1");
    if delegates && option_present(record.options, PostgresHbaOption::Map) {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Record,
            PostgresAuthDiagnosticCode::OAuthMapConflictsWithDelegation,
        );
    }
    // Whether validator= is optional, required, or names an allowed library
    // depends on the target's oauth_validator_libraries setting.
    validation.push(
        PostgresAuthDiagnosticDisposition::TargetDependent,
        effective_option(record.options, PostgresHbaOption::Validator)
            .map_or(PostgresAuthDiagnosticField::Record, |_| {
                option_field(record.options, PostgresHbaOption::Validator)
            }),
        PostgresAuthDiagnosticCode::OAuthValidatorSelectionDependsOnTarget,
    );
}

fn validate_ident_record(record: &PostgresIdentRecordInput<'_>) -> PostgresAuthValidation {
    let mut validation = PostgresAuthValidation::new();
    for (value, field) in [
        (record.map_name, PostgresAuthDiagnosticField::IdentMapName),
        (
            record.system_user,
            PostgresAuthDiagnosticField::IdentSystemUser,
        ),
        (
            record.database_user,
            PostgresAuthDiagnosticField::IdentDatabaseUser,
        ),
    ] {
        validate_record_field(value, field, &mut validation);
    }
    validation
}

fn validate_record_field(
    value: &str,
    field: PostgresAuthDiagnosticField,
    validation: &mut PostgresAuthValidation,
) {
    if value.is_empty() {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            field,
            PostgresAuthDiagnosticCode::EmptyField,
        );
    } else if value.len() > MAX_POSTGRES_AUTH_FIELD_BYTES {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            field,
            PostgresAuthDiagnosticCode::FieldTooLong,
        );
    } else if value
        .chars()
        .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            field,
            PostgresAuthDiagnosticCode::ForbiddenFieldCharacter,
        );
    }
}

fn validate_method_field(value: &str, validation: &mut PostgresAuthValidation) {
    if value.is_empty() {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Method,
            PostgresAuthDiagnosticCode::EmptyField,
        );
    } else if value.len() > MAX_POSTGRES_AUTH_METHOD_BYTES {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Method,
            PostgresAuthDiagnosticCode::FieldTooLong,
        );
    } else if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace() || character == '=')
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Method,
            PostgresAuthDiagnosticCode::ForbiddenFieldCharacter,
        );
    }
}

fn validate_name_or_cidr(value: &str, validation: &mut PostgresAuthValidation) {
    if value.is_empty()
        || value.len() > MAX_POSTGRES_AUTH_FIELD_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Address,
            PostgresAuthDiagnosticCode::InvalidCidrAddress,
        );
        return;
    }
    if matches!(value, "all" | "samehost" | "samenet") {
        return;
    }
    if value.contains('/') {
        let Some((address, prefix)) = value.split_once('/') else {
            unreachable!();
        };
        if prefix.contains('/')
            || address.parse::<IpAddr>().is_err()
            || !valid_cidr_prefix(address, prefix)
        {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                PostgresAuthDiagnosticField::Address,
                PostgresAuthDiagnosticCode::InvalidCidrAddress,
            );
        }
        return;
    }
    if value.parse::<IpAddr>().is_ok() {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Address,
            PostgresAuthDiagnosticCode::NumericAddressRequiresMask,
        );
        return;
    }
    validation.require(PostgresAuthTargetCapability::TargetNameResolution);
    validation.push(
        PostgresAuthDiagnosticDisposition::TargetDependent,
        PostgresAuthDiagnosticField::Address,
        PostgresAuthDiagnosticCode::HostNameResolutionNotChecked,
    );
}

fn valid_cidr_prefix(address: &str, prefix: &str) -> bool {
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn validate_numeric_and_mask(address: &str, mask: &str, validation: &mut PostgresAuthValidation) {
    let address = match address.parse::<IpAddr>() {
        Ok(address) => address,
        Err(_) => {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                PostgresAuthDiagnosticField::Address,
                PostgresAuthDiagnosticCode::InvalidNumericAddress,
            );
            return;
        }
    };
    let mask = match mask.parse::<IpAddr>() {
        Ok(mask) => mask,
        Err(_) => {
            validation.push(
                PostgresAuthDiagnosticDisposition::Invalid,
                PostgresAuthDiagnosticField::Address,
                PostgresAuthDiagnosticCode::InvalidNumericMask,
            );
            return;
        }
    };
    if !matches!(
        (address, mask),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    ) {
        validation.push(
            PostgresAuthDiagnosticDisposition::Invalid,
            PostgresAuthDiagnosticField::Address,
            PostgresAuthDiagnosticCode::AddressMaskFamilyMismatch,
        );
    }
}

fn validate_option_value(
    kind: PostgresHbaOptionValueKind,
    value: &str,
) -> Option<PostgresAuthOptionValueError> {
    match kind {
        PostgresHbaOptionValueKind::Text { allow_empty } => {
            (!allow_empty && value.is_empty()).then_some(PostgresAuthOptionValueError::Empty)
        }
        PostgresHbaOptionValueKind::Boolean01 => {
            (!matches!(value, "0" | "1")).then_some(PostgresAuthOptionValueError::InvalidBoolean)
        }
        PostgresHbaOptionValueKind::Port => {
            (!valid_port(value)).then_some(PostgresAuthOptionValueError::InvalidPort)
        }
        PostgresHbaOptionValueKind::Enumeration { values } => (!values.contains(&value))
            .then_some(PostgresAuthOptionValueError::UnknownEnumerationValue),
        PostgresHbaOptionValueKind::LdapUrl => {
            (!valid_ldap_url(value)).then_some(PostgresAuthOptionValueError::InvalidLdapUrl)
        }
        PostgresHbaOptionValueKind::HttpsUrl => {
            (!valid_https_url(value)).then_some(PostgresAuthOptionValueError::InvalidHttpsUrl)
        }
        PostgresHbaOptionValueKind::OAuthScopeList => (!valid_oauth_scope_list(value))
            .then_some(PostgresAuthOptionValueError::InvalidOAuthScopeList),
        PostgresHbaOptionValueKind::CommaSeparatedList => comma_list_count(value)
            .is_err()
            .then_some(PostgresAuthOptionValueError::InvalidCommaSeparatedList),
        PostgresHbaOptionValueKind::CommaSeparatedPortList => (!valid_comma_port_list(value))
            .then_some(PostgresAuthOptionValueError::InvalidCommaSeparatedPortList),
    }
}

fn valid_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn valid_ldap_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "ldap" | "ldaps")
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn ldap_url_uses_search_mode(value: &str) -> Option<bool> {
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "ldap" | "ldaps") {
        return None;
    }
    Some(!matches!(url.path(), "" | "/") || url.query().is_some())
}

fn valid_https_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn valid_oauth_scope_list(value: &str) -> bool {
    !value.is_empty()
        && value.split(' ').all(|scope| {
            !scope.is_empty()
                && scope
                    .bytes()
                    .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        })
}

fn comma_list_count(value: &str) -> Result<usize, ()> {
    if value.is_empty() {
        return Err(());
    }
    let mut count = 1_usize;
    let mut item_has_content = false;
    let mut quoted = false;
    let mut bytes = value.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte.is_ascii_control() {
            return Err(());
        }
        match byte {
            b'"' if quoted && bytes.peek() == Some(&b'"') => {
                bytes.next();
                item_has_content = true;
            }
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                if !item_has_content {
                    return Err(());
                }
                count += 1;
                item_has_content = false;
            }
            byte if !byte.is_ascii_whitespace() => item_has_content = true,
            _ => {}
        }
    }
    if quoted || !item_has_content {
        Err(())
    } else {
        Ok(count)
    }
}

fn valid_comma_port_list(value: &str) -> bool {
    comma_list_count(value).is_ok()
        && value
            .split(',')
            .map(str::trim)
            .all(|port| !port.contains('"') && valid_port(port))
}

fn effective_option(
    options: &[PostgresHbaOptionInput],
    wanted: PostgresHbaOption,
) -> Option<&PostgresHbaOptionInput> {
    options
        .iter()
        .rev()
        .find(|input| PostgresHbaOption::parse(input.name()) == Some(wanted))
}

fn option_present(options: &[PostgresHbaOptionInput], wanted: PostgresHbaOption) -> bool {
    effective_option(options, wanted).is_some()
}

fn option_field(
    options: &[PostgresHbaOptionInput],
    wanted: PostgresHbaOption,
) -> PostgresAuthDiagnosticField {
    options
        .iter()
        .rposition(|input| PostgresHbaOption::parse(input.name()) == Some(wanted))
        .map_or(PostgresAuthDiagnosticField::Record, |index| {
            PostgresAuthDiagnosticField::Option(index)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(
        product: DatabaseConfigProduct,
        major: u16,
        artifact_key: &str,
    ) -> PostgresAuthSchemaTarget<'_> {
        PostgresAuthSchemaTarget {
            product,
            version: DatabaseConfigVersion::new(major, 3, 0),
            artifact_key,
        }
    }

    fn option(name: &str, value: &str) -> PostgresHbaOptionInput {
        PostgresHbaOptionInput::new(name, Zeroizing::new(value.to_owned())).unwrap()
    }

    fn host_record<'a>(
        method: &'a str,
        options: &'a [PostgresHbaOptionInput],
    ) -> PostgresHbaRecordInput<'a> {
        PostgresHbaRecordInput {
            connection: PostgresHbaConnectionType::Host,
            database: "all",
            user: "all",
            address: PostgresHbaAddress::NameOrCidr("127.0.0.1/32"),
            method,
            options,
        }
    }

    fn hostssl_record<'a>(
        method: &'a str,
        options: &'a [PostgresHbaOptionInput],
    ) -> PostgresHbaRecordInput<'a> {
        PostgresHbaRecordInput {
            connection: PostgresHbaConnectionType::HostSsl,
            ..host_record(method, options)
        }
    }

    fn has_code(validation: &PostgresAuthValidation, code: PostgresAuthDiagnosticCode) -> bool {
        validation
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code)
    }

    #[test]
    fn lookup_is_native_versioned_and_artifact_exact() {
        for major in [16, 17, 18] {
            let hba = postgres_auth_schema(target(
                DatabaseConfigProduct::PostgreSql,
                major,
                POSTGRESQL_HBA_ARTIFACT_KEY,
            ))
            .unwrap();
            assert_eq!(hba.artifact, PostgresAuthArtifact::Hba);
            assert_eq!(hba.version.major(), major);

            let ident = postgres_auth_schema(target(
                DatabaseConfigProduct::PostgreSql,
                major,
                POSTGRESQL_IDENT_ARTIFACT_KEY,
            ))
            .unwrap();
            assert_eq!(ident.artifact, PostgresAuthArtifact::Ident);
            assert_eq!(ident.version.major(), major);
        }
        for major in [15, 19] {
            assert_eq!(
                postgres_auth_schema(target(
                    DatabaseConfigProduct::PostgreSql,
                    major,
                    POSTGRESQL_HBA_ARTIFACT_KEY,
                )),
                Err(PostgresAuthSchemaLookupError::UnsupportedVersion)
            );
        }
        assert_eq!(
            postgres_auth_schema(target(
                DatabaseConfigProduct::OpenGauss,
                18,
                "opengauss-hba",
            )),
            Err(PostgresAuthSchemaLookupError::NativePostgreSqlRequired)
        );
        assert_eq!(
            postgres_auth_schema(target(
                DatabaseConfigProduct::PostgreSql,
                18,
                "postgresql-main",
            )),
            Err(PostgresAuthSchemaLookupError::ExactArtifactRequired)
        );
        assert_eq!(
            postgres_auth_schema(target(
                DatabaseConfigProduct::PostgreSql,
                18,
                "postgresql_hba",
            )),
            Err(PostgresAuthSchemaLookupError::ArtifactUnknown)
        );
    }

    #[test]
    fn method_sets_are_exact_and_pg18_md5_is_advisory() {
        assert_eq!(POSTGRESQL_HBA_16_SCHEMA.methods().len(), 14);
        assert_eq!(POSTGRESQL_HBA_17_SCHEMA.methods().len(), 14);
        assert_eq!(POSTGRESQL_HBA_18_SCHEMA.methods().len(), 15);
        assert!(
            !POSTGRESQL_HBA_17_SCHEMA
                .methods()
                .contains(&PostgresHbaAuthMethod::OAuth)
        );
        assert!(
            POSTGRESQL_HBA_18_SCHEMA
                .methods()
                .contains(&PostgresHbaAuthMethod::OAuth)
        );

        let record = host_record("md5", &[]);
        let pg18 = POSTGRESQL_HBA_18_SCHEMA
            .validate_hba_record(&record)
            .unwrap();
        assert_eq!(pg18.status(), PostgresAuthValidationStatus::Advisory);
        assert!(!pg18.has_invalid());
        assert!(has_code(
            &pg18,
            PostgresAuthDiagnosticCode::Md5DeprecatedInPostgres18
        ));
        assert_eq!(
            POSTGRESQL_HBA_17_SCHEMA
                .validate_hba_record(&record)
                .unwrap()
                .status(),
            PostgresAuthValidationStatus::StaticValid
        );
    }

    #[test]
    fn option_metadata_has_exact_secret_and_version_boundaries() {
        let secrets: Vec<_> = POSTGRES_HBA_OPTION_METADATA
            .iter()
            .filter(|metadata| metadata.sensitivity == PostgresHbaOptionSensitivity::Secret)
            .map(|metadata| metadata.option)
            .collect();
        assert_eq!(
            secrets,
            vec![
                PostgresHbaOption::LdapBindPasswd,
                PostgresHbaOption::RadiusSecrets
            ]
        );
        assert!(matches!(
            POSTGRESQL_HBA_17_SCHEMA.lookup_hba_option("issuer"),
            Ok(PostgresHbaOptionLookup::UnavailableInVersion(_))
        ));
        assert!(matches!(
            POSTGRESQL_HBA_18_SCHEMA.lookup_hba_option("issuer"),
            Ok(PostgresHbaOptionLookup::Known(_))
        ));
        let client_cert = option_metadata(PostgresHbaOption::ClientCert);
        assert_eq!(
            client_cert.required_capability,
            Some(PostgresAuthTargetCapability::Ssl)
        );
        assert!(
            client_cert
                .allowed_methods
                .contains(&PostgresHbaAuthMethod::OAuth)
        );
    }

    #[test]
    fn record_shapes_distinguish_local_cidr_and_numeric_mask() {
        let local = PostgresHbaRecordInput {
            connection: PostgresHbaConnectionType::Local,
            database: "all",
            user: "all",
            address: PostgresHbaAddress::None,
            method: "peer",
            options: &[],
        };
        assert_eq!(
            validate_postgres_hba_record_shape(&local).status(),
            PostgresAuthValidationStatus::StaticValid
        );
        let cidr = host_record("scram-sha-256", &[]);
        assert!(!validate_postgres_hba_record_shape(&cidr).has_invalid());
        let numeric_mask = PostgresHbaRecordInput {
            address: PostgresHbaAddress::NumericAndMask {
                address: "127.0.0.1",
                mask: "255.255.255.255",
            },
            ..host_record("trust", &[])
        };
        assert!(!validate_postgres_hba_record_shape(&numeric_mask).has_invalid());

        let local_with_address = PostgresHbaRecordInput {
            address: PostgresHbaAddress::NameOrCidr("127.0.0.1/32"),
            ..local
        };
        assert!(validate_postgres_hba_record_shape(&local_with_address).has_invalid());
        for address in [
            PostgresHbaAddress::None,
            PostgresHbaAddress::NameOrCidr("127.0.0.1"),
            PostgresHbaAddress::NameOrCidr("127.0.0.1/33"),
            PostgresHbaAddress::NumericAndMask {
                address: "127.0.0.1",
                mask: "ffff:ffff:ffff:ffff::",
            },
        ] {
            let invalid = PostgresHbaRecordInput {
                address,
                ..host_record("trust", &[])
            };
            assert!(validate_postgres_hba_record_shape(&invalid).has_invalid());
        }
        let hostname = PostgresHbaRecordInput {
            address: PostgresHbaAddress::NameOrCidr("db.example.test"),
            ..host_record("trust", &[])
        };
        assert_eq!(
            validate_postgres_hba_record_shape(&hostname).status(),
            PostgresAuthValidationStatus::TargetDependent
        );
    }

    #[test]
    fn peer_cert_clientcert_and_clientname_cross_fields_are_typed() {
        let peer_host = host_record("peer", &[]);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&peer_host)
                .unwrap(),
            PostgresAuthDiagnosticCode::PeerRequiresLocal
        ));
        let cert_host = host_record("cert", &[]);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&cert_host)
                .unwrap(),
            PostgresAuthDiagnosticCode::CertRequiresHostSsl
        ));
        let cert_ssl = hostssl_record("cert", &[]);
        assert!(
            !POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&cert_ssl)
                .unwrap()
                .has_invalid()
        );

        let verify_ca = [option("clientcert", "verify-ca")];
        let cert_verify_ca = hostssl_record("cert", &verify_ca);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&cert_verify_ca)
                .unwrap(),
            PostgresAuthDiagnosticCode::CertClientCertMustVerifyFull
        ));
        let client_name = [option("clientname", "DN")];
        let name_without_cert = hostssl_record("scram-sha-256", &client_name);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&name_without_cert)
                .unwrap(),
            PostgresAuthDiagnosticCode::ClientNameRequiresCertificateValidation
        ));
        let certificate_pair = [
            option("clientcert", "verify-full"),
            option("clientname", "DN"),
        ];
        let valid_pair = hostssl_record("scram-sha-256", &certificate_pair);
        assert!(
            !POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&valid_pair)
                .unwrap()
                .has_invalid()
        );
    }

    #[test]
    fn ldap_simple_and_search_modes_are_not_mixed() {
        let simple_options = [
            option("ldapserver", "ldap.example.test"),
            option("ldapprefix", "cn="),
            option("ldapsuffix", ",dc=example,dc=test"),
        ];
        let simple = host_record("ldap", &simple_options);
        assert!(
            !POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&simple)
                .unwrap()
                .has_invalid()
        );

        let search_options = [
            option("ldapserver", "ldap.example.test"),
            option("ldapbasedn", "dc=example,dc=test"),
            option("ldapsearchattribute", "uid"),
            option("ldapbinddn", "cn=reader,dc=example,dc=test"),
            PostgresHbaOptionInput::secret_present(PostgresHbaSecretOption::LdapBindPasswd),
        ];
        let search = host_record("ldap", &search_options);
        assert!(
            !POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&search)
                .unwrap()
                .has_invalid()
        );

        let mixed_options = [
            option("ldapserver", "ldap.example.test"),
            option("ldapprefix", "cn="),
            option("ldapbasedn", "dc=example,dc=test"),
        ];
        let mixed = host_record("ldap", &mixed_options);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&mixed)
                .unwrap(),
            PostgresAuthDiagnosticCode::LdapSimpleAndSearchModesMixed
        ));

        let selectors = [
            option("ldapserver", "ldap.example.test"),
            option("ldapbasedn", "dc=example,dc=test"),
            option("ldapsearchattribute", "uid"),
            option("ldapsearchfilter", "(mail=$username)"),
        ];
        let conflicting_selectors = host_record("ldap", &selectors);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&conflicting_selectors)
                .unwrap(),
            PostgresAuthDiagnosticCode::LdapSearchSelectorsConflict
        ));
    }

    #[test]
    fn radius_required_options_and_cardinality_are_enforced_without_secret_leaks() {
        let missing = host_record("radius", &[]);
        let missing = POSTGRESQL_HBA_18_SCHEMA
            .validate_hba_record(&missing)
            .unwrap();
        assert!(has_code(
            &missing,
            PostgresAuthDiagnosticCode::RequiredOptionMissing(PostgresHbaOption::RadiusServers)
        ));
        assert!(has_code(
            &missing,
            PostgresAuthDiagnosticCode::RequiredOptionMissing(PostgresHbaOption::RadiusSecrets)
        ));

        let valid_options = [
            option("radiusservers", "one.example,two.example"),
            option("radiussecrets", "OneSecret,TwoSecret"),
            option("radiusports", "1812"),
            option("radiusidentifiers", "one,two"),
        ];
        let valid = host_record("radius", &valid_options);
        assert!(
            !POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&valid)
                .unwrap()
                .has_invalid()
        );

        let invalid_options = [
            option("radiusservers", "one.example,two.example"),
            option("radiussecrets", "one,two,three"),
        ];
        let invalid = host_record("radius", &invalid_options);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&invalid)
                .unwrap(),
            PostgresAuthDiagnosticCode::RadiusCardinalityMismatch {
                option: PostgresHbaOption::RadiusSecrets,
                servers: 2,
                values: 3,
            }
        ));
        assert!(!format!("{valid_options:?}").contains("OneSecret"));
        assert!(!format!("{invalid_options:?}").contains("three"));
    }

    #[test]
    fn oauth_requires_issuer_scope_and_rejects_map_delegation_pair() {
        let empty = hostssl_record("oauth", &[]);
        let empty = POSTGRESQL_HBA_18_SCHEMA
            .validate_hba_record(&empty)
            .unwrap();
        assert!(has_code(
            &empty,
            PostgresAuthDiagnosticCode::RequiredOptionMissing(PostgresHbaOption::Issuer)
        ));
        assert!(has_code(
            &empty,
            PostgresAuthDiagnosticCode::RequiredOptionMissing(PostgresHbaOption::Scope)
        ));

        let options = [
            option(
                "issuer",
                "https://issuer.example/.well-known/openid-configuration",
            ),
            option("scope", "openid profile"),
            option("map", "oauth-map"),
            option("delegate_ident_mapping", "1"),
        ];
        let conflicting = hostssl_record("oauth", &options);
        assert!(has_code(
            &POSTGRESQL_HBA_18_SCHEMA
                .validate_hba_record(&conflicting)
                .unwrap(),
            PostgresAuthDiagnosticCode::OAuthMapConflictsWithDelegation
        ));

        let valid_options = [
            option("issuer", "https://issuer.example"),
            option("scope", "openid"),
            option("delegate_ident_mapping", "0"),
        ];
        let valid = hostssl_record("oauth", &valid_options);
        let valid = POSTGRESQL_HBA_18_SCHEMA
            .validate_hba_record(&valid)
            .unwrap();
        assert!(!valid.has_invalid());
        assert_eq!(
            valid.status(),
            PostgresAuthValidationStatus::TargetDependent
        );
        assert!(has_code(
            &valid,
            PostgresAuthDiagnosticCode::OAuthValidatorSelectionDependsOnTarget
        ));

        let pg17 = POSTGRESQL_HBA_17_SCHEMA
            .validate_hba_record(&hostssl_record("oauth", &valid_options))
            .unwrap();
        assert!(has_code(
            &pg17,
            PostgresAuthDiagnosticCode::MethodUnavailableInVersion(PostgresHbaAuthMethod::OAuth)
        ));
    }

    #[test]
    fn unknown_method_and_option_remain_visible_without_opaque_failure() {
        assert_eq!(
            POSTGRESQL_HBA_18_SCHEMA.lookup_hba_method("vendor_auth"),
            Ok(PostgresHbaMethodLookup::VisibleUnknown)
        );
        assert_eq!(
            POSTGRESQL_HBA_18_SCHEMA.lookup_hba_option("vendor_option"),
            Ok(PostgresHbaOptionLookup::TargetDependent)
        );
        let unknown_options = [option("vendor_option", "NeverShownInDebug")];
        let record = host_record("vendor_auth", &unknown_options);
        let validation = POSTGRESQL_HBA_18_SCHEMA
            .validate_hba_record(&record)
            .unwrap();
        assert!(!validation.has_invalid());
        assert_eq!(
            validation.status(),
            PostgresAuthValidationStatus::VisibleUnknown
        );
        assert!(has_code(
            &validation,
            PostgresAuthDiagnosticCode::UnknownMethod
        ));
        assert!(has_code(
            &validation,
            PostgresAuthDiagnosticCode::UnknownOption
        ));
        assert!(!format!("{unknown_options:?}").contains("NeverShownInDebug"));
    }

    #[test]
    fn ident_shape_is_three_nonempty_fields_and_wrong_artifact_fails_closed() {
        let valid = PostgresIdentRecordInput {
            map_name: "team-map",
            system_user: "/^(.*)@example\\.com$",
            database_user: "\\1",
        };
        assert_eq!(
            POSTGRESQL_IDENT_18_SCHEMA
                .validate_ident_record(&valid)
                .unwrap()
                .status(),
            PostgresAuthValidationStatus::StaticValid
        );
        let invalid = PostgresIdentRecordInput {
            map_name: "",
            ..valid
        };
        assert!(
            POSTGRESQL_IDENT_18_SCHEMA
                .validate_ident_record(&invalid)
                .unwrap()
                .has_invalid()
        );
        assert!(matches!(
            POSTGRESQL_HBA_18_SCHEMA.validate_ident_record(&valid),
            Err(PostgresAuthArtifactError::WrongArtifact { .. })
        ));
    }

    #[test]
    fn raw_secret_input_is_zeroizing_and_debug_reports_presence_only() {
        let ldap_secret = PostgresHbaOptionInput::new(
            "ldapbindpasswd",
            Zeroizing::new("LdapNeverLeak".to_owned()),
        )
        .unwrap();
        let radius_secret = PostgresHbaOptionInput::new(
            "radiussecrets",
            Zeroizing::new("RadiusNeverLeak".to_owned()),
        )
        .unwrap();
        for (input, secret) in [
            (&ldap_secret, "LdapNeverLeak"),
            (&radius_secret, "RadiusNeverLeak"),
        ] {
            let debug = format!("{input:?}");
            assert!(!debug.contains(secret));
            assert!(debug.contains("Supplied"));
        }
        let presence =
            PostgresHbaOptionInput::secret_present(PostgresHbaSecretOption::LdapBindPasswd);
        assert_eq!(
            presence.value_presence(),
            PostgresHbaOptionValuePresence::SecretPresent
        );
        assert!(presence.raw_value().is_none());
    }
}
