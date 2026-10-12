//! The generator's one search box, answered from core's reviewed goals.
//!
//! A sentence finds closed recipes, multi-step database goals, reviewed
//! database parameters and files, and products that cannot yet do what was
//! asked, each with the reason. A typed assignment such as
//! `PostgreSQL 16 max_connections = 300` is never fuzzy-searched: core either
//! resolves it to one exact parameter, offers the exact candidates, or
//! refuses it with a typed reason. A resolved assignment is held here under a
//! lease until it is confirmed; the value itself is only echoed once core has
//! normalised it for a public parameter, and a refusal never repeats it.

use lovelyhawk_core::{
    configuration_goal::{
        ConfigurationGoalAvailability, ConfigurationGoalMatch, ConfigurationGoalSearchError,
        ConfigurationGoalSubject, ConfigurationGoalSupportGap, DatabaseParameterAssignment,
        DatabaseParameterAssignmentAmbiguity, DatabaseParameterAssignmentError,
        DatabaseParameterGoalDraftError, database_goal_resolutions_for_version,
        database_parameter_goal_availability, search_configuration_goals,
    },
    database_config::{DatabaseConfigProduct, artifacts_for},
    database_config_schema::{DATABASE_CONFIG_SCHEMAS, DatabaseConfigSchema},
    middleware::MiddlewareProduct,
    visual_document::{
        DatabaseAssignmentPreflightError, DatabaseParameterStageError, database_artifact_by_key,
        database_artifact_display_label, database_visual_parser, schema_value_kind_description,
    },
};
use serde::Serialize;

use crate::config_visual_api::{
    ConfigVisualSchemaDto, activation_key, database_product_definition, risk_key, schema_dto,
};

/// More results than this would not be read; the page says the list is cut.
const MAX_GOAL_RESULTS: usize = 80;
/// One goal can read differently for each reviewed version; a few are enough.
const MAX_RESOLUTIONS_PER_GOAL: usize = 6;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfigGoalSearchDto {
    /// Present when the sentence is an assignment; then there are no results.
    pub(crate) assignment: Option<GoalAssignmentDto>,
    pub(crate) results: Vec<GoalResultDto>,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GoalAssignmentDto {
    /// Names the held assignment; only the latest one can be chosen or confirmed.
    pub(crate) lease: Option<String>,
    /// "ready", "ambiguous" or "rejected".
    pub(crate) state: &'static str,
    pub(crate) target: Option<GoalTargetDto>,
    /// The value as core normalised it, for a ready public parameter only.
    pub(crate) value: Option<String>,
    /// Where a confirmed value would go: "open-draft" or "new-draft".
    pub(crate) landing: Option<&'static str>,
    /// Why confirming now would be refused, found before anything changes.
    pub(crate) blocked: Option<&'static str>,
    pub(crate) candidates: Vec<GoalTargetDto>,
    pub(crate) rejection: Option<&'static str>,
}

/// One reviewed parameter of one reviewed version of one file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GoalTargetDto {
    pub(crate) product: &'static str,
    pub(crate) product_label: &'static str,
    pub(crate) artifact_key: &'static str,
    pub(crate) file_label: &'static str,
    pub(crate) schema: ConfigVisualSchemaDto,
    pub(crate) parameter_index: usize,
    pub(crate) key: &'static str,
    pub(crate) group: Option<&'static str>,
    pub(crate) value_domain: String,
    pub(crate) activation: &'static str,
    pub(crate) risk: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GoalStepDto {
    pub(crate) title: &'static str,
    pub(crate) explanation: &'static str,
    pub(crate) required: bool,
    /// The reviewed parameters of the version that serve this step; none
    /// means the step happens outside this file.
    pub(crate) parameters: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum GoalResultDto {
    /// A closed recipe the generator can draft.
    Recipe {
        key: &'static str,
        product: &'static str,
        product_label: &'static str,
        title: &'static str,
        summary: &'static str,
        effect: &'static str,
    },
    /// A database goal of several steps, as one reviewed version reads it.
    DatabaseGoal {
        key: &'static str,
        product: &'static str,
        product_label: &'static str,
        title: &'static str,
        summary: &'static str,
        artifact_key: &'static str,
        file_label: &'static str,
        schema: ConfigVisualSchemaDto,
        steps: Vec<GoalStepDto>,
        missing_required: usize,
        gap: Option<&'static str>,
    },
    /// One reviewed parameter, and whether a value can be drafted for it.
    DatabaseParameter {
        target: GoalTargetDto,
        draftable: bool,
        gap: Option<&'static str>,
    },
    /// A catalogued configuration file of a database product.
    DatabaseFile {
        product: &'static str,
        product_label: &'static str,
        artifact_key: &'static str,
        file_label: &'static str,
        opens: bool,
        read_only: bool,
        gap: Option<&'static str>,
    },
    /// A product that was named but cannot do this yet, and why.
    Unavailable {
        subject: &'static str,
        family: &'static str,
        recipes: usize,
        parameters: usize,
        files: usize,
        gap: &'static str,
    },
}

/// The document a search or a confirmation is made against, as the page
/// shows it: which one, at which revision, and whether it has unsaved edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoalBinding {
    pub(crate) handle: String,
    pub(crate) revision: u64,
}

/// The one assignment held for confirmation. A new search replaces it.
#[derive(Default)]
pub(crate) struct PendingGoal {
    pub(crate) lease: Option<String>,
    pub(crate) state: PendingGoalState,
}

#[derive(Default)]
pub(crate) enum PendingGoalState {
    #[default]
    Empty,
    Ready {
        assignment: DatabaseParameterAssignment,
        binding: Option<GoalBinding>,
    },
    Ambiguous {
        ambiguity: DatabaseParameterAssignmentAmbiguity,
    },
    /// Confirmed once; the same lease never applies twice.
    Consumed,
}

impl std::fmt::Debug for PendingGoal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match &self.state {
            PendingGoalState::Empty => "empty",
            PendingGoalState::Ready { .. } => "ready",
            PendingGoalState::Ambiguous { .. } => "ambiguous",
            PendingGoalState::Consumed => "consumed",
        };
        formatter
            .debug_struct("PendingGoal")
            .field("leased", &self.lease.is_some())
            .field("state", &state)
            .finish()
    }
}

impl PendingGoal {
    /// Holds a new state under a fresh lease, dropping whatever was held.
    pub(crate) fn hold(&mut self, state: PendingGoalState) -> String {
        let lease = uuid::Uuid::new_v4().to_string();
        self.lease = Some(lease.clone());
        self.state = state;
        lease
    }

    pub(crate) fn clear(&mut self) {
        self.lease = None;
        self.state = PendingGoalState::Empty;
    }

    pub(crate) fn is_current(&self, lease: &str) -> bool {
        self.lease.as_deref() == Some(lease)
    }
}

pub(crate) fn subject_key(product: DatabaseConfigProduct) -> &'static str {
    database_product_definition(product).map_or("unknown", |definition| definition.key)
}

pub(crate) fn subject_label(product: DatabaseConfigProduct) -> &'static str {
    database_product_definition(product).map_or("数据库", |definition| definition.label)
}

fn middleware_key(product: MiddlewareProduct) -> &'static str {
    match product {
        MiddlewareProduct::Nginx => "nginx",
        MiddlewareProduct::ApacheHttpd => "apache",
        MiddlewareProduct::Redis => "redis",
        MiddlewareProduct::Tomcat => "tomcat",
    }
}

fn middleware_label(product: MiddlewareProduct) -> &'static str {
    match product {
        MiddlewareProduct::ApacheHttpd => "Apache httpd",
        other => other.label(),
    }
}

fn schema_index(schema: &'static DatabaseConfigSchema) -> usize {
    DATABASE_CONFIG_SCHEMAS
        .iter()
        .position(|candidate| std::ptr::eq(candidate, schema))
        .expect("every schema core hands out is in the registry")
}

pub(crate) fn target_dto(
    schema: &'static DatabaseConfigSchema,
    parameter_index: usize,
) -> GoalTargetDto {
    let parameter = &schema.parameters[parameter_index];
    let artifact = database_artifact_by_key(schema.binding.artifact_key);
    GoalTargetDto {
        product: subject_key(schema.binding.product),
        product_label: subject_label(schema.binding.product),
        artifact_key: schema.binding.artifact_key,
        file_label: artifact.map_or(schema.binding.artifact_key, database_artifact_display_label),
        schema: schema_dto(schema_index(schema), schema),
        parameter_index,
        key: parameter.canonical_key,
        group: parameter.container_path,
        value_domain: schema_value_kind_description(parameter.value_kind),
        activation: activation_key(parameter.activation),
        risk: risk_key(parameter.risk),
    }
}

pub(crate) const fn gap_key(gap: ConfigurationGoalSupportGap) -> &'static str {
    match gap {
        ConfigurationGoalSupportGap::MissingReviewedIntent => "no-reviewed-intent",
        ConfigurationGoalSupportGap::MissingReviewedRecipe => "no-recipe",
        ConfigurationGoalSupportGap::MissingExactSchema => "no-version-catalogue",
        ConfigurationGoalSupportGap::MissingVersion => "version-not-catalogued",
        ConfigurationGoalSupportGap::MissingEditableArtifact => "file-not-editable",
        ConfigurationGoalSupportGap::MissingTypedValidator => "no-value-rules",
        ConfigurationGoalSupportGap::MissingRuntimeCapability => "needs-capability",
        ConfigurationGoalSupportGap::MissingExternalEvidence => "needs-outside-steps",
        ConfigurationGoalSupportGap::SensitiveValue => "secret-value",
    }
}

/// Why an assignment sentence was refused, without its value.
pub(crate) const fn rejection_key(error: DatabaseParameterAssignmentError) -> &'static str {
    match error {
        DatabaseParameterAssignmentError::QueryTooLong
        | DatabaseParameterAssignmentError::InvalidQuery => "query-refused",
        DatabaseParameterAssignmentError::UnsupportedOperator => "unsupported-operator",
        DatabaseParameterAssignmentError::MissingTarget => "missing-target",
        DatabaseParameterAssignmentError::MissingValue => "missing-value",
        DatabaseParameterAssignmentError::MultipleOperators => "multiple-operators",
        DatabaseParameterAssignmentError::MissingProduct => "missing-product",
        DatabaseParameterAssignmentError::AmbiguousProduct => "ambiguous-product",
        DatabaseParameterAssignmentError::InvalidVersion => "invalid-version",
        DatabaseParameterAssignmentError::MissingVersion => "version-not-catalogued",
        DatabaseParameterAssignmentError::MissingExactSchema => "no-version-catalogue",
        DatabaseParameterAssignmentError::MissingParameter => "missing-parameter",
        DatabaseParameterAssignmentError::InvalidQualifier => "invalid-qualifier",
        DatabaseParameterAssignmentError::UnknownArtifact => "unknown-file",
        DatabaseParameterAssignmentError::ArtifactProductMismatch => "file-of-another-product",
        DatabaseParameterAssignmentError::UnknownContainer => "unknown-group",
        DatabaseParameterAssignmentError::UnknownParameter => "unknown-parameter",
        DatabaseParameterAssignmentError::UnknownCandidate => "unknown-candidate",
        DatabaseParameterAssignmentError::TooManyCandidates => "too-many-candidates",
        DatabaseParameterAssignmentError::Draft(error) => draft_rejection_key(error),
    }
}

pub(crate) const fn draft_rejection_key(error: DatabaseParameterGoalDraftError) -> &'static str {
    match error {
        DatabaseParameterGoalDraftError::SchemaUnavailable
        | DatabaseParameterGoalDraftError::UnknownParameter => "no-version-catalogue",
        DatabaseParameterGoalDraftError::ArtifactUnavailable
        | DatabaseParameterGoalDraftError::ArtifactBindingMismatch
        | DatabaseParameterGoalDraftError::ReadOnlyArtifact
        | DatabaseParameterGoalDraftError::UnsupportedDialect => "file-not-editable",
        DatabaseParameterGoalDraftError::NonPublicParameter => "secret-value",
        DatabaseParameterGoalDraftError::RequiredCapability => "needs-capability",
        DatabaseParameterGoalDraftError::VisibleUnvalidated => "no-value-rules",
        DatabaseParameterGoalDraftError::InvalidValue(_)
        | DatabaseParameterGoalDraftError::UnsafeValue => "value-refused",
        DatabaseParameterGoalDraftError::EmptyValueUnsupported => "empty-value",
    }
}

/// Why a resolved assignment cannot go into the draft now.
pub(crate) const fn preflight_key(error: DatabaseAssignmentPreflightError) -> &'static str {
    match error {
        DatabaseAssignmentPreflightError::ArtifactMissing => "file-not-editable",
        DatabaseAssignmentPreflightError::OtherFileUnsaved => "other-file-unsaved",
        DatabaseAssignmentPreflightError::OtherSchemaUnsaved => "other-version-unsaved",
        DatabaseAssignmentPreflightError::Stage(error) => match error {
            DatabaseParameterStageError::Duplicate => "duplicate",
            DatabaseParameterStageError::LineLocked => "line-locked",
            DatabaseParameterStageError::ReadOnly => "file-not-editable",
            DatabaseParameterStageError::AmbiguousGroup => "ambiguous-group",
            DatabaseParameterStageError::ParameterGone
            | DatabaseParameterStageError::NotDatabaseDocument
            | DatabaseParameterStageError::TargetMismatch
            | DatabaseParameterStageError::WriterRefused
            | DatabaseParameterStageError::ReadBackFailed => "writer-refused",
        },
    }
}

/// The fuzzy results for a sentence that is not an assignment.
pub(crate) fn goal_results(
    query: &str,
) -> Result<(Vec<GoalResultDto>, bool), ConfigurationGoalSearchError> {
    let found = search_configuration_goals(query)?;
    let mut truncated = found.truncated();
    let mut results = Vec::new();
    for matched in found.matches() {
        if results.len() >= MAX_GOAL_RESULTS {
            truncated = true;
            break;
        }
        let gap = matched.support_gap().map(gap_key);
        match *matched {
            ConfigurationGoalMatch::Recipe(recipe) => {
                let ConfigurationGoalSubject::Middleware(product) = recipe.subject else {
                    continue;
                };
                results.push(GoalResultDto::Recipe {
                    key: recipe.key,
                    product: middleware_key(product),
                    product_label: middleware_label(product),
                    title: recipe.title,
                    summary: recipe.summary,
                    effect: recipe.expected_effect,
                });
            }
            ConfigurationGoalMatch::DatabaseGoal {
                goal,
                product,
                version,
            } => {
                let resolutions = database_goal_resolutions_for_version(goal, product, version);
                if resolutions.len() > MAX_RESOLUTIONS_PER_GOAL {
                    truncated = true;
                }
                for resolution in resolutions.iter().take(MAX_RESOLUTIONS_PER_GOAL) {
                    let schema = resolution.schema();
                    results.push(GoalResultDto::DatabaseGoal {
                        key: goal.key,
                        product: subject_key(product),
                        product_label: subject_label(product),
                        title: goal.title,
                        summary: goal.summary,
                        artifact_key: schema.binding.artifact_key,
                        file_label: database_artifact_by_key(schema.binding.artifact_key)
                            .map_or(schema.binding.artifact_key, database_artifact_display_label),
                        schema: schema_dto(schema_index(schema), schema),
                        steps: resolution
                            .steps()
                            .iter()
                            .map(|step| GoalStepDto {
                                title: step.definition().title,
                                explanation: step.definition().explanation,
                                required: step.definition().required,
                                parameters: step
                                    .parameter_indices()
                                    .iter()
                                    .map(|index| schema.parameters[*index].canonical_key)
                                    .collect(),
                            })
                            .collect(),
                        missing_required: resolution.missing_required_count(),
                        gap,
                    });
                }
            }
            ConfigurationGoalMatch::DatabaseParameter {
                schema,
                parameter_index,
            } => results.push(GoalResultDto::DatabaseParameter {
                target: target_dto(schema, parameter_index),
                draftable: database_parameter_goal_availability(schema, parameter_index)
                    == ConfigurationGoalAvailability::LocalDraftRecipe,
                gap,
            }),
            ConfigurationGoalMatch::DatabaseArtifact { artifact } => {
                results.push(GoalResultDto::DatabaseFile {
                    product: subject_key(artifact.product),
                    product_label: subject_label(artifact.product),
                    artifact_key: artifact.key,
                    file_label: database_artifact_display_label(artifact),
                    opens: database_visual_parser(artifact).is_some(),
                    read_only: !artifact.allows_lossless_local_draft(),
                    gap,
                });
            }
            ConfigurationGoalMatch::UnavailableSubject { coverage, gap } => {
                let (subject, family, files) = match coverage.subject {
                    ConfigurationGoalSubject::Middleware(product) => {
                        (middleware_label(product), "middleware", 0)
                    }
                    ConfigurationGoalSubject::Database(product) => (
                        subject_label(product),
                        "database",
                        artifacts_for(product).count(),
                    ),
                };
                results.push(GoalResultDto::Unavailable {
                    subject,
                    family,
                    recipes: coverage.reviewed_recipes,
                    parameters: coverage.reviewed_parameters,
                    files,
                    gap: gap_key(gap),
                });
            }
        }
    }
    Ok((results, truncated))
}
