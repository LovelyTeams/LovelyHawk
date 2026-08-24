//! Bounded, target-bound provenance and precedence for database configuration sources.
//!
//! This module records already-observed source facts. It performs no discovery,
//! file access, command execution, runtime query, or vendor precedence inference.
//! A file is therefore never treated as effective merely because it was found.

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    database_config::{DatabaseConfigComponent, DatabaseConfigProduct, artifact_by_key},
    target::TargetGuard,
};

pub const MAX_DATABASE_CONFIG_SOURCE_NODES: usize = 128;
pub const MAX_DATABASE_CONFIG_SOURCE_RELATIONS: usize = 4_096;
pub const MAX_DATABASE_CONFIG_SOURCE_BARRIERS: usize = 128;
pub const MAX_DATABASE_CONFIG_SOURCE_DEPTH: usize = 64;
pub const MAX_DATABASE_CONFIG_SOURCE_LABEL_BYTES: usize = 1_024;
pub const MAX_DATABASE_CONFIG_SOURCE_REVISION_BYTES: usize = 1_024;
pub const MAX_DATABASE_CONFIG_SOURCE_VALUE_BYTES: usize = 64 * 1_024;
pub const MAX_DATABASE_CONFIG_SOURCE_TOTAL_TEXT_BYTES: usize = 4 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DatabaseConfigSourceKind {
    File,
    IncludedFile,
    CommandLine,
    Environment,
    ServiceManager,
    RuntimePersisted,
    RuntimeEphemeral,
    ToolManaged,
    CloudControlPlane,
    GeneratedState,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigSourceBinding {
    target: TargetGuard,
    product: DatabaseConfigProduct,
    component: DatabaseConfigComponent,
    artifact_key: &'static str,
}

impl fmt::Debug for DatabaseConfigSourceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSourceBinding")
            .field("target_identity", &"<omitted>")
            .field("target_generation", &self.target.generation)
            .field("product", &self.product)
            .field("component", &self.component)
            .field("artifact_key", &self.artifact_key)
            .finish()
    }
}

impl DatabaseConfigSourceBinding {
    pub fn new(
        target: TargetGuard,
        product: DatabaseConfigProduct,
        component: DatabaseConfigComponent,
        artifact_key: &str,
    ) -> Result<Self, DatabaseConfigSourceError> {
        let artifact =
            artifact_by_key(artifact_key).ok_or(DatabaseConfigSourceError::ArtifactUnknown)?;
        if artifact.product != product {
            return Err(DatabaseConfigSourceError::ArtifactProductMismatch);
        }
        if artifact.component != component {
            return Err(DatabaseConfigSourceError::ArtifactComponentMismatch);
        }
        Ok(Self {
            target,
            product,
            component,
            artifact_key: artifact.key,
        })
    }

    pub const fn target(&self) -> &TargetGuard {
        &self.target
    }

    pub const fn product(&self) -> DatabaseConfigProduct {
        self.product
    }

    pub const fn component(&self) -> DatabaseConfigComponent {
        self.component
    }

    pub const fn artifact_key(&self) -> &'static str {
        self.artifact_key
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DatabaseConfigSourceNodeId(u32);

impl DatabaseConfigSourceNodeId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Exact observation identity for one source. Labels, revisions, and digests
/// may expose paths, instance metadata, or low-entropy material, so `Debug`
/// reports only their shape.
#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigSourceOrigin {
    label: Zeroizing<String>,
    content_digest: Option<[u8; 32]>,
    revision: Option<Zeroizing<String>>,
}

impl fmt::Debug for DatabaseConfigSourceOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSourceOrigin")
            .field("label_bytes", &self.label.len())
            .field("has_content_digest", &self.content_digest.is_some())
            .field("has_revision", &self.revision.is_some())
            .finish()
    }
}

impl DatabaseConfigSourceOrigin {
    pub fn from_content_digest(
        label: impl Into<String>,
        content_digest: [u8; 32],
    ) -> Result<Self, DatabaseConfigSourceError> {
        Self::new(label.into(), Some(content_digest), None)
    }

    pub fn from_revision(
        label: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, DatabaseConfigSourceError> {
        Self::new(label.into(), None, Some(revision.into()))
    }

    pub fn from_content_digest_and_revision(
        label: impl Into<String>,
        content_digest: [u8; 32],
        revision: impl Into<String>,
    ) -> Result<Self, DatabaseConfigSourceError> {
        Self::new(label.into(), Some(content_digest), Some(revision.into()))
    }

    fn new(
        label: String,
        content_digest: Option<[u8; 32]>,
        revision: Option<String>,
    ) -> Result<Self, DatabaseConfigSourceError> {
        if !valid_display_text(&label, MAX_DATABASE_CONFIG_SOURCE_LABEL_BYTES) {
            return Err(DatabaseConfigSourceError::InvalidText {
                field: DatabaseConfigSourceTextField::OriginLabel,
            });
        }
        if revision.as_deref().is_some_and(|revision| {
            !valid_display_text(revision, MAX_DATABASE_CONFIG_SOURCE_REVISION_BYTES)
        }) {
            return Err(DatabaseConfigSourceError::InvalidText {
                field: DatabaseConfigSourceTextField::Revision,
            });
        }
        Ok(Self {
            label: Zeroizing::new(label),
            content_digest,
            revision: revision.map(Zeroizing::new),
        })
    }

    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    pub const fn content_digest(&self) -> Option<&[u8; 32]> {
        self.content_digest.as_ref()
    }

    pub fn revision(&self) -> Option<&str> {
        self.revision.as_ref().map(|revision| revision.as_str())
    }

    fn text_bytes(&self) -> usize {
        self.label.len() + self.revision.as_ref().map_or(0, |revision| revision.len())
    }
}

/// An observed configuration value. The raw value remains explicitly
/// accessible to core consumers but is always omitted from diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigSourceValue(Zeroizing<String>);

impl fmt::Debug for DatabaseConfigSourceValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSourceValue")
            .field("bytes", &self.0.len())
            .field("value", &"<omitted>")
            .finish()
    }
}

impl DatabaseConfigSourceValue {
    pub fn new(value: impl Into<String>) -> Result<Self, DatabaseConfigSourceError> {
        let value = value.into();
        if value.len() > MAX_DATABASE_CONFIG_SOURCE_VALUE_BYTES {
            return Err(DatabaseConfigSourceError::ValueTooLong);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Returns hostile plain text. Callers must not reinterpret it as markup,
    /// a path, an action identifier, or a command.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigSourceNode {
    id: DatabaseConfigSourceNodeId,
    binding: DatabaseConfigSourceBinding,
    kind: DatabaseConfigSourceKind,
    origin: DatabaseConfigSourceOrigin,
    value: Option<DatabaseConfigSourceValue>,
}

impl fmt::Debug for DatabaseConfigSourceNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSourceNode")
            .field("id", &self.id)
            .field("binding", &self.binding)
            .field("kind", &self.kind)
            .field("origin", &self.origin)
            .field("has_value", &self.value.is_some())
            .field(
                "value_bytes",
                &self.value.as_ref().map(DatabaseConfigSourceValue::len),
            )
            .finish()
    }
}

impl DatabaseConfigSourceNode {
    pub fn metadata_only(
        id: DatabaseConfigSourceNodeId,
        binding: DatabaseConfigSourceBinding,
        kind: DatabaseConfigSourceKind,
        origin: DatabaseConfigSourceOrigin,
    ) -> Self {
        Self {
            id,
            binding,
            kind,
            origin,
            value: None,
        }
    }

    pub fn observed(
        id: DatabaseConfigSourceNodeId,
        binding: DatabaseConfigSourceBinding,
        kind: DatabaseConfigSourceKind,
        origin: DatabaseConfigSourceOrigin,
        value: DatabaseConfigSourceValue,
    ) -> Self {
        Self {
            id,
            binding,
            kind,
            origin,
            value: Some(value),
        }
    }

    pub const fn id(&self) -> DatabaseConfigSourceNodeId {
        self.id
    }

    pub const fn binding(&self) -> &DatabaseConfigSourceBinding {
        &self.binding
    }

    pub const fn kind(&self) -> DatabaseConfigSourceKind {
        self.kind
    }

    pub const fn origin(&self) -> &DatabaseConfigSourceOrigin {
        &self.origin
    }

    pub const fn value(&self) -> Option<&DatabaseConfigSourceValue> {
        self.value.as_ref()
    }

    fn text_bytes(&self) -> usize {
        self.origin.text_bytes()
            + self
                .value
                .as_ref()
                .map_or(0, DatabaseConfigSourceValue::len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourcePrecedence {
    /// The left source has strictly higher precedence than the right source.
    Higher,
    /// The left source has strictly lower precedence than the right source.
    Lower,
    /// Both sources have the same proven precedence.
    Equal,
    /// Available evidence cannot order the two sources.
    Unknown,
    /// Available evidence is contradictory.
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseConfigSourceRelation {
    left: DatabaseConfigSourceNodeId,
    right: DatabaseConfigSourceNodeId,
    precedence: DatabaseConfigSourcePrecedence,
}

impl DatabaseConfigSourceRelation {
    pub const fn new(
        left: DatabaseConfigSourceNodeId,
        right: DatabaseConfigSourceNodeId,
        precedence: DatabaseConfigSourcePrecedence,
    ) -> Self {
        Self {
            left,
            right,
            precedence,
        }
    }

    pub const fn left(self) -> DatabaseConfigSourceNodeId {
        self.left
    }

    pub const fn right(self) -> DatabaseConfigSourceNodeId {
        self.right
    }

    pub const fn precedence(self) -> DatabaseConfigSourcePrecedence {
        self.precedence
    }
}

/// An expected source that could not be resolved. Its sensitive label may be
/// an include path, tool key, unit name, or control-plane resource identifier.
#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseConfigSourceBarrier {
    binding: DatabaseConfigSourceBinding,
    expected_kind: DatabaseConfigSourceKind,
    label: Zeroizing<String>,
}

impl fmt::Debug for DatabaseConfigSourceBarrier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSourceBarrier")
            .field("binding", &self.binding)
            .field("expected_kind", &self.expected_kind)
            .field("label_bytes", &self.label.len())
            .finish()
    }
}

impl DatabaseConfigSourceBarrier {
    pub fn unresolved(
        binding: DatabaseConfigSourceBinding,
        expected_kind: DatabaseConfigSourceKind,
        label: impl Into<String>,
    ) -> Result<Self, DatabaseConfigSourceError> {
        let label = label.into();
        if !valid_display_text(&label, MAX_DATABASE_CONFIG_SOURCE_LABEL_BYTES) {
            return Err(DatabaseConfigSourceError::InvalidText {
                field: DatabaseConfigSourceTextField::BarrierLabel,
            });
        }
        Ok(Self {
            binding,
            expected_kind,
            label: Zeroizing::new(label),
        })
    }

    pub const fn binding(&self) -> &DatabaseConfigSourceBinding {
        &self.binding
    }

    pub const fn expected_kind(&self) -> DatabaseConfigSourceKind {
        self.expected_kind
    }

    pub fn label(&self) -> &str {
        self.label.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourceCoverage {
    NotRun,
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourcePartialReason {
    DiscoveryIncomplete,
    UnresolvedBarrier,
    UnknownPrecedence,
    NoSources,
    IncomparableSources,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourceBlockedReason {
    ConflictingPrecedence,
    EqualPrecedenceValuesDiffer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseConfigEffectiveSources {
    source_ids: Vec<DatabaseConfigSourceNodeId>,
}

impl DatabaseConfigEffectiveSources {
    pub fn source_ids(&self) -> &[DatabaseConfigSourceNodeId] {
        &self.source_ids
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourceProjection {
    NotRun,
    Partial(DatabaseConfigSourcePartialReason),
    Blocked(DatabaseConfigSourceBlockedReason),
    Effective(DatabaseConfigEffectiveSources),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourceTextField {
    OriginLabel,
    Revision,
    BarrierLabel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourceMemberKind {
    Node,
    Barrier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseConfigSourceError {
    ArtifactUnknown,
    ArtifactProductMismatch,
    ArtifactComponentMismatch,
    InvalidText {
        field: DatabaseConfigSourceTextField,
    },
    ValueTooLong,
    TooManyNodes,
    TooManyRelations,
    TooManyBarriers,
    TotalTextTooLarge,
    NotRunContainsEvidence,
    TargetMismatch {
        member: DatabaseConfigSourceMemberKind,
        index: usize,
    },
    BindingMismatch {
        member: DatabaseConfigSourceMemberKind,
        index: usize,
    },
    DuplicateNodeId {
        first_node_index: usize,
        duplicate_node_index: usize,
    },
    DuplicateSource {
        first_node_index: usize,
        duplicate_node_index: usize,
    },
    DuplicateBarrier {
        first_barrier_index: usize,
        duplicate_barrier_index: usize,
    },
    SelfRelation {
        relation_index: usize,
    },
    UnknownRelationEndpoint {
        relation_index: usize,
    },
    DuplicateRelation {
        first_relation_index: usize,
        duplicate_relation_index: usize,
    },
    StrictRelationWithinEqualSet {
        relation_index: usize,
    },
    Cycle,
    DepthExceeded,
}

#[derive(Clone)]
pub struct DatabaseConfigSourceGraph {
    binding: DatabaseConfigSourceBinding,
    coverage: DatabaseConfigSourceCoverage,
    nodes: Vec<DatabaseConfigSourceNode>,
    relations: Vec<DatabaseConfigSourceRelation>,
    barriers: Vec<DatabaseConfigSourceBarrier>,
    normalized: NormalizedPrecedence,
}

impl fmt::Debug for DatabaseConfigSourceGraph {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfigSourceGraph")
            .field("binding", &self.binding)
            .field("coverage", &self.coverage)
            .field("nodes", &self.nodes)
            .field("relations", &self.relations)
            .field("barriers", &self.barriers)
            .finish()
    }
}

impl DatabaseConfigSourceGraph {
    pub fn new(
        binding: DatabaseConfigSourceBinding,
        coverage: DatabaseConfigSourceCoverage,
        nodes: Vec<DatabaseConfigSourceNode>,
        relations: Vec<DatabaseConfigSourceRelation>,
        barriers: Vec<DatabaseConfigSourceBarrier>,
    ) -> Result<Self, DatabaseConfigSourceError> {
        if nodes.len() > MAX_DATABASE_CONFIG_SOURCE_NODES {
            return Err(DatabaseConfigSourceError::TooManyNodes);
        }
        if relations.len() > MAX_DATABASE_CONFIG_SOURCE_RELATIONS {
            return Err(DatabaseConfigSourceError::TooManyRelations);
        }
        if barriers.len() > MAX_DATABASE_CONFIG_SOURCE_BARRIERS {
            return Err(DatabaseConfigSourceError::TooManyBarriers);
        }
        if coverage == DatabaseConfigSourceCoverage::NotRun
            && (!nodes.is_empty() || !relations.is_empty() || !barriers.is_empty())
        {
            return Err(DatabaseConfigSourceError::NotRunContainsEvidence);
        }

        validate_member_bindings(&binding, &nodes, &barriers)?;
        validate_duplicates(&nodes, &barriers)?;
        validate_relations(&nodes, &relations)?;
        validate_total_text(&nodes, &barriers)?;
        let normalized = normalize_precedence(&nodes, &relations)?;

        Ok(Self {
            binding,
            coverage,
            nodes,
            relations,
            barriers,
            normalized,
        })
    }

    pub const fn binding(&self) -> &DatabaseConfigSourceBinding {
        &self.binding
    }

    pub const fn coverage(&self) -> DatabaseConfigSourceCoverage {
        self.coverage
    }

    pub fn nodes(&self) -> &[DatabaseConfigSourceNode] {
        &self.nodes
    }

    pub fn relations(&self) -> &[DatabaseConfigSourceRelation] {
        &self.relations
    }

    pub fn barriers(&self) -> &[DatabaseConfigSourceBarrier] {
        &self.barriers
    }

    pub fn node(&self, id: DatabaseConfigSourceNodeId) -> Option<&DatabaseConfigSourceNode> {
        self.nodes.iter().find(|node| node.id == id)
    }

    pub fn effective_projection(&self) -> DatabaseConfigSourceProjection {
        if self.coverage == DatabaseConfigSourceCoverage::NotRun {
            return DatabaseConfigSourceProjection::NotRun;
        }
        if self
            .relations
            .iter()
            .any(|relation| relation.precedence == DatabaseConfigSourcePrecedence::Conflict)
        {
            return DatabaseConfigSourceProjection::Blocked(
                DatabaseConfigSourceBlockedReason::ConflictingPrecedence,
            );
        }
        if !self.barriers.is_empty() {
            return DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::UnresolvedBarrier,
            );
        }
        if self.coverage == DatabaseConfigSourceCoverage::Partial {
            return DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::DiscoveryIncomplete,
            );
        }
        if self
            .relations
            .iter()
            .any(|relation| relation.precedence == DatabaseConfigSourcePrecedence::Unknown)
        {
            return DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::UnknownPrecedence,
            );
        }
        if self.nodes.is_empty() {
            return DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::NoSources,
            );
        }

        let reachable = transitive_closure(&self.normalized.adjacency);
        for (left, left_reachable) in reachable.iter().enumerate() {
            for (right, right_reachable) in reachable.iter().enumerate().skip(left + 1) {
                if !left_reachable[right] && !right_reachable[left] {
                    return DatabaseConfigSourceProjection::Partial(
                        DatabaseConfigSourcePartialReason::IncomparableSources,
                    );
                }
            }
        }

        let highest_class = (0..self.normalized.class_count)
            .find(|candidate| {
                (0..self.normalized.class_count)
                    .all(|other| other == *candidate || !reachable[other][*candidate])
            })
            .expect("a non-empty acyclic total precedence has a highest class");
        let source_indices = self
            .normalized
            .class_of
            .iter()
            .enumerate()
            .filter_map(|(index, class)| (*class == highest_class).then_some(index))
            .collect::<Vec<_>>();
        let first_value = &self.nodes[source_indices[0]].value;
        if source_indices
            .iter()
            .skip(1)
            .any(|index| self.nodes[*index].value != *first_value)
        {
            return DatabaseConfigSourceProjection::Blocked(
                DatabaseConfigSourceBlockedReason::EqualPrecedenceValuesDiffer,
            );
        }

        DatabaseConfigSourceProjection::Effective(DatabaseConfigEffectiveSources {
            source_ids: source_indices
                .into_iter()
                .map(|index| self.nodes[index].id)
                .collect(),
        })
    }
}

#[derive(Clone)]
struct NormalizedPrecedence {
    class_count: usize,
    class_of: Vec<usize>,
    /// Directed from higher precedence to lower precedence.
    adjacency: Vec<Vec<bool>>,
}

fn validate_member_bindings(
    binding: &DatabaseConfigSourceBinding,
    nodes: &[DatabaseConfigSourceNode],
    barriers: &[DatabaseConfigSourceBarrier],
) -> Result<(), DatabaseConfigSourceError> {
    for (index, node) in nodes.iter().enumerate() {
        validate_member_binding(
            binding,
            &node.binding,
            DatabaseConfigSourceMemberKind::Node,
            index,
        )?;
    }
    for (index, barrier) in barriers.iter().enumerate() {
        validate_member_binding(
            binding,
            &barrier.binding,
            DatabaseConfigSourceMemberKind::Barrier,
            index,
        )?;
    }
    Ok(())
}

fn validate_member_binding(
    expected: &DatabaseConfigSourceBinding,
    actual: &DatabaseConfigSourceBinding,
    member: DatabaseConfigSourceMemberKind,
    index: usize,
) -> Result<(), DatabaseConfigSourceError> {
    if actual.target != expected.target {
        return Err(DatabaseConfigSourceError::TargetMismatch { member, index });
    }
    if actual.product != expected.product
        || actual.component != expected.component
        || actual.artifact_key != expected.artifact_key
    {
        return Err(DatabaseConfigSourceError::BindingMismatch { member, index });
    }
    Ok(())
}

fn validate_duplicates(
    nodes: &[DatabaseConfigSourceNode],
    barriers: &[DatabaseConfigSourceBarrier],
) -> Result<(), DatabaseConfigSourceError> {
    for (duplicate_node_index, node) in nodes.iter().enumerate() {
        if let Some(first_node_index) = nodes[..duplicate_node_index]
            .iter()
            .position(|candidate| candidate.id == node.id)
        {
            return Err(DatabaseConfigSourceError::DuplicateNodeId {
                first_node_index,
                duplicate_node_index,
            });
        }
        if let Some(first_node_index) = nodes[..duplicate_node_index].iter().position(|candidate| {
            candidate.kind == node.kind && candidate.origin.label == node.origin.label
        }) {
            return Err(DatabaseConfigSourceError::DuplicateSource {
                first_node_index,
                duplicate_node_index,
            });
        }
    }
    for (duplicate_barrier_index, barrier) in barriers.iter().enumerate() {
        if let Some(first_barrier_index) =
            barriers[..duplicate_barrier_index]
                .iter()
                .position(|candidate| {
                    candidate.expected_kind == barrier.expected_kind
                        && candidate.label == barrier.label
                })
        {
            return Err(DatabaseConfigSourceError::DuplicateBarrier {
                first_barrier_index,
                duplicate_barrier_index,
            });
        }
    }
    Ok(())
}

fn validate_relations(
    nodes: &[DatabaseConfigSourceNode],
    relations: &[DatabaseConfigSourceRelation],
) -> Result<(), DatabaseConfigSourceError> {
    for (relation_index, relation) in relations.iter().enumerate() {
        if relation.left == relation.right {
            return Err(DatabaseConfigSourceError::SelfRelation { relation_index });
        }
        if node_index(nodes, relation.left).is_none() || node_index(nodes, relation.right).is_none()
        {
            return Err(DatabaseConfigSourceError::UnknownRelationEndpoint { relation_index });
        }
        if let Some(first_relation_index) = relations[..relation_index]
            .iter()
            .position(|candidate| same_unordered_pair(*candidate, *relation))
        {
            return Err(DatabaseConfigSourceError::DuplicateRelation {
                first_relation_index,
                duplicate_relation_index: relation_index,
            });
        }
    }
    Ok(())
}

fn same_unordered_pair(
    first: DatabaseConfigSourceRelation,
    second: DatabaseConfigSourceRelation,
) -> bool {
    (first.left == second.left && first.right == second.right)
        || (first.left == second.right && first.right == second.left)
}

fn validate_total_text(
    nodes: &[DatabaseConfigSourceNode],
    barriers: &[DatabaseConfigSourceBarrier],
) -> Result<(), DatabaseConfigSourceError> {
    let total = nodes
        .iter()
        .map(DatabaseConfigSourceNode::text_bytes)
        .chain(barriers.iter().map(|barrier| barrier.label.len()))
        .try_fold(0usize, usize::checked_add)
        .ok_or(DatabaseConfigSourceError::TotalTextTooLarge)?;
    if total > MAX_DATABASE_CONFIG_SOURCE_TOTAL_TEXT_BYTES {
        return Err(DatabaseConfigSourceError::TotalTextTooLarge);
    }
    Ok(())
}

fn normalize_precedence(
    nodes: &[DatabaseConfigSourceNode],
    relations: &[DatabaseConfigSourceRelation],
) -> Result<NormalizedPrecedence, DatabaseConfigSourceError> {
    let mut parents = (0..nodes.len()).collect::<Vec<_>>();
    for relation in relations {
        if relation.precedence == DatabaseConfigSourcePrecedence::Equal {
            let left = node_index(nodes, relation.left).expect("relation endpoints were validated");
            let right =
                node_index(nodes, relation.right).expect("relation endpoints were validated");
            union(&mut parents, left, right);
        }
    }

    let mut root_to_class = vec![usize::MAX; nodes.len()];
    let mut class_of = Vec::with_capacity(nodes.len());
    let mut class_count = 0usize;
    for index in 0..nodes.len() {
        let root = find_root(&mut parents, index);
        if root_to_class[root] == usize::MAX {
            root_to_class[root] = class_count;
            class_count += 1;
        }
        class_of.push(root_to_class[root]);
    }

    let mut adjacency = vec![vec![false; class_count]; class_count];
    for (relation_index, relation) in relations.iter().enumerate() {
        let left = node_index(nodes, relation.left).expect("relation endpoints were validated");
        let right = node_index(nodes, relation.right).expect("relation endpoints were validated");
        let edge = match relation.precedence {
            DatabaseConfigSourcePrecedence::Higher => Some((class_of[left], class_of[right])),
            DatabaseConfigSourcePrecedence::Lower => Some((class_of[right], class_of[left])),
            DatabaseConfigSourcePrecedence::Equal
            | DatabaseConfigSourcePrecedence::Unknown
            | DatabaseConfigSourcePrecedence::Conflict => None,
        };
        let Some((higher, lower)) = edge else {
            continue;
        };
        if higher == lower {
            return Err(DatabaseConfigSourceError::StrictRelationWithinEqualSet { relation_index });
        }
        adjacency[higher][lower] = true;
    }

    validate_dag_depth(&adjacency)?;
    Ok(NormalizedPrecedence {
        class_count,
        class_of,
        adjacency,
    })
}

fn node_index(nodes: &[DatabaseConfigSourceNode], id: DatabaseConfigSourceNodeId) -> Option<usize> {
    nodes.iter().position(|node| node.id == id)
}

fn find_root(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}

fn union(parents: &mut [usize], left: usize, right: usize) {
    let left_root = find_root(parents, left);
    let right_root = find_root(parents, right);
    if left_root != right_root {
        parents[right_root] = left_root;
    }
}

fn validate_dag_depth(adjacency: &[Vec<bool>]) -> Result<(), DatabaseConfigSourceError> {
    let mut indegree = vec![0usize; adjacency.len()];
    for edges in adjacency {
        for (lower, exists) in edges.iter().copied().enumerate() {
            if exists {
                indegree[lower] += 1;
            }
        }
    }

    let mut queue = indegree
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect::<Vec<_>>();
    let mut depth = vec![1usize; adjacency.len()];
    let mut cursor = 0usize;
    while cursor < queue.len() {
        let higher = queue[cursor];
        cursor += 1;
        for (lower, exists) in adjacency[higher].iter().copied().enumerate() {
            if !exists {
                continue;
            }
            depth[lower] = depth[lower].max(depth[higher].saturating_add(1));
            indegree[lower] -= 1;
            if indegree[lower] == 0 {
                queue.push(lower);
            }
        }
    }
    if queue.len() != adjacency.len() {
        return Err(DatabaseConfigSourceError::Cycle);
    }
    if depth.into_iter().max().unwrap_or(0) > MAX_DATABASE_CONFIG_SOURCE_DEPTH {
        return Err(DatabaseConfigSourceError::DepthExceeded);
    }
    Ok(())
}

fn transitive_closure(adjacency: &[Vec<bool>]) -> Vec<Vec<bool>> {
    let mut reachable = adjacency.to_vec();
    for intermediate in 0..reachable.len() {
        let intermediate_reachable = reachable[intermediate].clone();
        for higher_reachable in &mut reachable {
            if !higher_reachable[intermediate] {
                continue;
            }
            for (reachable, through_intermediate) in
                higher_reachable.iter_mut().zip(&intermediate_reachable)
            {
                *reachable |= *through_intermediate;
            }
        }
    }
    reachable
}

fn valid_display_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.chars().any(is_unsafe_display_character)
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{061c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

#[cfg(test)]
mod tests {
    use crate::target::TargetIdentity;

    use super::*;

    fn target(identity: &str, generation: u64) -> TargetGuard {
        TargetGuard {
            identity: TargetIdentity::new(identity).unwrap(),
            generation,
        }
    }

    fn binding(
        target: TargetGuard,
        product: DatabaseConfigProduct,
        component: DatabaseConfigComponent,
        artifact_key: &'static str,
    ) -> DatabaseConfigSourceBinding {
        DatabaseConfigSourceBinding::new(target, product, component, artifact_key).unwrap()
    }

    fn origin(label: impl Into<String>, seed: u8) -> DatabaseConfigSourceOrigin {
        DatabaseConfigSourceOrigin::from_content_digest(label, [seed; 32]).unwrap()
    }

    fn node(
        id: u32,
        binding: &DatabaseConfigSourceBinding,
        kind: DatabaseConfigSourceKind,
        label: impl Into<String>,
    ) -> DatabaseConfigSourceNode {
        DatabaseConfigSourceNode::metadata_only(
            DatabaseConfigSourceNodeId::new(id),
            binding.clone(),
            kind,
            origin(label, id as u8),
        )
    }

    fn relation(
        left: u32,
        right: u32,
        precedence: DatabaseConfigSourcePrecedence,
    ) -> DatabaseConfigSourceRelation {
        DatabaseConfigSourceRelation::new(
            DatabaseConfigSourceNodeId::new(left),
            DatabaseConfigSourceNodeId::new(right),
            precedence,
        )
    }

    fn effective_ids(graph: &DatabaseConfigSourceGraph) -> Vec<u32> {
        match graph.effective_projection() {
            DatabaseConfigSourceProjection::Effective(effective) => {
                effective.source_ids().iter().map(|id| id.get()).collect()
            }
            status => panic!("expected Effective, got {status:?}"),
        }
    }

    #[test]
    fn mysql_option_cli_and_persisted_precedence_is_explicit() {
        let binding = binding(
            target("mysql-a", 7),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::RuntimeParameters,
            "mysql-runtime-variables",
        );
        let graph = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                node(1, &binding, DatabaseConfigSourceKind::File, "/etc/my.cnf"),
                node(
                    2,
                    &binding,
                    DatabaseConfigSourceKind::CommandLine,
                    "mysqld argv revision",
                ),
                node(
                    3,
                    &binding,
                    DatabaseConfigSourceKind::RuntimePersisted,
                    "mysqld-auto.cnf",
                ),
            ],
            vec![
                relation(1, 2, DatabaseConfigSourcePrecedence::Lower),
                relation(2, 3, DatabaseConfigSourcePrecedence::Lower),
            ],
            vec![],
        )
        .unwrap();

        assert_eq!(effective_ids(&graph), [3]);
    }

    #[test]
    fn postgresql_file_auto_conf_and_cli_precedence_is_explicit() {
        let binding = binding(
            target("postgres-a", 11),
            DatabaseConfigProduct::PostgreSql,
            DatabaseConfigComponent::RuntimeParameters,
            "postgresql-runtime-parameters",
        );
        let graph = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                node(
                    1,
                    &binding,
                    DatabaseConfigSourceKind::File,
                    "postgresql.conf",
                ),
                node(
                    2,
                    &binding,
                    DatabaseConfigSourceKind::RuntimePersisted,
                    "postgresql.auto.conf",
                ),
                node(
                    3,
                    &binding,
                    DatabaseConfigSourceKind::CommandLine,
                    "postgres argv revision",
                ),
            ],
            vec![
                relation(1, 2, DatabaseConfigSourcePrecedence::Lower),
                relation(2, 3, DatabaseConfigSourcePrecedence::Lower),
            ],
            vec![],
        )
        .unwrap();

        assert_eq!(effective_ids(&graph), [3]);
    }

    #[test]
    fn tidb_file_cli_and_unknown_etcd_order_stays_partial() {
        let binding = binding(
            target("tidb-a", 3),
            DatabaseConfigProduct::TiDb,
            DatabaseConfigComponent::TiDb,
            "tidb-server-toml",
        );
        let graph = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                node(1, &binding, DatabaseConfigSourceKind::File, "tidb.toml"),
                node(
                    2,
                    &binding,
                    DatabaseConfigSourceKind::CommandLine,
                    "tidb-server argv revision",
                ),
                node(
                    3,
                    &binding,
                    DatabaseConfigSourceKind::ToolManaged,
                    "etcd configuration key",
                ),
            ],
            vec![
                relation(1, 2, DatabaseConfigSourcePrecedence::Lower),
                relation(2, 3, DatabaseConfigSourcePrecedence::Unknown),
            ],
            vec![],
        )
        .unwrap();

        assert_eq!(
            graph.effective_projection(),
            DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::UnknownPrecedence
            )
        );
    }

    #[test]
    fn unresolved_include_is_an_explicit_projection_barrier() {
        let binding = binding(
            target("postgres-b", 4),
            DatabaseConfigProduct::PostgreSql,
            DatabaseConfigComponent::Server,
            "postgresql-main",
        );
        let barrier = DatabaseConfigSourceBarrier::unresolved(
            binding.clone(),
            DatabaseConfigSourceKind::IncludedFile,
            "/etc/postgresql/conf.d/private.conf",
        )
        .unwrap();
        let graph = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![node(
                1,
                &binding,
                DatabaseConfigSourceKind::File,
                "postgresql.conf",
            )],
            vec![],
            vec![barrier],
        )
        .unwrap();

        assert_eq!(
            graph.effective_projection(),
            DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::UnresolvedBarrier
            )
        );
    }

    #[test]
    fn cycles_and_strict_edges_inside_equal_sets_are_rejected() {
        let binding = binding(
            target("mysql-cycle", 1),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::RuntimeParameters,
            "mysql-runtime-variables",
        );
        let nodes = vec![
            node(1, &binding, DatabaseConfigSourceKind::File, "one"),
            node(2, &binding, DatabaseConfigSourceKind::CommandLine, "two"),
            node(
                3,
                &binding,
                DatabaseConfigSourceKind::RuntimePersisted,
                "three",
            ),
        ];
        assert_eq!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Complete,
                nodes.clone(),
                vec![
                    relation(1, 2, DatabaseConfigSourcePrecedence::Higher),
                    relation(2, 3, DatabaseConfigSourcePrecedence::Higher),
                    relation(3, 1, DatabaseConfigSourcePrecedence::Higher),
                ],
                vec![],
            )
            .unwrap_err(),
            DatabaseConfigSourceError::Cycle
        );
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                binding,
                DatabaseConfigSourceCoverage::Complete,
                nodes,
                vec![
                    relation(1, 2, DatabaseConfigSourcePrecedence::Equal),
                    relation(2, 3, DatabaseConfigSourcePrecedence::Equal),
                    relation(1, 3, DatabaseConfigSourcePrecedence::Higher),
                ],
                vec![],
            ),
            Err(DatabaseConfigSourceError::StrictRelationWithinEqualSet { .. })
        ));
    }

    #[test]
    fn target_and_exact_artifact_bindings_cannot_mix() {
        let graph_binding = binding(
            target("host-a", 9),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::RuntimeParameters,
            "mysql-runtime-variables",
        );
        let stale_target_binding = binding(
            target("host-a", 8),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::RuntimeParameters,
            "mysql-runtime-variables",
        );
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                graph_binding.clone(),
                DatabaseConfigSourceCoverage::Complete,
                vec![node(
                    1,
                    &stale_target_binding,
                    DatabaseConfigSourceKind::File,
                    "my.cnf"
                )],
                vec![],
                vec![],
            ),
            Err(DatabaseConfigSourceError::TargetMismatch {
                member: DatabaseConfigSourceMemberKind::Node,
                index: 0,
            })
        ));

        let other_binding = binding(
            graph_binding.target().clone(),
            DatabaseConfigProduct::PostgreSql,
            DatabaseConfigComponent::RuntimeParameters,
            "postgresql-runtime-parameters",
        );
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                graph_binding,
                DatabaseConfigSourceCoverage::Complete,
                vec![node(
                    1,
                    &other_binding,
                    DatabaseConfigSourceKind::File,
                    "postgresql.conf"
                )],
                vec![],
                vec![],
            ),
            Err(DatabaseConfigSourceError::BindingMismatch {
                member: DatabaseConfigSourceMemberKind::Node,
                index: 0,
            })
        ));
    }

    #[test]
    fn duplicate_sources_ids_relations_and_barriers_are_rejected() {
        let binding = binding(
            target("duplicates", 1),
            DatabaseConfigProduct::TiDb,
            DatabaseConfigComponent::TiDb,
            "tidb-server-toml",
        );
        let first = node(1, &binding, DatabaseConfigSourceKind::File, "tidb.toml");
        let same_id = node(1, &binding, DatabaseConfigSourceKind::CommandLine, "argv");
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Complete,
                vec![first.clone(), same_id],
                vec![],
                vec![],
            ),
            Err(DatabaseConfigSourceError::DuplicateNodeId { .. })
        ));
        let same_source = DatabaseConfigSourceNode::metadata_only(
            DatabaseConfigSourceNodeId::new(2),
            binding.clone(),
            DatabaseConfigSourceKind::File,
            DatabaseConfigSourceOrigin::from_revision("tidb.toml", "new revision").unwrap(),
        );
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Complete,
                vec![first.clone(), same_source],
                vec![],
                vec![],
            ),
            Err(DatabaseConfigSourceError::DuplicateSource { .. })
        ));

        let second = node(2, &binding, DatabaseConfigSourceKind::CommandLine, "argv");
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Complete,
                vec![first.clone(), second],
                vec![
                    relation(1, 2, DatabaseConfigSourcePrecedence::Lower),
                    relation(2, 1, DatabaseConfigSourcePrecedence::Higher),
                ],
                vec![],
            ),
            Err(DatabaseConfigSourceError::DuplicateRelation { .. })
        ));

        let barrier = DatabaseConfigSourceBarrier::unresolved(
            binding.clone(),
            DatabaseConfigSourceKind::IncludedFile,
            "missing.toml",
        )
        .unwrap();
        assert!(matches!(
            DatabaseConfigSourceGraph::new(
                binding,
                DatabaseConfigSourceCoverage::Partial,
                vec![first],
                vec![],
                vec![barrier.clone(), barrier],
            ),
            Err(DatabaseConfigSourceError::DuplicateBarrier { .. })
        ));
    }

    #[test]
    fn graph_and_text_bounds_fail_closed() {
        let binding = binding(
            target("bounds", 1),
            DatabaseConfigProduct::TiDb,
            DatabaseConfigComponent::TiDb,
            "tidb-server-toml",
        );
        let too_many_nodes = (0..=MAX_DATABASE_CONFIG_SOURCE_NODES)
            .map(|index| {
                node(
                    index as u32,
                    &binding,
                    DatabaseConfigSourceKind::File,
                    format!("source-{index}"),
                )
            })
            .collect();
        assert_eq!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Partial,
                too_many_nodes,
                vec![],
                vec![],
            )
            .unwrap_err(),
            DatabaseConfigSourceError::TooManyNodes
        );

        let too_many_relations = vec![
            relation(1, 2, DatabaseConfigSourcePrecedence::Unknown);
            MAX_DATABASE_CONFIG_SOURCE_RELATIONS + 1
        ];
        assert_eq!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Partial,
                vec![],
                too_many_relations,
                vec![],
            )
            .unwrap_err(),
            DatabaseConfigSourceError::TooManyRelations
        );

        let chain_nodes = (0..=MAX_DATABASE_CONFIG_SOURCE_DEPTH)
            .map(|index| {
                node(
                    index as u32,
                    &binding,
                    DatabaseConfigSourceKind::GeneratedState,
                    format!("depth-{index}"),
                )
            })
            .collect::<Vec<_>>();
        let chain_relations = (0..MAX_DATABASE_CONFIG_SOURCE_DEPTH)
            .map(|index| {
                relation(
                    index as u32,
                    index as u32 + 1,
                    DatabaseConfigSourcePrecedence::Higher,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            DatabaseConfigSourceGraph::new(
                binding.clone(),
                DatabaseConfigSourceCoverage::Complete,
                chain_nodes,
                chain_relations,
                vec![],
            )
            .unwrap_err(),
            DatabaseConfigSourceError::DepthExceeded
        );

        assert!(matches!(
            DatabaseConfigSourceOrigin::from_revision(
                "x".repeat(MAX_DATABASE_CONFIG_SOURCE_LABEL_BYTES + 1),
                "revision"
            ),
            Err(DatabaseConfigSourceError::InvalidText {
                field: DatabaseConfigSourceTextField::OriginLabel
            })
        ));
        assert_eq!(
            DatabaseConfigSourceValue::new("x".repeat(MAX_DATABASE_CONFIG_SOURCE_VALUE_BYTES + 1))
                .unwrap_err(),
            DatabaseConfigSourceError::ValueTooLong
        );

        let large_value = "x".repeat(MAX_DATABASE_CONFIG_SOURCE_VALUE_BYTES);
        let large_nodes = (0..65)
            .map(|index| {
                DatabaseConfigSourceNode::observed(
                    DatabaseConfigSourceNodeId::new(index),
                    binding.clone(),
                    DatabaseConfigSourceKind::GeneratedState,
                    origin(format!("large-{index}"), index as u8),
                    DatabaseConfigSourceValue::new(large_value.clone()).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            DatabaseConfigSourceGraph::new(
                binding,
                DatabaseConfigSourceCoverage::Partial,
                large_nodes,
                vec![],
                vec![],
            )
            .unwrap_err(),
            DatabaseConfigSourceError::TotalTextTooLarge
        );
    }

    #[test]
    fn projection_never_defaults_to_a_discovered_file() {
        let binding = binding(
            target("projection", 1),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::Server,
            "mysql-option-file",
        );
        let not_run = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::NotRun,
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(
            not_run.effective_projection(),
            DatabaseConfigSourceProjection::NotRun
        );

        let partial = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Partial,
            vec![node(1, &binding, DatabaseConfigSourceKind::File, "my.cnf")],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(
            partial.effective_projection(),
            DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::DiscoveryIncomplete
            )
        );

        let incomparable = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                node(1, &binding, DatabaseConfigSourceKind::File, "my.cnf"),
                node(
                    2,
                    &binding,
                    DatabaseConfigSourceKind::Environment,
                    "MYSQL_SETTING",
                ),
            ],
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(
            incomparable.effective_projection(),
            DatabaseConfigSourceProjection::Partial(
                DatabaseConfigSourcePartialReason::IncomparableSources
            )
        );

        let conflict = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                node(1, &binding, DatabaseConfigSourceKind::File, "my.cnf"),
                node(
                    2,
                    &binding,
                    DatabaseConfigSourceKind::ServiceManager,
                    "mysql.service",
                ),
            ],
            vec![relation(1, 2, DatabaseConfigSourcePrecedence::Conflict)],
            vec![],
        )
        .unwrap();
        assert_eq!(
            conflict.effective_projection(),
            DatabaseConfigSourceProjection::Blocked(
                DatabaseConfigSourceBlockedReason::ConflictingPrecedence
            )
        );
    }

    #[test]
    fn equal_highest_sources_require_the_same_observed_value() {
        let binding = binding(
            target("equal", 1),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::RuntimeParameters,
            "mysql-runtime-variables",
        );
        let observed = |id, label: &'static str, value: &'static str| {
            DatabaseConfigSourceNode::observed(
                DatabaseConfigSourceNodeId::new(id),
                binding.clone(),
                DatabaseConfigSourceKind::RuntimeEphemeral,
                origin(label, id as u8),
                DatabaseConfigSourceValue::new(value).unwrap(),
            )
        };
        let same = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                observed(1, "session-a", "safe"),
                observed(2, "session-b", "safe"),
            ],
            vec![relation(1, 2, DatabaseConfigSourcePrecedence::Equal)],
            vec![],
        )
        .unwrap();
        assert_eq!(effective_ids(&same), [1, 2]);

        let different = DatabaseConfigSourceGraph::new(
            binding.clone(),
            DatabaseConfigSourceCoverage::Complete,
            vec![
                observed(1, "session-a", "first"),
                observed(2, "session-b", "second"),
            ],
            vec![relation(1, 2, DatabaseConfigSourcePrecedence::Equal)],
            vec![],
        )
        .unwrap();
        assert_eq!(
            different.effective_projection(),
            DatabaseConfigSourceProjection::Blocked(
                DatabaseConfigSourceBlockedReason::EqualPrecedenceValuesDiffer
            )
        );
    }

    #[test]
    fn debug_omits_sensitive_labels_revisions_digests_and_values() {
        let binding = binding(
            target("debug-target-DontLeak", 5),
            DatabaseConfigProduct::MySql,
            DatabaseConfigComponent::RuntimeParameters,
            "mysql-runtime-variables",
        );
        let secret_label = "mysql://admin:DontLeak@host/private";
        let secret_revision = "revision-DontLeak";
        let secret_value = "password=DontLeak";
        let origin = DatabaseConfigSourceOrigin::from_content_digest_and_revision(
            secret_label,
            [0xab; 32],
            secret_revision,
        )
        .unwrap();
        let value = DatabaseConfigSourceValue::new(secret_value).unwrap();
        let node = DatabaseConfigSourceNode::observed(
            DatabaseConfigSourceNodeId::new(1),
            binding.clone(),
            DatabaseConfigSourceKind::CloudControlPlane,
            origin,
            value,
        );
        let barrier = DatabaseConfigSourceBarrier::unresolved(
            binding.clone(),
            DatabaseConfigSourceKind::IncludedFile,
            "include-DontLeak",
        )
        .unwrap();
        let graph = DatabaseConfigSourceGraph::new(
            binding,
            DatabaseConfigSourceCoverage::Partial,
            vec![node],
            vec![],
            vec![barrier],
        )
        .unwrap();

        for debug in [format!("{graph:?}"), format!("{:?}", graph.clone())] {
            assert!(!debug.contains("DontLeak"));
            assert!(!debug.contains(secret_label));
            assert!(!debug.contains(secret_revision));
            assert!(!debug.contains(secret_value));
            assert!(!debug.contains("abababab"));
        }
        assert_eq!(graph.nodes()[0].origin().label(), secret_label);
        assert_eq!(graph.nodes()[0].origin().revision(), Some(secret_revision));
        assert_eq!(graph.nodes()[0].value().unwrap().as_str(), secret_value);
    }
}
