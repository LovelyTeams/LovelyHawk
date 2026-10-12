//! Static PG 16+ role paths. No SET ROLE or authorization-changing SQL is run.
use crate::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const DATABASE_OWNER: u32 = 6171;
const PAGE_SIZE: usize = 20;
const PATH_SIZE: usize = 32;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Membership {
    pub oid: u32,
    pub role_oid: u32,
    pub member_oid: u32,
    pub grantor_oid: u32,
    pub admin_option: bool,
    pub inherit_option: bool,
    pub set_option: bool,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DatabaseContext {
    pub oid: u32,
    pub name: String,
    pub owner_oid: u32,
}
impl DatabaseContext {
    pub(crate) fn valid(&self, identity: (u32, &str)) -> bool {
        self.oid > 0 && self.owner_oid > 0 && self.oid == identity.0 && self.name == identity.1
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Role {
    pub oid: u32,
    pub name: String,
    pub can_login: bool,
    pub superuser: bool,
    pub create_role: bool,
    pub create_database: bool,
    pub replication: bool,
    pub bypass_rls: bool,
}
impl Role {
    fn gains_management(&self, target: &Self) -> bool {
        !self.superuser
            && (target.superuser
                || target.create_role && !self.create_role
                || target.create_database && !self.create_database
                || target.replication && !self.replication
                || target.bypass_rls && !self.bypass_rls)
    }
    fn reference(&self) -> serde_json::Value {
        serde_json::json!({"oid":self.oid,"name":self.name})
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RoleAccessMode {
    Member,
    Inherit,
    Set,
    AfterSet,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RoleGraphUnavailable {
    RolesUnavailable,
    MembershipsUnavailable,
    DatabaseUnavailable,
    InvalidGraph,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleGraphSummary {
    state: &'static str,
    reason: Option<RoleGraphUnavailable>,
    database: Option<DatabaseContext>,
    additional_management_logins: Option<usize>,
}
impl std::fmt::Debug for RoleGraphSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleGraphSummary")
            .field("state", &self.state)
            .field("reason", &self.reason)
            .field(
                "additional_management_logins",
                &self.additional_management_logins,
            )
            .finish()
    }
}
impl RoleGraphSummary {
    pub(crate) fn unavailable(reason: RoleGraphUnavailable) -> Self {
        Self {
            state: "unavailable",
            reason: Some(reason),
            database: None,
            additional_management_logins: None,
        }
    }
}

#[derive(Clone, Copy)]
struct Edge {
    target: usize,
    grant: Option<u32>, // None is the database-owner implicit membership.
    inherit: bool,
    set: bool,
}
#[derive(Clone, Copy)]
struct Trace {
    parent: usize,
    grant: Option<u32>,
    operation: RoleAccessMode,
    superuser: bool,
}
#[derive(Clone)]
pub(crate) struct RoleGraph {
    roles: Vec<Role>,
    edges: Vec<Vec<Edge>>,
    database: DatabaseContext,
    additional_management_logins: usize,
}
pub(crate) struct OrdinaryRoleContext {
    pub source: Role,
    pub inherited: BTreeSet<u32>,
    pub after_set: BTreeSet<u32>,
    pub set_superuser: Option<u32>,
}
impl RoleGraph {
    pub(crate) fn database(&self) -> &DatabaseContext {
        &self.database
    }
    pub(crate) fn role(&self, oid: u32) -> Option<&Role> {
        self.roles.iter().find(|r| r.oid == oid)
    }
    pub(crate) fn ordinary_context(&self, oid: u32) -> Option<OrdinaryRoleContext> {
        let source = self.roles.iter().position(|r| r.oid == oid)?;
        let inherited = self
            .walk(source, RoleAccessMode::Inherit)
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_some())
            .map(|(i, _)| self.roles[i].oid)
            .collect();
        let (_, extra) = self.paths(source, RoleAccessMode::AfterSet);
        let after_set = extra
            .iter()
            .enumerate()
            .filter(|(_, included)| **included)
            .map(|(i, _)| self.roles[i].oid)
            .collect();
        let set_superuser = self
            .walk(source, RoleAccessMode::Set)
            .iter()
            .enumerate()
            .find(|(i, t)| *i != source && t.is_some() && self.roles[*i].superuser)
            .map(|(i, _)| self.roles[i].oid);
        Some(OrdinaryRoleContext {
            source: self.roles[source].clone(),
            inherited,
            after_set,
            set_superuser,
        })
    }
    pub(crate) fn build(
        roles: Vec<Role>,
        memberships: &[Membership],
        database: DatabaseContext,
    ) -> Option<Self> {
        if roles.is_empty()
            || roles.len() > 1024
            || memberships.len() > 2048
            || !roles.windows(2).all(|p| p[0].oid < p[1].oid)
            || roles.iter().any(|r| {
                r.oid == 0
                    || r.name.is_empty()
                    || r.name.len() > 256
                    || r.name.chars().any(char::is_control)
            })
            || roles.iter().map(|r| &r.name).collect::<BTreeSet<_>>().len() != roles.len()
        {
            return None;
        }
        let indices: BTreeMap<_, _> = roles.iter().enumerate().map(|(i, r)| (r.oid, i)).collect();
        let owner = *indices.get(&database.owner_oid)?;
        let implicit = *indices.get(&DATABASE_OWNER)?;
        if roles[implicit].name != "pg_database_owner" {
            return None;
        }
        let mut edges = vec![vec![]; roles.len()];
        let mut oids = BTreeSet::new();
        let mut grants = BTreeSet::new();
        for m in memberships {
            // Multiple grantors for the same pair are valid; identical grants are not.
            if m.oid == 0
                || !oids.insert(m.oid)
                || !grants.insert((m.role_oid, m.member_oid, m.grantor_oid))
                || m.role_oid == m.member_oid
                || m.role_oid == DATABASE_OWNER
                || m.member_oid == DATABASE_OWNER
            {
                return None;
            }
            let source = *indices.get(&m.member_oid)?;
            let target = *indices.get(&m.role_oid)?;
            indices.get(&m.grantor_oid)?;
            edges[source].push(Edge {
                target,
                grant: Some(m.oid),
                inherit: m.inherit_option,
                set: m.set_option,
            });
        }
        // Verify the explicit DAG before adding the context-dependent implicit edge.
        let mut incoming = vec![0; roles.len()];
        for edge in edges.iter().flatten() {
            incoming[edge.target] += 1;
        }
        let mut queue: VecDeque<_> = incoming
            .iter()
            .enumerate()
            .filter(|(_, n)| **n == 0)
            .map(|(i, _)| i)
            .collect();
        let mut visited = 0;
        while let Some(i) = queue.pop_front() {
            visited += 1;
            for edge in &edges[i] {
                incoming[edge.target] -= 1;
                if incoming[edge.target] == 0 {
                    queue.push_back(edge.target);
                }
            }
        }
        if visited != roles.len() {
            return None;
        }
        if owner != implicit {
            edges[owner].push(Edge {
                target: implicit,
                grant: None,
                inherit: true,
                set: true,
            });
        }
        let mut graph = Self {
            roles,
            edges,
            database,
            additional_management_logins: 0,
        };
        graph.additional_management_logins =
            graph
                .roles
                .iter()
                .enumerate()
                .filter(|(i, source)| {
                    source.can_login
                        && !source.superuser
                        && graph.walk(*i, RoleAccessMode::Set).iter().enumerate().any(
                            |(j, trace)| {
                                trace.is_some() && source.gains_management(&graph.roles[j])
                            },
                        )
                })
                .count();
        Some(graph)
    }
    pub(crate) fn summary(&self) -> RoleGraphSummary {
        RoleGraphSummary {
            state: "available",
            reason: None,
            database: Some(self.database.clone()),
            additional_management_logins: Some(self.additional_management_logins),
        }
    }
    pub(crate) fn case_summary(&self) -> String {
        format!(
            "角色路径：已分析；可经 SET ROLE 获得额外管理属性的登录角色：{}。仅为静态路径，未验证对象授权、登录或执行操作。\n",
            self.additional_management_logins
        )
    }
    fn expand(
        &self,
        traces: &mut [Option<Trace>],
        mut queue: VecDeque<usize>,
        mode: RoleAccessMode,
    ) {
        while let Some(i) = queue.pop_front() {
            for edge in &self.edges[i] {
                if traces[edge.target].is_some()
                    || mode == RoleAccessMode::Inherit && !edge.inherit
                    || mode == RoleAccessMode::Set && !edge.set
                {
                    continue;
                }
                traces[edge.target] = Some(Trace {
                    parent: i,
                    grant: edge.grant,
                    operation: mode,
                    superuser: false,
                });
                queue.push_back(edge.target);
            }
        }
    }
    fn walk(&self, source: usize, mode: RoleAccessMode) -> Vec<Option<Trace>> {
        let mut traces = vec![None; self.roles.len()];
        traces[source] = Some(Trace {
            parent: source,
            grant: None,
            operation: mode,
            superuser: false,
        });
        // Only the original source has this shortcut, never an inherited intermediate role.
        if self.roles[source].superuser {
            for (i, trace) in traces.iter_mut().enumerate() {
                if i != source {
                    *trace = Some(Trace {
                        parent: source,
                        grant: None,
                        operation: mode,
                        superuser: true,
                    });
                }
            }
        } else {
            self.expand(&mut traces, VecDeque::from([source]), mode);
        }
        traces
    }
    fn paths(&self, source: usize, mode: RoleAccessMode) -> (Vec<Option<Trace>>, Vec<bool>) {
        if mode != RoleAccessMode::AfterSet {
            let traces = self.walk(source, mode);
            let included = traces
                .iter()
                .enumerate()
                .map(|(i, t)| i != source && t.is_some())
                .collect();
            return (traces, included);
        }
        let inherited = self.walk(source, RoleAccessMode::Inherit);
        let mut traces = self.walk(source, RoleAccessMode::Set);
        let roots: VecDeque<_> = traces
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_some())
            .map(|(i, _)| i)
            .collect();
        let elevated = roots.iter().copied().find(|i| self.roles[*i].superuser);
        self.expand(&mut traces, roots, RoleAccessMode::Inherit);
        // SET to a superuser supplies all ordinary privileges. It does not enlarge
        // the original session user's SET ROLE graph (see sql-set-role).
        if let Some(parent) = elevated {
            for trace in &mut traces {
                if trace.is_none() {
                    *trace = Some(Trace {
                        parent,
                        grant: None,
                        operation: RoleAccessMode::Inherit,
                        superuser: true,
                    });
                }
            }
        }
        let included = traces
            .iter()
            .zip(inherited)
            .enumerate()
            .map(|(i, (t, automatic))| i != source && t.is_some() && automatic.is_none())
            .collect();
        (traces, included)
    }
    pub(crate) fn page(
        &self,
        oid: u32,
        mode: RoleAccessMode,
        query: &str,
        offset: usize,
    ) -> CoreResult<serde_json::Value> {
        if query.len() > 128 || query.chars().any(char::is_control) || offset > 1024 {
            return Err(invalid());
        }
        let source = self
            .roles
            .iter()
            .position(|r| r.oid == oid)
            .ok_or_else(invalid)?;
        let (traces, included) = self.paths(source, mode);
        let q = query.to_lowercase();
        let matching: Vec<_> = included
            .iter()
            .enumerate()
            .filter(|(i, yes)| **yes && self.roles[*i].name.to_lowercase().contains(&q))
            .map(|(i, _)| i)
            .collect();
        let mut rows = Vec::new();
        for &target in matching.iter().skip(offset).take(PAGE_SIZE) {
            let mut route = vec![];
            let mut at = target;
            while at != source {
                let trace = traces[at].ok_or_else(invalid)?;
                route.push((at, trace));
                at = trace.parent;
                if route.len() > self.roles.len() {
                    return Err(invalid());
                }
            }
            route.reverse();
            let hops = route.len();
            let mut steps = vec![
                serde_json::json!({"role":self.roles[source].reference(),"via":"source","grantOid":null,"operation":null}),
            ];
            for &(i, trace) in route.iter().take(PATH_SIZE - 1) {
                steps.push(serde_json::json!({"role":self.roles[i].reference(),"via":if trace.superuser {"superuser"} else if trace.grant.is_some() {"grant"} else {"database-owner"},"grantOid":trace.grant,"operation":trace.operation}));
            }
            rows.push(serde_json::json!({"target":self.roles[target],"hops":hops,"truncated":hops+1>PATH_SIZE,"steps":steps}));
        }
        Ok(
            serde_json::json!({"source":self.roles[source],"database":self.database,"roleOid":oid,"mode":mode,"query":query,"offset":offset,"total":included.iter().filter(|v| **v).count(),"matched":matching.len(),"rows":rows}),
        )
    }
}
fn invalid() -> CoreError {
    CoreError::validation(
        "PostgreSQL role paths",
        "角色权限来源无法核实，请重新读取数据库状态。",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn role(oid: u32) -> Role {
        Role {
            oid,
            name: format!("role_{oid}"),
            can_login: true,
            superuser: false,
            create_role: false,
            create_database: false,
            replication: false,
            bypass_rls: false,
        }
    }
    fn grant(oid: u32, from: u32, to: u32, inherit: bool, set: bool) -> Membership {
        Membership {
            oid,
            member_oid: from,
            role_oid: to,
            grantor_oid: 1,
            admin_option: false,
            inherit_option: inherit,
            set_option: set,
        }
    }
    fn graph(mut roles: Vec<Role>, grants: Vec<Membership>, owner_oid: u32) -> Option<RoleGraph> {
        let mut builtin = role(DATABASE_OWNER);
        builtin.name = "pg_database_owner".into();
        builtin.can_login = false;
        roles.push(builtin);
        RoleGraph::build(
            roles,
            &grants,
            DatabaseContext {
                oid: 5,
                name: "postgres".into(),
                owner_oid,
            },
        )
    }
    fn targets(g: &RoleGraph, source: u32, mode: RoleAccessMode) -> Vec<u32> {
        g.page(source, mode, "", 0).unwrap()["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["target"]["oid"].as_u64().unwrap() as u32)
            .collect()
    }
    #[test]
    fn flags_control_each_path_and_mixed_paths_explain_new_sources() {
        let g = graph(
            (1..=5).map(role).collect(),
            vec![
                grant(1, 1, 2, false, true),
                grant(2, 2, 3, true, false),
                grant(3, 1, 4, true, false),
            ],
            5,
        )
        .unwrap();
        assert_eq!(targets(&g, 1, RoleAccessMode::Member), [2, 3, 4]);
        assert_eq!(targets(&g, 1, RoleAccessMode::Inherit), [4]);
        assert_eq!(targets(&g, 1, RoleAccessMode::Set), [2]);
        assert_eq!(targets(&g, 1, RoleAccessMode::AfterSet), [2, 3]);
        let page = g.page(1, RoleAccessMode::AfterSet, "role_3", 0).unwrap();
        assert_eq!(page["rows"][0]["steps"][1]["operation"], "set");
        assert_eq!(page["rows"][0]["steps"][2]["operation"], "inherit");
        assert_eq!(targets(&g, 5, RoleAccessMode::Set), [DATABASE_OWNER]);
        assert_eq!(
            g.page(5, RoleAccessMode::Inherit, "", 0).unwrap()["rows"][0]["steps"][1]["via"],
            "database-owner"
        );
    }
    #[test]
    fn inherited_superuser_does_not_confer_superuser_or_universal_set() {
        let mut roles: Vec<_> = (1..=4).map(role).collect();
        roles[1].superuser = true;
        let g = graph(
            roles,
            vec![grant(1, 1, 2, true, false), grant(2, 3, 2, false, true)],
            4,
        )
        .unwrap();
        assert_eq!(targets(&g, 1, RoleAccessMode::Inherit), [2]);
        assert!(targets(&g, 1, RoleAccessMode::Set).is_empty());
        assert_eq!(targets(&g, 3, RoleAccessMode::Set), [2]);
        assert_eq!(
            targets(&g, 3, RoleAccessMode::AfterSet),
            [1, 2, 4, DATABASE_OWNER]
        );
        assert_eq!(g.additional_management_logins, 1);
        assert_eq!(
            targets(&g, 2, RoleAccessMode::Set),
            [1, 3, 4, DATABASE_OWNER]
        );
        assert!(targets(&g, 2, RoleAccessMode::AfterSet).is_empty());
    }
    #[test]
    fn cycles_missing_references_and_duplicate_grants_are_rejected() {
        assert!(
            graph(
                vec![role(1), role(2)],
                vec![grant(1, 1, 2, true, true), grant(2, 2, 1, true, true)],
                1
            )
            .is_none()
        );
        assert!(graph(vec![role(1)], vec![grant(1, 1, 2, true, true)], 1).is_none());
        let mut other = grant(2, 1, 2, true, false);
        other.grantor_oid = 2;
        let g = graph(
            vec![role(1), role(2)],
            vec![grant(1, 1, 2, false, true), other],
            2,
        )
        .unwrap();
        assert_eq!(targets(&g, 1, RoleAccessMode::Inherit), [2, DATABASE_OWNER]);
        assert_eq!(targets(&g, 1, RoleAccessMode::Set), [2, DATABASE_OWNER]);
        assert!(
            graph(
                vec![role(1), role(2)],
                vec![grant(1, 1, 2, true, true), grant(2, 1, 2, true, true)],
                1
            )
            .is_none()
        );
    }
    #[test]
    fn long_paths_and_pages_are_bounded_and_never_silently_complete() {
        let g = graph(
            (1..=70).map(role).collect(),
            (1..70).map(|i| grant(i, i, i + 1, true, true)).collect(),
            70,
        )
        .unwrap();
        let page = g.page(1, RoleAccessMode::Set, "role_70", 0).unwrap();
        assert_eq!(page["rows"][0]["hops"], 69);
        assert_eq!(page["rows"][0]["steps"].as_array().unwrap().len(), 32);
        assert_eq!(page["rows"][0]["truncated"], true);
        let first = g.page(1, RoleAccessMode::Member, "", 0).unwrap();
        let next = g.page(1, RoleAccessMode::Member, "", 20).unwrap();
        assert_eq!(first["rows"].as_array().unwrap().len(), 20);
        assert_ne!(
            first["rows"][0]["target"]["oid"],
            next["rows"][0]["target"]["oid"]
        );
        assert!(g.page(0, RoleAccessMode::Set, "", 0).is_err());
        assert!(g.page(1, RoleAccessMode::Set, "\n", 0).is_err());
    }
}
