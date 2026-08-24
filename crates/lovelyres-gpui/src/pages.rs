use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PageId {
    SystemInfo,
    Docker,
    Kubernetes,
    QuickDetection,
    SecurityReference,
    EmergencyCommands,
    LogAnalysis,
    PacketCapture,
    CheckAudit,
    Integrity,
    Notes,
    Firewall,
    Snapshot,
    BaselineQuickEdit,
    Database,
    Middleware,
    JavaHotUpdate,
    BatchServers,
    AiHistory,
    ConfigGenerator,
}

impl PageId {
    pub const ALL: [Self; 20] = [
        Self::SystemInfo,
        Self::Docker,
        Self::Kubernetes,
        Self::QuickDetection,
        Self::SecurityReference,
        Self::EmergencyCommands,
        Self::LogAnalysis,
        Self::PacketCapture,
        Self::CheckAudit,
        Self::Integrity,
        Self::Notes,
        Self::Firewall,
        Self::Snapshot,
        Self::BaselineQuickEdit,
        Self::Database,
        Self::Middleware,
        Self::JavaHotUpdate,
        Self::BatchServers,
        Self::AiHistory,
        Self::ConfigGenerator,
    ];

    pub const fn descriptor(self) -> &'static PageDescriptor {
        &PAGE_DESCRIPTORS[self as usize]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageGroup {
    Target,
    Triage,
    Investigation,
    Response,
    Operations,
    Intelligence,
}

impl PageGroup {
    pub const ALL: [Self; 6] = [
        Self::Target,
        Self::Triage,
        Self::Investigation,
        Self::Response,
        Self::Operations,
        Self::Intelligence,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Target => "目标",
            Self::Triage => "摸底",
            Self::Investigation => "调查",
            Self::Response => "处置",
            Self::Operations => "运维",
            Self::Intelligence => "助手",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityRequirement {
    ConnectedTarget,
    LocalWorkspace,
    OptionalAi,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageBlueprint {
    pub summary: &'static str,
    pub primary_action: &'static str,
    pub sections: &'static [&'static str],
}

pub type PageFactory = fn() -> PageBlueprint;

#[derive(Clone, Copy)]
pub struct PageDescriptor {
    pub id: PageId,
    pub group: PageGroup,
    pub title: &'static str,
    pub icon: &'static str,
    pub capability: CapabilityRequirement,
    pub create: PageFactory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageImplementationStatus {
    Pending,
    Implemented,
}

impl PageImplementationStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Implemented => "Ported · Implemented",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPageModel {
    pub id: PageId,
    pub title: &'static str,
    pub summary: &'static str,
    pub intended_action: &'static str,
    pub sections: &'static [&'static str],
    pub capability: CapabilityRequirement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementedPageModel {
    pub id: PageId,
    pub title: &'static str,
    pub summary: &'static str,
    pub capability: CapabilityRequirement,
}

impl PendingPageModel {
    pub const fn status_label(&self) -> &'static str {
        PageImplementationStatus::Pending.label()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageModel {
    Pending(PendingPageModel),
    Implemented(ImplementedPageModel),
}

impl PageModel {
    pub fn for_page(page: PageId) -> Self {
        let descriptor = page.descriptor();
        let blueprint = descriptor.blueprint();
        if matches!(
            page,
            PageId::SecurityReference
                | PageId::Notes
                | PageId::Firewall
                | PageId::BaselineQuickEdit
                | PageId::Middleware
                | PageId::JavaHotUpdate
                | PageId::BatchServers
                | PageId::AiHistory
                | PageId::Database
                | PageId::ConfigGenerator
        ) {
            Self::Implemented(ImplementedPageModel {
                id: page,
                title: descriptor.title,
                summary: blueprint.summary,
                capability: descriptor.capability,
            })
        } else {
            Self::Pending(PendingPageModel {
                id: page,
                title: descriptor.title,
                summary: blueprint.summary,
                intended_action: blueprint.primary_action,
                sections: blueprint.sections,
                capability: descriptor.capability,
            })
        }
    }

    pub const fn status(&self) -> PageImplementationStatus {
        match self {
            Self::Pending(_) => PageImplementationStatus::Pending,
            Self::Implemented(_) => PageImplementationStatus::Implemented,
        }
    }
}

impl std::fmt::Debug for PageDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PageDescriptor")
            .field("id", &self.id)
            .field("group", &self.group)
            .field("title", &self.title)
            .field("icon", &self.icon)
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

impl PageDescriptor {
    pub fn blueprint(&self) -> PageBlueprint {
        (self.create)()
    }

    pub fn primary_label(&self) -> &'static str {
        self.blueprint().primary_action
    }
}

macro_rules! blueprint {
    ($name:ident, $summary:literal, $primary:literal, [$($section:literal),+ $(,)?]) => {
        fn $name() -> PageBlueprint {
            PageBlueprint {
                summary: $summary,
                primary_action: $primary,
                sections: &[$($section),+],
            }
        }
    };
}

blueprint!(
    system_info,
    "汇总远端主机运行状态与关键资源。",
    "刷新主机信息",
    ["系统概况", "CPU 与内存", "磁盘与网络"]
);
blueprint!(
    docker,
    "检查容器、镜像、网络与运行日志。",
    "刷新 Docker",
    ["容器", "镜像", "网络"]
);
blueprint!(
    kubernetes,
    "调查工作负载、事件、日志与集群资源。",
    "刷新集群",
    ["工作负载", "事件", "资源"]
);
blueprint!(
    quick_detection,
    "按计划执行应急检测并保存证据。",
    "新建检测",
    ["检测模块", "执行结果", "修复计划"]
);
blueprint!(
    security_reference,
    "离线安全速查与命令参考。",
    "搜索速查",
    ["收藏", "Linux", "网络"]
);
blueprint!(
    emergency_commands,
    "以计划、确认和审计方式执行应急动作。",
    "创建命令计划",
    ["命令工作台", "执行结果", "回滚"]
);
blueprint!(
    log_analysis,
    "采集、筛选并关联分析远端日志。",
    "选择日志",
    ["数据源", "时间线", "规则命中"]
);
blueprint!(
    packet_capture,
    "受控抓包、流量查看与证据导出。",
    "配置抓包",
    ["接口", "实时数据", "证据"]
);
blueprint!(
    check_audit,
    "核查账号、服务、网络与安全配置。",
    "开始核查",
    ["核查项", "发现", "建议"]
);
blueprint!(
    integrity,
    "建立和比较文件完整性基线。",
    "选择目录",
    ["基线", "差异", "历史"]
);
blueprint!(
    notes,
    "记录并整理目标调查笔记。",
    "新建笔记",
    ["笔记列表", "编辑器", "附件索引"]
);
blueprint!(
    firewall,
    "审阅并计划边界隔离与恢复。",
    "创建隔离计划",
    ["当前规则", "隔离计划", "恢复记录"]
);
blueprint!(
    snapshot,
    "保存主机取证快照并比较变化。",
    "创建快照",
    ["快照", "差异", "导出"]
);
blueprint!(
    baseline_quick_edit,
    "计划基线修复、验证并保留恢复命令。",
    "选择基线",
    ["基线模板", "变更计划", "验证"]
);
blueprint!(
    database,
    "连接数据库并安全执行查询与巡检。",
    "选择连接",
    ["连接", "查询", "历史"]
);
blueprint!(
    middleware,
    "无损查看、校验、应用并恢复常见中间件配置。",
    "扫描中间件",
    ["实例与健康", "完整配置", "变更与恢复"]
);
blueprint!(
    java_hot_update,
    "分析并执行受控 Java 热更新。",
    "选择进程",
    ["JVM", "类与方法", "部署记录"]
);
blueprint!(
    batch_servers,
    "对多个目标计划和执行一致的任务。",
    "创建批量任务",
    ["目标", "任务模板", "结果"]
);
blueprint!(
    ai_history,
    "离线查看 AI 分析历史；联网调用由明确配置控制。",
    "筛选历史",
    ["会话", "提示词", "结果"]
);
blueprint!(
    config_generator,
    "从受控模板快速生成可审阅的服务配置。",
    "生成配置",
    ["配置类型", "参数", "预览与导出"]
);

pub const PAGE_DESCRIPTORS: [PageDescriptor; 20] = [
    PageDescriptor {
        id: PageId::SystemInfo,
        group: PageGroup::Target,
        title: "主机全景",
        icon: "◎",
        capability: CapabilityRequirement::ConnectedTarget,
        create: system_info,
    },
    PageDescriptor {
        id: PageId::Docker,
        group: PageGroup::Target,
        title: "Docker",
        icon: "▣",
        capability: CapabilityRequirement::ConnectedTarget,
        create: docker,
    },
    PageDescriptor {
        id: PageId::Kubernetes,
        group: PageGroup::Target,
        title: "Kubernetes",
        icon: "⬡",
        capability: CapabilityRequirement::ConnectedTarget,
        create: kubernetes,
    },
    PageDescriptor {
        id: PageId::QuickDetection,
        group: PageGroup::Triage,
        title: "快速检测",
        icon: "⌁",
        capability: CapabilityRequirement::ConnectedTarget,
        create: quick_detection,
    },
    PageDescriptor {
        id: PageId::SecurityReference,
        group: PageGroup::Triage,
        title: "安全速查",
        icon: "◇",
        capability: CapabilityRequirement::LocalWorkspace,
        create: security_reference,
    },
    PageDescriptor {
        id: PageId::EmergencyCommands,
        group: PageGroup::Triage,
        title: "命令工作台",
        icon: ">_",
        capability: CapabilityRequirement::ConnectedTarget,
        create: emergency_commands,
    },
    PageDescriptor {
        id: PageId::LogAnalysis,
        group: PageGroup::Investigation,
        title: "日志分析",
        icon: "≡",
        capability: CapabilityRequirement::ConnectedTarget,
        create: log_analysis,
    },
    PageDescriptor {
        id: PageId::PacketCapture,
        group: PageGroup::Investigation,
        title: "网络抓包",
        icon: "⌁",
        capability: CapabilityRequirement::ConnectedTarget,
        create: packet_capture,
    },
    PageDescriptor {
        id: PageId::CheckAudit,
        group: PageGroup::Investigation,
        title: "核查审计",
        icon: "✓",
        capability: CapabilityRequirement::ConnectedTarget,
        create: check_audit,
    },
    PageDescriptor {
        id: PageId::Integrity,
        group: PageGroup::Investigation,
        title: "文件完整性",
        icon: "◆",
        capability: CapabilityRequirement::ConnectedTarget,
        create: integrity,
    },
    PageDescriptor {
        id: PageId::Notes,
        group: PageGroup::Investigation,
        title: "Notes",
        icon: "✎",
        capability: CapabilityRequirement::LocalWorkspace,
        create: notes,
    },
    PageDescriptor {
        id: PageId::Firewall,
        group: PageGroup::Response,
        title: "边界隔离",
        icon: "⛨",
        capability: CapabilityRequirement::ConnectedTarget,
        create: firewall,
    },
    PageDescriptor {
        id: PageId::Snapshot,
        group: PageGroup::Response,
        title: "取证快照",
        icon: "◉",
        capability: CapabilityRequirement::ConnectedTarget,
        create: snapshot,
    },
    PageDescriptor {
        id: PageId::BaselineQuickEdit,
        group: PageGroup::Response,
        title: "基线修复",
        icon: "⌘",
        capability: CapabilityRequirement::ConnectedTarget,
        create: baseline_quick_edit,
    },
    PageDescriptor {
        id: PageId::Database,
        group: PageGroup::Operations,
        title: "数据库",
        icon: "▤",
        capability: CapabilityRequirement::ConnectedTarget,
        create: database,
    },
    PageDescriptor {
        id: PageId::Middleware,
        group: PageGroup::Operations,
        title: "中间件",
        icon: "⚙",
        capability: CapabilityRequirement::ConnectedTarget,
        create: middleware,
    },
    PageDescriptor {
        id: PageId::JavaHotUpdate,
        group: PageGroup::Operations,
        title: "Java 热更新",
        icon: "♨",
        capability: CapabilityRequirement::ConnectedTarget,
        create: java_hot_update,
    },
    PageDescriptor {
        id: PageId::BatchServers,
        group: PageGroup::Operations,
        title: "多机批量",
        icon: "▦",
        capability: CapabilityRequirement::ConnectedTarget,
        create: batch_servers,
    },
    PageDescriptor {
        id: PageId::AiHistory,
        group: PageGroup::Intelligence,
        title: "AI 历史",
        icon: "✦",
        capability: CapabilityRequirement::OptionalAi,
        create: ai_history,
    },
    PageDescriptor {
        id: PageId::ConfigGenerator,
        group: PageGroup::Operations,
        title: "配置生成",
        icon: "▧",
        capability: CapabilityRequirement::LocalWorkspace,
        create: config_generator,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageLease {
    pub page: PageId,
    pub generation: u64,
}

#[derive(Debug)]
pub struct PageLifecycle {
    active: PageId,
    generation: u64,
}

impl PageLifecycle {
    pub fn new(initial: PageId) -> Self {
        Self {
            active: initial,
            generation: 1,
        }
    }

    pub fn activate(&mut self, page: PageId) -> PageLease {
        if self.active != page {
            self.active = page;
            self.generation = self.generation.wrapping_add(1).max(1);
        }
        self.lease()
    }

    pub const fn lease(&self) -> PageLease {
        PageLease {
            page: self.active,
            generation: self.generation,
        }
    }

    pub const fn active(&self) -> PageId {
        self.active
    }

    pub fn accepts(&self, lease: PageLease) -> bool {
        self.lease() == lease
    }
}

#[derive(Debug)]
pub struct PageHost {
    lifecycle: PageLifecycle,
}

impl PageHost {
    pub fn new(initial: PageId) -> Self {
        Self {
            lifecycle: PageLifecycle::new(initial),
        }
    }

    pub const fn active(&self) -> PageId {
        self.lifecycle.active()
    }

    pub fn activate(&mut self, page: PageId) -> PageLease {
        self.lifecycle.activate(page)
    }

    pub const fn lease(&self) -> PageLease {
        self.lifecycle.lease()
    }

    pub fn accepts(&self, lease: PageLease) -> bool {
        self.lifecycle.accepts(lease)
    }

    pub fn model(&self) -> PageModel {
        PageModel::for_page(self.active())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn all_pages_have_one_descriptor_and_factory() {
        assert_eq!(PageId::ALL.len(), 20);
        let ids: HashSet<_> = PAGE_DESCRIPTORS.iter().map(|page| page.id).collect();
        assert_eq!(ids.len(), PageId::ALL.len());
        for (index, id) in PageId::ALL.iter().copied().enumerate() {
            let descriptor = id.descriptor();
            assert_eq!(descriptor.id, id);
            assert_eq!(descriptor.id as usize, index);
            assert!(!(descriptor.create)().sections.is_empty());
        }
    }

    #[test]
    fn navigation_invalidates_old_async_results() {
        let mut lifecycle = PageLifecycle::new(PageId::SystemInfo);
        let old = lifecycle.lease();
        lifecycle.activate(PageId::Docker);
        assert!(!lifecycle.accepts(old));
        assert!(lifecycle.accepts(lifecycle.lease()));
    }

    #[test]
    fn page_host_only_marks_fully_wired_pages_as_implemented() {
        let mut host = PageHost::new(PageId::SystemInfo);
        let first = host.lease();
        assert_eq!(host.model().status(), PageImplementationStatus::Pending);
        host.activate(PageId::SecurityReference);
        assert_eq!(host.active(), PageId::SecurityReference);
        assert!(!host.accepts(first));
        let PageModel::Implemented(model) = host.model() else {
            panic!("security reference must use the native implemented model");
        };
        assert_eq!(model.id, PageId::SecurityReference);
        assert_eq!(model.capability, CapabilityRequirement::LocalWorkspace);

        let PageModel::Implemented(notes) = PageModel::for_page(PageId::Notes) else {
            panic!("notes must use the native implemented model");
        };
        assert_eq!(notes.id, PageId::Notes);

        let PageModel::Implemented(ai_history) = PageModel::for_page(PageId::AiHistory) else {
            panic!("AI history must use the native implemented model");
        };
        assert_eq!(ai_history.id, PageId::AiHistory);

        let PageModel::Implemented(baseline) = PageModel::for_page(PageId::BaselineQuickEdit)
        else {
            panic!("baseline quick edit must use the native implemented model");
        };
        assert_eq!(baseline.id, PageId::BaselineQuickEdit);

        let PageModel::Implemented(java) = PageModel::for_page(PageId::JavaHotUpdate) else {
            panic!("Java hot update must use the native implemented model");
        };
        assert_eq!(java.id, PageId::JavaHotUpdate);

        let PageModel::Implemented(middleware) = PageModel::for_page(PageId::Middleware) else {
            panic!("middleware must use the native implemented model");
        };
        assert_eq!(middleware.id, PageId::Middleware);

        let PageModel::Implemented(batch) = PageModel::for_page(PageId::BatchServers) else {
            panic!("multi-host batch must use the native implemented model");
        };
        assert_eq!(batch.id, PageId::BatchServers);
        let PageModel::Implemented(generator) = PageModel::for_page(PageId::ConfigGenerator) else {
            panic!("config generator must use the native implemented model");
        };
        assert_eq!(generator.id, PageId::ConfigGenerator);
        let PageModel::Implemented(database) = PageModel::for_page(PageId::Database) else {
            panic!("database must use the native implemented model");
        };
        assert_eq!(database.id, PageId::Database);

        for page in PageId::ALL {
            if matches!(
                page,
                PageId::SecurityReference
                    | PageId::Notes
                    | PageId::Firewall
                    | PageId::BaselineQuickEdit
                    | PageId::Middleware
                    | PageId::JavaHotUpdate
                    | PageId::BatchServers
                    | PageId::AiHistory
                    | PageId::Database
                    | PageId::ConfigGenerator
            ) {
                continue;
            }
            assert_eq!(
                PageModel::for_page(page).status(),
                PageImplementationStatus::Pending,
                "{page:?} must remain pending"
            );
        }
    }
}
