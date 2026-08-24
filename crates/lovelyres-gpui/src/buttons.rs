use gpui::ElementId;
use gpui_component::{IconName, button::Button};

/// Creates a LovelyRes button with a semantic, locally embedded SVG icon.
///
/// Button IDs are already stable action identifiers throughout the application, so they are
/// also the single source used to choose an icon. Callers may still override the icon with
/// `Button::icon` when the action needs a more specific glyph.
pub(crate) fn button(id: impl Into<ElementId>) -> Button {
    let id = id.into();
    let icon = icon_for_button_id(&id.to_string());
    Button::new(id).icon(icon)
}

/// Creates an icon-only close control. Keeping the accessible explanation in a tooltip avoids
/// rendering a redundant `关闭` label beside the X in dialogs and secondary panels.
pub(crate) fn close_button(id: impl Into<ElementId>) -> Button {
    button(id).tooltip("关闭")
}

pub(crate) fn icon_for_button_id(id: &str) -> IconName {
    let id = id.to_lowercase();

    if contains_any(
        &id,
        &[
            "cancel",
            "close",
            "dismiss",
            "disconnect",
            "stop",
            "terminate",
            "取消",
            "关闭",
            "断开",
            "停止",
            "终止",
        ],
    ) {
        IconName::CircleX
    } else if contains_any(
        &id,
        &[
            "delete",
            "remove",
            "clear",
            "prune",
            "quarantine",
            "删除",
            "移除",
            "清空",
            "隔离",
        ],
    ) {
        IconName::Delete
    } else if contains_any(&id, &["font", "字号", "字体"]) {
        IconName::ALargeSmall
    } else if contains_any(
        &id,
        &["restore", "rollback", "undo", "恢复", "回滚", "撤销"],
    ) {
        IconName::Undo2
    } else if contains_any(
        &id,
        &[
            "refresh",
            "reload",
            "retry",
            "reconnect",
            "reset",
            "刷新",
            "重载",
            "重试",
            "重连",
            "重置",
        ],
    ) {
        IconName::Redo2
    } else if contains_any(&id, &["copy", "复制"]) {
        IconName::Copy
    } else if contains_any(
        &id,
        &[
            "search", "find", "detect", "probe", "搜索", "查找", "检测", "探测",
        ],
    ) {
        IconName::Search
    } else if contains_any(&id, &["import", "upload", "导入", "上传"]) {
        IconName::ArrowUp
    } else if contains_any(&id, &["export", "download", "导出", "下载"]) {
        IconName::ArrowDown
    } else if contains_any(&id, &["save", "保存"]) {
        IconName::Check
    } else if contains_any(
        &id,
        &[
            "terminal", "command", "execute", "shell", "ssh", "run", "终端", "命令", "执行", "运行",
        ],
    ) {
        IconName::SquareTerminal
    } else if contains_any(
        &id,
        &[
            "settings",
            "config",
            "configure",
            "edit",
            "permission",
            "chmod",
            "设置",
            "配置",
            "编辑",
            "权限",
        ],
    ) {
        IconName::Settings
    } else if contains_any(&id, &["history", "timeline", "calendar", "历史", "时间线"]) {
        IconName::Calendar
    } else if contains_any(
        &id,
        &[
            "user", "account", "profile", "auth", "用户", "账户", "账号", "认证",
        ],
    ) {
        IconName::User
    } else if contains_any(&id, &["favorite", "star", "收藏"]) {
        IconName::Star
    } else if contains_any(
        &id,
        &[
            "detail", "inspect", "view", "info", "analysis", "report", "audit", "详情", "查看",
            "检查", "分析", "报告", "审计",
        ],
    ) {
        IconName::Inspector
    } else if contains_any(
        &id,
        &[
            "sftp",
            "folder",
            "directory",
            "path",
            "目录",
            "文件夹",
            "路径",
        ],
    ) {
        IconName::FolderOpen
    } else if contains_any(&id, &["file", "artifact", "evidence", "文件", "证据"]) {
        IconName::File
    } else if contains_any(&id, &["back", "previous", "prev", "返回", "上一"]) {
        IconName::ArrowLeft
    } else if contains_any(&id, &["next", "forward", "下一"]) {
        IconName::ArrowRight
    } else if contains_any(
        &id,
        &["new", "create", "add", "plus", "新建", "创建", "添加"],
    ) {
        IconName::Plus
    } else if contains_any(
        &id,
        &[
            "approve", "confirm", "apply", "submit", "connect", "start", "deploy", "enable",
            "确认", "应用", "提交", "连接", "开始", "部署", "启用",
        ],
    ) {
        IconName::CircleCheck
    } else if contains_any(
        &id,
        &[
            "filter", "sort", "select", "category", "strategy", "tab", "group", "筛选", "排序",
            "选择", "分类", "标签",
        ],
    ) {
        IconName::ChevronsUpDown
    } else if contains_any(&id, &["assistant", "ai", "助手"]) {
        IconName::Bot
    } else if contains_any(
        &id,
        &["theme", "light", "dark", "palette", "主题", "亮色", "暗色"],
    ) {
        IconName::Palette
    } else if contains_any(&id, &["risk", "danger", "warning", "风险", "危险", "警告"]) {
        IconName::TriangleAlert
    } else if contains_any(&id, &["open", "external", "打开"]) {
        IconName::ExternalLink
    } else {
        IconName::ChevronRight
    }
}

fn contains_any(value: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|candidate| value.contains(candidate))
}

#[cfg(test)]
mod tests {
    use gpui::AssetSource;
    use gpui_component::IconNamed;

    use super::*;
    use crate::assets::Assets;

    #[test]
    fn semantic_button_ids_map_to_local_svg_assets() {
        for (id, expected_path) in [
            ("connection-create", "icons/plus.svg"),
            ("connection-delete", "icons/delete.svg"),
            ("application-log-refresh", "icons/redo-2.svg"),
            ("command-copy-output", "icons/copy.svg"),
            ("docker-action-terminal", "icons/square-terminal.svg"),
            ("settings-save", "icons/check.svg"),
            ("返回", "icons/arrow-left.svg"),
            ("unknown-action", "icons/chevron-right.svg"),
        ] {
            let path = icon_for_button_id(id).path();
            assert_eq!(path.as_ref(), expected_path);
            assert!(
                Assets.load(path.as_ref()).unwrap().is_some(),
                "semantic icon {path} is absent from the offline asset bundle"
            );
        }
    }

    #[test]
    fn dialog_and_panel_close_actions_use_the_icon_only_control() {
        for (source, id) in [
            (include_str!("app.rs"), "application-log-close"),
            (include_str!("command_history.rs"), "command-history-close"),
            (include_str!("disposal_report.rs"), "disposal-report-close"),
            (include_str!("docker.rs"), "docker-file-close"),
            (include_str!("docker.rs"), "docker-copy-close"),
            (include_str!("log_analysis.rs"), "log-ai-close"),
            (include_str!("settings_panel.rs"), "native-settings-close"),
            (include_str!("sftp.rs"), "sftp-overlay-close"),
            (include_str!("system_info.rs"), "system-info-close-detail"),
        ] {
            assert!(
                source.contains(&format!("close_button(\"{id}\")")),
                "{id} must render as the shared icon-only close control"
            );
        }
    }
}
