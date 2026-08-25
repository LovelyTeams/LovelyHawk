import type {
  DockerCollectionKind,
  DockerContainerItem,
  DockerSecuritySeverity,
} from "../shared/docker-read-contract";
import type { DockerTab } from "./docker-read-state";

export function dockerReadScope(
  bindingHandle: string,
): string {
  return bindingHandle;
}

export function dockerCollectionForTab(tab: DockerTab): DockerCollectionKind | null {
  switch (tab) {
    case "containers": return "stats";
    case "images": return "images";
    case "networks": return "networks";
    case "volumes": return "volumes";
    case "compose-projects": return "compose-projects";
    case "security": return null;
  }
}

export function dockerTabLabel(tab: DockerTab): string {
  switch (tab) {
    case "containers": return "容器";
    case "images": return "镜像";
    case "networks": return "网络";
    case "volumes": return "存储卷";
    case "compose-projects": return "Compose";
    case "security": return "安全审计";
  }
}

export function filterDockerContainers(
  containers: readonly DockerContainerItem[],
  query: string,
): DockerContainerItem[] {
  const needle = query.trim().toLocaleLowerCase();
  if (needle.length === 0) return [...containers];
  return containers.filter((container) => [
    container.name,
    container.image,
    container.state,
    container.status,
    container.ports,
    container.createdAt,
  ].some((value) => value.toLocaleLowerCase().includes(needle)));
}

export function dockerSecuritySeverityLabel(severity: DockerSecuritySeverity): string {
  switch (severity) {
    case "critical": return "严重";
    case "high": return "高";
    case "medium": return "中";
    case "low": return "低";
    case "info": return "信息";
  }
}

export function dockerBooleanLabel(value: boolean): string {
  return value ? "是" : "否";
}

export function dockerSnapshotMinutes(expiresInSeconds: number): string {
  return `${Math.max(1, Math.ceil(expiresInSeconds / 60))} 分钟`;
}
