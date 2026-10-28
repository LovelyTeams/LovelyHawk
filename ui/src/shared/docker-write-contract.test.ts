import { describe, expect, it } from "vitest";

import {
  isDockerActionPlan,
  isDockerContainerFile,
  isDockerFileCopyDirection,
  isDockerFilePath,
  isDockerFileText,
  isDockerPlanKind,
  MAX_DOCKER_FILE_BYTES,
} from "./docker-write-contract";

const plan = {
  planHandle: "plan-1",
  containerHandle: "container-1",
  containerName: "app-shell",
  action: "write-file",
  actionLabel: "写入文件",
  beforeState: "文件现为 120 字节",
  summary: "向 Docker 容器 56d6010d1ed5 里的 /etc/app.conf 写入 130 字节",
  dangerous: true,
  restoreDescription: "用写入前留下的备份把这个容器文件恢复原样",
  confirmed: false,
  expiresInSeconds: 300,
};

describe("container file contract", () => {
  it("accepts the two file plan kinds next to the container actions, and nothing else", () => {
    expect(isDockerPlanKind("start")).toBe(true);
    expect(isDockerPlanKind("write-file")).toBe(true);
    expect(isDockerPlanKind("copy-file")).toBe(true);
    expect(isDockerPlanKind("exec")).toBe(false);
    expect(isDockerActionPlan(plan)).toBe(true);
    expect(isDockerActionPlan({ ...plan, action: "delete-file" })).toBe(false);
  });

  it("takes only absolute file paths without control characters", () => {
    expect(isDockerFilePath("/etc/nginx/nginx.conf")).toBe(true);
    for (const bad of ["", "/", "etc/hosts", "/etc/", "/etc/ho\nsts", "/a".repeat(2_049), 7]) {
      expect(isDockerFilePath(bad), String(bad).slice(0, 20)).toBe(false);
    }
  });

  it("bounds text by UTF-8 bytes, not characters", () => {
    expect(isDockerFileText("x".repeat(MAX_DOCKER_FILE_BYTES))).toBe(true);
    expect(isDockerFileText("x".repeat(MAX_DOCKER_FILE_BYTES + 1))).toBe(false);
    // Three bytes each: fewer characters than the limit, more bytes.
    expect(isDockerFileText("界".repeat(Math.floor(MAX_DOCKER_FILE_BYTES / 3) + 1))).toBe(false);
  });

  it("accepts an opened file only when its byte count matches its text", () => {
    const file = { fileHandle: "file-1", containerHandle: "container-1", containerName: "app-shell", path: "/etc/app.conf", text: "端口=80\n", bytes: 10 };
    expect(isDockerContainerFile(file)).toBe(true);
    expect(isDockerContainerFile({ ...file, bytes: 8 })).toBe(false);
    expect(isDockerContainerFile({ ...file, path: "app.conf" })).toBe(false);
    expect(isDockerContainerFile({ ...file, extra: true })).toBe(false);
  });

  it("knows the three copy directions", () => {
    for (const direction of ["container-to-host", "host-to-container", "in-container"]) {
      expect(isDockerFileCopyDirection(direction)).toBe(true);
    }
    expect(isDockerFileCopyDirection("host-to-host")).toBe(false);
  });
});
