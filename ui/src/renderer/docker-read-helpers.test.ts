import { describe, expect, it } from "vitest";

import { dockerStateText, dockerStatusText } from "./docker-read-helpers";

describe("Docker state and status in words", () => {
  it("names the states, and shows one it does not know as it came", () => {
    expect(dockerStateText("running")).toBe("运行中");
    expect(dockerStateText("exited")).toBe("已停止");
    expect(dockerStateText("paused")).toBe("已暂停");
    expect(dockerStateText("restarting")).toBe("重启中");
    expect(dockerStateText("frozen")).toBe("frozen");
    expect(dockerStateText("")).toBe("—");
  });

  it("translates the status line the runtime writes", () => {
    expect(dockerStatusText("Up 4 minutes")).toBe("已运行 4 分钟");
    expect(dockerStatusText("Up About a minute")).toBe("已运行 约 1 分钟");
    expect(dockerStatusText("Up About an hour")).toBe("已运行 约 1 小时");
    expect(dockerStatusText("Up Less than a second")).toBe("已运行 不到 1 秒");
    expect(dockerStatusText("Up 3 days (healthy)")).toBe("已运行 3 天，健康检查通过");
    expect(dockerStatusText("Up 2 hours (unhealthy)")).toBe("已运行 2 小时，健康检查未通过");
    expect(dockerStatusText("Up 10 seconds (health: starting)")).toBe("已运行 10 秒，健康检查进行中");
    expect(dockerStatusText("Up 5 minutes (Paused)")).toBe("已运行 5 分钟，已暂停");
    expect(dockerStatusText("Exited (0) 53 seconds ago")).toBe("53 秒前退出，退出码 0");
    expect(dockerStatusText("Exited (137) 2 hours ago")).toBe("2 小时前退出，退出码 137");
    expect(dockerStatusText("Restarting (1) 5 seconds ago")).toBe("重启中，5 秒前以退出码 1 结束");
    expect(dockerStatusText("Created")).toBe("已创建，还没启动");
  });

  it("leaves a line it does not recognise exactly as written", () => {
    // A wrong translation would be worse than English.
    for (const line of ["Up 2 fortnights", "Exited (0) yesterday", "Something new", "Up"]) {
      expect(dockerStatusText(line)).toBe(line);
    }
    expect(dockerStatusText("")).toBe("—");
  });
});
