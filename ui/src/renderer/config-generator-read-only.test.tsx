import { readFileSync } from "node:fs";

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { ConfigReadOnlyArtifactStatus } from "../shared/config-contract";
import { ConfigReadOnlyStatusPanel } from "./ConfigGeneratorPage";
import { selectConfigReadOnlyArtifactStatus } from "./config-generator-state";

describe("config generator read-only artifact boundary", () => {
  it("schemas_never_change_vendor_or_generated_local_draft_permission", () => {
    const artifacts: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "opengauss-om-cluster-xml",
        productKey: "opengauss",
        productTitle: "openGauss",
        title: "cluster.xml",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：厂商 schema 元数据完整性 Partial；该元数据不授予本地草稿权限。",
      },
      {
        artifactKey: "mysql-persisted-variables",
        productKey: "mysql",
        productTitle: "MySQL",
        title: "mysqld-auto.cnf",
        authority: "read-only",
        reason: "generated-artifact",
        notice: "只读展示：厂商 schema 元数据完整性 Complete；生成工件仍不授予本地草稿权限。",
      },
    ];

    for (const [artifactKey, completeness] of [
      ["opengauss-om-cluster-xml", "Partial"],
      ["mysql-persisted-variables", "Complete"],
    ] as const) {
      const selected = selectConfigReadOnlyArtifactStatus(artifacts, artifactKey);
      expect(selected).toMatchObject({ artifactKey, authority: "read-only" });
      const html = renderToStaticMarkup(
        <ConfigReadOnlyStatusPanel
          artifacts={artifacts}
          selectedArtifactKey={selected?.artifactKey ?? null}
          onSelect={vi.fn()}
        />,
      );
      expect(html).toContain(completeness);
      expect(html).toContain("data-config-mutation-authority=\"read-only\"");
      expect(html).toContain("预览、复制、另存、修改、应用和部署均不可用");
      expect(html).not.toMatch(/<button\b|<textarea\b|<pre\b|\shref=/iu);
    }
  });

  it("compatible_and_domestic_starters_do_not_guess_upstream_defaults", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("lovelyres-gpui");
    expect(source).not.toContain("database_starter_contents");

    const artifacts: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "kingbase-es-main",
        productKey: "kingbase-es",
        productTitle: "KingbaseES",
        title: "kingbase.conf",
        authority: "read-only",
        reason: "read-only-policy",
        notice: "当前工件没有经审查的产品级 starter；请导入目标实例原文件，本页不会依据 PostgreSQL 兼容方言猜测参数或端口。",
      },
      {
        artifactKey: "gbase-8c-main",
        productKey: "gbase-8c",
        productTitle: "GBase 8c",
        title: "postgresql.conf",
        authority: "read-only",
        reason: "read-only-policy",
        notice: "当前工件没有经审查的产品级 starter；请导入目标实例原文件，本页不会依据 PostgreSQL 兼容方言猜测参数或端口。",
      },
      {
        artifactKey: "tidb-server-toml",
        productKey: "tidb",
        productTitle: "TiDB",
        title: "tidb.toml",
        authority: "read-only",
        reason: "read-only-policy",
        notice: "TOML 组件参数随版本变化；请导入目标机原文件。",
      },
    ];

    for (const artifact of artifacts) {
      const html = renderToStaticMarkup(
        <ConfigReadOnlyStatusPanel
          artifacts={artifacts}
          selectedArtifactKey={artifact.artifactKey}
          onSelect={vi.fn()}
        />,
      );
      expect(html).toContain(artifact.productTitle);
      expect(html).toContain("导入");
      expect(html).toContain("data-config-mutation-authority=\"read-only\"");
      for (const guessedDefault of [
        "port = 5432",
        "port = 3306",
        "PORT_NUM = 5432",
        "password_encryption",
        "scram-sha-256",
        "bind-address",
      ]) {
        expect(html).not.toContain(guessedDefault);
      }
      expect(html).not.toMatch(/<button\b|<textarea\b|<pre\b|\shref=/iu);
    }
  });

  it("local_visual_selection_hides_managed_runtime_cloud_binary_and_unparsed_artifacts", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("lovelyres-gpui");
    for (const hiddenArtifact of [
      "mysql-runtime-variables",
      "tdsql-mysql-managed-parameter-api",
      "oceanbase-observer-binary",
      "opengauss-cluster-static-config",
    ]) {
      expect(source).not.toContain(hiddenArtifact);
    }

    const readOnlyMetadata: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "kingbase-es-repmgr",
        productKey: "kingbase-es",
        productTitle: "KingbaseES",
        title: "repmgr.conf",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读元数据：未提供经过审查的本地可视解析器。",
      },
      {
        artifactKey: "goldendb-cluster-config",
        productKey: "goldendb",
        productTitle: "GoldenDB",
        title: "goldendb-cluster-config",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读元数据：厂商 schema 工件不进入本地可视草稿。",
      },
    ];

    for (const hiddenArtifact of [
      "mysql-runtime-variables",
      "tdsql-mysql-managed-parameter-api",
      "oceanbase-observer-binary",
      "opengauss-cluster-static-config",
    ]) {
      expect(selectConfigReadOnlyArtifactStatus(readOnlyMetadata, hiddenArtifact)).toBeNull();
    }

    for (const artifact of readOnlyMetadata) {
      const html = renderToStaticMarkup(
        <ConfigReadOnlyStatusPanel
          artifacts={readOnlyMetadata}
          selectedArtifactKey={artifact.artifactKey}
          onSelect={vi.fn()}
        />,
      );
      expect(html).toContain("数据库只读工件");
      expect(html).toContain(artifact.productTitle);
      expect(html).toContain("data-config-mutation-authority=\"read-only\"");
      expect(html).toContain("目录响应不携带工件字节");
      expect(html).not.toContain("AUTHKEY");
      expect(html).not.toMatch(/<button\b|<textarea\b|<pre\b|\shref=/iu);
    }
  });

  it("unparsed_vendor_text_never_reaches_visual_rows_or_copy_boundaries", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("lovelyres-gpui");
    expect(source).not.toContain("dangerouslySetInnerHTML");

    const hostileMarkup = [
      "<script>globalThis.vendorTextExecuted=true</script>",
      "<img src=x onerror=globalThis.vendorTextExecuted=true>",
    ].join("\n");
    const metadataOnly: ConfigReadOnlyArtifactStatus[] = [{
      artifactKey: "kingbase-es-repmgr",
      productKey: "kingbase-es",
      productTitle: "KingbaseES",
      title: "repmgr.conf",
      authority: "read-only",
      reason: "vendor-schema-required",
      notice: hostileMarkup,
    }];
    const selected = selectConfigReadOnlyArtifactStatus(
      metadataOnly,
      "kingbase-es-repmgr",
    );
    expect(selected).toMatchObject({
      artifactKey: "kingbase-es-repmgr",
      authority: "read-only",
      reason: "vendor-schema-required",
    });

    const html = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={metadataOnly}
        selectedArtifactKey={selected?.artifactKey ?? null}
        onSelect={vi.fn()}
      />,
    );
    expect(html).toContain("数据库只读工件");
    expect(html).toContain("目录响应不携带工件字节");
    expect(html).toContain("&lt;script&gt;globalThis.vendorTextExecuted=true&lt;/script&gt;");
    expect(html).toContain("&lt;img src=x onerror=globalThis.vendorTextExecuted=true&gt;");
    expect(html).toContain("data-config-mutation-authority=\"read-only\"");
    expect(html).not.toContain("K9z7Q2");
    expect(html).not.toContain("AUTHKEY");
    expect(html).not.toContain("data-testid=\"config-artifact-preview-text\"");
    expect(html).not.toMatch(/<script\b|<img\b|<button\b|<textarea\b|<pre\b|\shref=/iu);
  });

  it("gbase_8s_visual_text_authkey_is_redacted_and_blocks_whole_document_copy", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("lovelyres-gpui");
    expect(source).not.toContain("dangerouslySetInnerHTML");
    expect(source).not.toContain("gbase-8s-onconfig");
    expect(source).not.toContain("gbase-8s-sqlhosts");
    expect(source).not.toContain("AUTHKEY");

    const sentinel = "K9z7Q2";
    const hostileCredential =
      "<script>globalThis.gbaseAuthkeyExecuted=true</script> AUTHKEY K9z7Q2";
    const metadataOnly: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "gbase-8s-onconfig",
        productKey: "gbase-8s",
        productTitle: "GBase 8s",
        title: "onconfig",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：匹配版本的厂商 schema 也不授予本地草稿权限。",
      },
      {
        artifactKey: "gbase-8s-sqlhosts",
        productKey: "gbase-8s",
        productTitle: "GBase 8s",
        title: "sqlhosts",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：目录响应不携带源文件内容。",
      },
    ];

    for (const artifact of metadataOnly) {
      const selected = selectConfigReadOnlyArtifactStatus(metadataOnly, artifact.artifactKey);
      expect(selected).toMatchObject({
        artifactKey: artifact.artifactKey,
        authority: "read-only",
        reason: "vendor-schema-required",
      });
      const html = renderToStaticMarkup(
        <ConfigReadOnlyStatusPanel
          artifacts={metadataOnly}
          selectedArtifactKey={artifact.artifactKey}
          onSelect={vi.fn()}
        />,
      );
      expect(html).toContain(`value=\"${artifact.artifactKey}\"`);
      expect(html).toContain(`GBase 8s · ${artifact.title}`);
      expect(html).toContain("data-config-mutation-authority=\"read-only\"");
      expect(html).toContain("目录响应不携带工件字节");
      expect(html).toContain("预览、复制、另存、修改、应用和部署均不可用");
      expect(html).not.toContain(hostileCredential);
      expect(html).not.toContain("gbaseAuthkeyExecuted");
      expect(html).not.toContain("AUTHKEY");
      expect(html).not.toContain(sentinel);
      expect(html).not.toContain("[sensitive value redacted]");
      expect(html).not.toContain("data-testid=\"config-artifact-preview-text\"");
      expect(html).not.toMatch(/<script\b|<button\b|<textarea\b|<pre\b|\shref=/iu);
    }
  });

  it("dm_dcr_array_and_startup_command_payloads_never_reach_the_generic_ini_editor", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("lovelyres-gpui");
    expect(source).not.toContain("dangerouslySetInnerHTML");
    expect(source).not.toContain("DCR_GRP_NAME");
    expect(source).not.toContain("DMDCR_DB_STARTUP_CMD");

    const metadataOnly: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "dm-dcr-config",
        productKey: "dm",
        productTitle: "达梦数据库",
        title: "dmdcr_cfg.ini",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "<script>globalThis.dcrExecuted=true</script>",
      },
      {
        artifactKey: "dm-dcr-node",
        productKey: "dm",
        productTitle: "达梦数据库",
        title: "dmdcr.ini",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读元数据：DCR startup command 不进入通用 INI 编辑器。",
      },
    ];

    for (const artifact of metadataOnly) {
      const html = renderToStaticMarkup(
        <ConfigReadOnlyStatusPanel
          artifacts={metadataOnly}
          selectedArtifactKey={artifact.artifactKey}
          onSelect={vi.fn()}
        />,
      );
      expect(html).toContain(`value=\"${artifact.artifactKey}\"`);
      expect(html).toContain("达梦数据库");
      expect(html).toContain("数据库只读工件");
      expect(html).toContain("目录响应不携带工件字节");
      expect(html).toContain("data-config-mutation-authority=\"read-only\"");
      expect(html).not.toContain("DCR_GRP_NAME");
      expect(html).not.toContain("DMDCR_DB_STARTUP_CMD");
      expect(html).not.toContain("dmserver");
      expect(html).not.toContain("NeverShow42");
      expect(html).not.toContain("data-testid=\"config-artifact-preview-text\"");
      expect(html).not.toMatch(/<script\b|<button\b|<textarea\b|<pre\b|\shref=/iu);
      if (artifact.artifactKey === "dm-dcr-config") {
        expect(html).toContain("&lt;script&gt;globalThis.dcrExecuted=true&lt;/script&gt;");
      }
    }
  });

  it("dm_init_password_is_redacted_non_copyable_and_rejects_ordinary_updates", () => {
    const source = readFileSync(new URL("./ConfigGeneratorPage.tsx", import.meta.url), "utf8");
    expect(source).not.toContain("lovelyres-gpui");
    expect(source).not.toContain("dangerouslySetInnerHTML");
    expect(source).not.toContain("dm-init");
    expect(source).not.toContain("SYSDBA_PWD");

    const productionMetadata: ConfigReadOnlyArtifactStatus[] = [{
      artifactKey: "mysql-server-uuid",
      productKey: "mysql",
      productTitle: "MySQL",
      title: "auto.cnf",
      authority: "read-only",
      reason: "generated-artifact",
      notice: "只读展示：服务器生成工件。",
    }];
    expect(selectConfigReadOnlyArtifactStatus(productionMetadata, "dm-init")).toBeNull();
    const unavailableHtml = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={productionMetadata}
        selectedArtifactKey="dm-init"
        onSelect={vi.fn()}
      />,
    );
    expect(unavailableHtml).toBe("");

    const hostileInput = "<script>globalThis.dmInitExecuted=true</script> password=EchoMe";
    const fixedRedactionMetadata: ConfigReadOnlyArtifactStatus[] = [{
      artifactKey: "dm-init",
      productKey: "dm",
      productTitle: "达梦数据库",
      title: "dminit.ini",
      authority: "read-only",
      reason: "read-only-policy",
      notice: "固定脱敏：[sensitive value redacted]",
    }];
    const html = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={fixedRedactionMetadata}
        selectedArtifactKey="dm-init"
        onSelect={vi.fn()}
      />,
    );
    expect(html).toContain("[sensitive value redacted]");
    expect(html).toContain("data-config-mutation-authority=\"read-only\"");
    expect(html).toContain("预览、复制、另存、修改、应用和部署均不可用");
    expect(html).not.toContain(hostileInput);
    expect(html).not.toContain("dmInitExecuted");
    expect(html).not.toContain("NeverShow42");
    expect(html).not.toContain("SYSDBA_PWD");
    expect(html).not.toContain("EchoMe");
    expect(html).not.toContain("data-testid=\"config-artifact-preview-text\"");
    expect(html).not.toMatch(/<script\b|<button\b|<textarea\b|<pre\b|\shref=/iu);
  });

  it("renders YashanDB 23.5.4.100 schema as notice-only metadata without mutation or save authority", () => {
    const artifacts: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "yashandb-yasdb-ini",
        productKey: "yashandb",
        productTitle: "崖山数据库",
        title: "yasdb.ini",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：仅公开 schema 元数据；精确 build 23.5.4.100；文档族 official-doc-family-23.5.4.100；完整性 Partial。该元数据只用于显示，绝不会写入目标内容、本地草稿或另存文件，也不授予修改权限。",
      },
    ];
    const selected = selectConfigReadOnlyArtifactStatus(
      artifacts,
      "yashandb-yasdb-ini",
    );
    expect(selected).toMatchObject({
      artifactKey: "yashandb-yasdb-ini",
      productKey: "yashandb",
      title: "yasdb.ini",
      authority: "read-only",
      reason: "vendor-schema-required",
    });

    const html = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={artifacts}
        selectedArtifactKey={selected?.artifactKey ?? null}
        onSelect={vi.fn()}
      />,
    );
    expect(html).toContain("崖山数据库 · yasdb.ini");
    expect(html).toContain("23.5.4.100");
    expect(html).toContain("official-doc-family-23.5.4.100");
    expect(html).toContain("Partial");
    expect(html).toContain("只用于显示");
    expect(html).toContain("绝不会写入目标内容、本地草稿或另存文件");
    expect(html).toContain("不授予修改权限");
    expect(html).not.toContain("当前仅允许预览");
    expect(html).toContain("data-config-read-only-reason=\"vendor-schema-required\"");
    expect(html).toContain("data-config-mutation-authority=\"read-only\"");
    expect(html).toContain("预览、复制、另存、修改、应用和部署均不可用");
    expect(html).not.toContain("RUN_LOG_LEVEL");
    expect(html).not.toContain("INFO");
    expect(html).not.toMatch(/<button\b|<textarea\b|<pre\b|\shref=/iu);
  });

  it("selects auto.cnf while preview copy save and mutation remain unavailable", () => {
    const artifacts: ConfigReadOnlyArtifactStatus[] = [
      {
        artifactKey: "opengauss-om-cluster-xml",
        productKey: "opengauss",
        productTitle: "openGauss",
        title: "opengauss-om-cluster-xml",
        authority: "read-only",
        reason: "vendor-schema-required",
        notice: "只读展示：需要匹配产品/版本的厂商 schema。",
      },
      {
        artifactKey: "mysql-server-uuid",
        productKey: "mysql",
        productTitle: "MySQL",
        title: "auto.cnf",
        authority: "read-only",
        reason: "generated-artifact",
        notice: "只读展示：该工件由服务器或厂商工具生成；所有结构修改均已禁用。",
      },
    ];
    const selected = selectConfigReadOnlyArtifactStatus(artifacts, "mysql-server-uuid");
    expect(selected).toMatchObject({
      artifactKey: "mysql-server-uuid",
      productKey: "mysql",
      title: "auto.cnf",
      authority: "read-only",
      reason: "generated-artifact",
    });

    const html = renderToStaticMarkup(
      <ConfigReadOnlyStatusPanel
        artifacts={artifacts}
        selectedArtifactKey={selected?.artifactKey ?? null}
        onSelect={vi.fn()}
      />,
    );
    expect(html).toContain("value=\"mysql-server-uuid\" selected=\"\"");
    expect(html).toContain("MySQL · auto.cnf");
    expect(html).toContain("data-config-read-only-reason=\"generated-artifact\"");
    expect(html).toContain("data-config-mutation-authority=\"read-only\"");
    expect(html).toContain("只读展示");
    expect(html).toContain("生成");
    expect(html).toContain("目录响应不携带工件字节");
    expect(html).toContain("预览、复制、另存、修改、应用和部署均不可用");
    expect(html).not.toMatch(/<button\b|<textarea\b|<pre\b|\shref=/iu);
  });
});
