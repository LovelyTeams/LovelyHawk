// Additional real desktop checks, exclusively against the parent's owned fixture.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { accessScenario } from "./postgresql-access-scenario.mjs";
import { processScenario } from "./postgresql-process-scenario.mjs";

export async function observationScenario({ dataRoot, page, host, rpc, binding, read, click, uiWait, until, sql, script, check, observations, registerAccessCanary }) {
  const lastJob = async () => (await rpc("poll", { jobHandle: await host.lastJobHandle() })).job;
  const caseRpc = (action, fields = {}) => page.evaluate(`window.lovelyhawk.caseWorkspace(${JSON.stringify({ action, bindingHandle: binding, ...fields })})`);
  const selectCurrentProfile = async () => {
    await click(".database-toolbar button", "刷新连接");
    await uiWait("[...document.querySelectorAll('.database-toolbar button')].some(b=>b.textContent==='读取数据库状态'&&!b.disabled)", "current profile ready");
  };
  const retainRead = async (expected = "读取完成") => {
    await read(expected, "读取并留证");
    return lastJob();
  };
  observations.desktopPhase = "native session and configuration origins";
  await until(() => sql("SELECT count(*) FROM pg_locks WHERE relation='pg_catalog.pg_settings'::regclass AND mode='AccessExclusiveLock' AND granted") === "0", "previous cancellation fixture lock released");
  await read();
  let current = await lastJob();
  const independent = JSON.parse(sql("SELECT json_build_object('cluster', (SELECT system_identifier::text FROM pg_control_system()), 'oid', (SELECT oid::bigint FROM pg_database WHERE datname=current_database()), 'start', to_char(pg_postmaster_start_time() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), 'config', current_setting('config_file'))"));
  check("native session identity matches independent cluster, database and server-start observations", current.state === "completed" && current.result.session.clusterIdentifier === independent.cluster && current.result.session.databaseOid === independent.oid && current.result.session.serverStartedAt === independent.start && current.result.session.serverAddress === "127.0.0.1" && current.result.session.backendPid > 0);
  check("server-reported configuration locations are visible without becoming operations", current.result.session.paths.find(p => p.name === "config_file").path === independent.config && !Object.hasOwn(current.result.session, "command"));
  observations.sessionIdentity = current.result.session;
  await processScenario({ current, read, lastJob, script, sql, page, check, until, observations });
  await accessScenario({ dataRoot, page, host, read, lastJob, rpc, click, uiWait, script, sql, check, observations, registerAccessCanary });
  script("printf '\ninclude = \\047lovelyres-origin.conf\\047\n' >> /var/lib/postgresql/data/postgresql.conf\nprintf 'log_statement = \\047none\\047\n' > /var/lib/postgresql/data/lovelyres-origin.conf\nchown postgres:postgres /var/lib/postgresql/data/lovelyres-origin.conf\n");
  sql("SELECT pg_reload_conf()");
  await until(() => sql("SELECT sourcefile FROM pg_settings WHERE name='log_statement'").endsWith("/lovelyres-origin.conf"), "included origin loaded");
  await read(); current = await lastJob();
  const catalogOrigins = JSON.parse(sql("SELECT json_agg(json_build_object('name',name,'path',sourcefile,'line',sourceline)) FROM pg_settings WHERE name IN ('log_statement','ssl')"));
  check("include and ALTER SYSTEM origins match PostgreSQL's independent catalog including line numbers", catalogOrigins.every(expected => { const actual = current.result.session.origins.find(o => o.name === expected.name); return actual.sourceFile === expected.path && actual.sourceLine === expected.line; }) && catalogOrigins.find(o => o.name === "ssl").path.endsWith("postgresql.auto.conf"));
  // A changed disk file without reload must not be promoted to an active setting.
  script("printf 'log_statement = \\047all\\047\n' > /var/lib/postgresql/data/lovelyres-origin.conf\n");
  await read(); current = await lastJob();
  check("an un-reloaded disk edit does not replace the observed runtime value", current.result.observations.find(r => r.name === "log_statement").value === "none" && sql("SHOW log_statement") === "none");
  script("printf 'log_statement = \\047none\\047\n' > /var/lib/postgresql/data/lovelyres-origin.conf\n");
  const profile = (await rpc("list")).profiles[0], editor = await rpc("edit", { profileHandle: profile.profileHandle });
  const input = { name: profile.name, host: profile.host, port: profile.port, username: profile.username, database: profile.database, tlsMode: profile.tlsMode, caPem: editor.caPem };
  sql("GRANT SELECT ON pg_catalog.pg_settings TO lr_denied; REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC, lr_denied");
  const restrictedQuery = sql("SET SESSION AUTHORIZATION lr_denied;\n" + fs.readFileSync(new URL("../../crates/lovelyhawk-core/src/postgresql_observation.sql", import.meta.url), "utf8")).split(/\r?\n/u).at(-1);
  observations.restrictedBaseSessionQuery = JSON.parse(Buffer.from(restrictedQuery, "hex").toString("utf8"));
  observations.restrictedReviewNames = JSON.parse(sql("SET SESSION AUTHORIZATION lr_denied; SELECT json_agg(json_build_object('name',name,'source',source,'pending',pending_restart)) FROM pg_settings WHERE name IN ('ssl','logging_collector','log_connections','log_disconnections','password_encryption','log_statement','listen_addresses','ssl_min_protocol_version','ssl_max_protocol_version','default_transaction_read_only')").split(/\r?\n/u).at(-1));
  let saved = await rpc("save", { profileHandle: profile.profileHandle, profile: { ...input, username: "lr_denied" }, password: { action: "keep" } });
  await selectCurrentProfile(); await read(); current = await lastJob();
  check("a restricted monitoring role reads values while retaining explicit identity and source permission gaps", current.state === "completed" && current.result.session.sessionUser === "lr_denied" && current.result.session.clusterIdentifier === null && !current.result.session.clusterIdentifierReadable && !current.result.session.settingsReadable && current.result.session.paths.every(p => p.path === null) && current.result.session.origins.every(o => o.sourceFile === null && o.sourceLine === null) && current.result.hostProcess.state === "matched" && current.result.hostProcess.process.reportedDirectoryMatches === null);
  check("restricted native access diagnostics retain parameter results, HBA/ident gaps and public roles", current.result.access.hba.reason === "permission-denied" && current.result.access.ident.reason === "permission-denied" && current.result.access.roles.state === "available" && !current.result.access.passwordClassification);
  const restrictedRoles = await rpc("access-rows", { jobHandle: current.jobHandle, section: "roles", query: "", offset: 0 });
  check("restricted role pages contain no private password classification", restrictedRoles.kind === "access-rows" && restrictedRoles.rows.length > 0 && restrictedRoles.rows.every(r => r.passwordKind === "unavailable"));
  check("role-hidden TLS settings remain explicit unknowns while visible values are usable", current.result.session.origins.filter(o => o.source === null).map(o => o.name).join(",") === "ssl_min_protocol_version,ssl_max_protocol_version" && !current.result.observations.some(o => o.name.startsWith("ssl_")) && await page.evaluate("document.querySelector('.database-session').textContent.includes('2 项重点参数未取得：ssl_min_protocol_version、ssl_max_protocol_version')"));
  await page.evaluate("if(!document.querySelector('.database-mode input').checked)document.querySelector('.database-mode input').click()");
  await page.evaluate("document.querySelector('.database-source-details').open=true");
  check("beginner and expert language does not treat hidden origins as a clean baseline", await page.evaluate("document.querySelector('.database-session').textContent.includes('没有完整参数来源读取权限')&&document.querySelector('.database-session').textContent.includes('未取得路径')"));
  await page.evaluate("document.querySelector('.database-session').scrollIntoView({block:'start'})"); await page.shot("restricted-sources-1080x700.png");
  sql("REVOKE SELECT ON pg_catalog.pg_auth_members FROM PUBLIC");
  try {
    await read(); const gap = await lastJob();
    check("restricted membership permission loss preserves roles and runtime values with an explicit graph gap", gap.state === "completed" && gap.result.access.roles.state === "available" && gap.result.access.memberships.reason === "permission-denied" && gap.result.access.roleGraph.reason === "memberships-unavailable");
  } finally { sql("GRANT SELECT ON pg_catalog.pg_auth_members TO PUBLIC"); }
  sql("GRANT pg_read_all_settings TO lr_denied");
  await read(); current = await lastJob();
  check("pg_read_all_settings exposes paths without implying permission to read the cluster control identifier", current.result.session.settingsReadable && current.result.session.paths.find(p => p.name === "config_file").path === independent.config && current.result.session.clusterIdentifier === null);
  saved = await rpc("save", { profileHandle: saved.profile.profileHandle, profile: input, password: { action: "keep" } });
  await selectCurrentProfile();

  observations.desktopPhase = "case retention and retry";
  const firstCase = await caseRpc("create", { title: "PostgreSQL 原始调查", mutationId: randomUUID() });
  current = await retainRead();
  check("the actual retention button saves a bounded, scoped summary into its starting case", current.retention.state === "saved" && current.retention.caseId === firstCase.caseId && current.retention.recordText.includes("未包含全部参数") && current.retention.recordText.includes("本次会话 PID") && current.retention.recordText.includes("SSH 来源：root@") && current.retention.recordText.includes("SSH 主机进程对应：采集时") && current.retention.recordText.includes(current.result.hostProcess.process.executableSha256));
  const firstRecord = current.retention;
  await page.evaluate("document.querySelector('.database-retention').scrollIntoView({block:'start'})"); await page.shot("case-retained-1080x700.png");
  const root = fs.realpathSync(dataRoot), casesFile = path.join(root, "data", "cases.json");
  if (path.dirname(root) !== fs.realpathSync(os.tmpdir()) || !/^lovelyhawk-pg-native-[A-Za-z0-9]{6}$/u.test(path.basename(root)) || fs.lstatSync(casesFile).isSymbolicLink()) throw Error("Unexpected owned case data root");
  let original, corrupt = false;
  function breakCaseStore() {
    original = fs.readFileSync(casesFile); const document = JSON.parse(original.toString());
    if (!document.data.cases.some(c => c.id === firstCase.caseId)) throw Error("Missing owned case identity");
    fs.writeFileSync(casesFile, "owned-lab-save-failure"); corrupt = true;
  }
  function restoreCaseStore() {
    if (!corrupt) return;
    if (fs.readFileSync(casesFile, "utf8") !== "owned-lab-save-failure") throw Error("Case store changed during owned failure fixture");
    fs.writeFileSync(casesFile, original); corrupt = false;
  }
  const lock = () => script("runuser -u postgres -- sh -c 'psql -X -w -v ON_ERROR_STOP=1 -d postgres -c \"BEGIN; LOCK TABLE pg_catalog.pg_settings IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(9); COMMIT;\" >/tmp/pg-observation-lock.log 2>&1 &'\n");
  const locked = () => Number(sql("SELECT count(*) FROM pg_locks WHERE relation='pg_catalog.pg_settings'::regclass AND mode='AccessExclusiveLock' AND granted")) > 0;
  try {
    lock(); await until(locked, "owned settings lock");
    await click(".database-toolbar button", "读取并留证");
    await uiWait("document.querySelector('.database-result h3')?.textContent==='正在读取'", "reading with captured case");
    const captured = await lastJob();
    check("case destination is captured while the real PostgreSQL read is pending", captured.retention.state === "pending" && captured.retention.caseId === firstCase.caseId);
    breakCaseStore();
    await uiWait("document.querySelector('.database-retention h4')?.textContent==='检查摘要尚未保存'", "actual case persistence failure");
    current = await lastJob(); const failedRecord = current.retention.recordText;
    check("a failed database read and failed local save preserve the exact original summary", current.state === "failed" && current.retention.canRetry && failedRecord.includes("读取失败") && current.retention.caseId === firstCase.caseId && fs.readFileSync(casesFile, "utf8") === "owned-lab-save-failure");
    await click(".nav-item", "主机全景"); await uiWait("document.querySelector('[role=dialog]')!==null", "unsaved summary navigation confirmation"); await click("[role=dialog] button", "取消");
    check("cancelled navigation preserves unsaved database evidence and blocks replacement reads", await page.evaluate(`document.querySelector('.database-retention textarea').value===${JSON.stringify(failedRecord)}&&[...document.querySelectorAll('.database-toolbar button')].find(b=>b.textContent==='读取数据库状态').disabled`));
    await host.requestWindowClose();
    await uiWait("document.querySelector('[role=dialog]')!==null", "unsaved summary native window-close confirmation"); await click("[role=dialog] button", "取消");
    check("cancelling the real window close preserves the unretained summary", await page.evaluate(`document.querySelector('.database-retention textarea').value===${JSON.stringify(failedRecord)}`));
    await page.evaluate("document.querySelector('.database-retention').scrollIntoView({block:'start'})"); await page.shot("case-save-failure-1080x700.png");
    restoreCaseStore();
    const later = await caseRpc("create", { title: "PostgreSQL 后续调查", mutationId: randomUUID() });
    const actionsBefore = await host.actionCount("begin");
    await click(".database-retention button", "重试留证"); await uiWait("document.querySelector('.database-retention h4')?.textContent==='检查摘要已留证'", "retry saved");
    current = await lastJob();
    check("retry stores the same failure summary in the original case after active-case changes, without recollection", current.retention.caseId === firstCase.caseId && current.retention.recordText === failedRecord && (await caseRpc("list")).activeCaseId === later.caseId && await host.actionCount("begin") === actionsBefore);
    const replay = await rpc("retain", { jobHandle: current.jobHandle });
    check("repeating a saved retention request returns the same evidence identity", replay.job.retention.evidenceId === current.retention.evidenceId && replay.job.retention.sha256 === current.retention.sha256);
    await until(() => !locked(), "owned lock releases");
    breakCaseStore(); current = await retainRead();
    check("failure to select a case leaves a complete readable summary with explicit retry semantics", current.retention.state === "unsaved" && current.retention.caseId === null && current.retention.canRetry);
    restoreCaseStore();
    const beforeDiscard = fs.readFileSync(casesFile, "utf8");
    await click(".database-retention button", "放弃本次未保存摘要"); await uiWait("document.querySelector('[role=dialog]')!==null", "discard summary confirmation"); await click("[role=dialog] button", "取消");
    check("cancelling explicit discard leaves the complete summary available", await page.evaluate("document.querySelector('.database-retention textarea').value.includes('PostgreSQL 检查摘要 v5')"));
    await click(".database-retention button", "放弃本次未保存摘要"); await uiWait("document.querySelector('[role=dialog]')!==null", "second discard confirmation"); await click("[role=dialog] button", "放弃本次未保存摘要");
    await uiWait("document.querySelector('.database-retention')===null", "unsaved summary discarded");
    check("confirmed discard only releases the unsaved observation and preserves existing case records", fs.readFileSync(casesFile, "utf8") === beforeDiscard);
    lock(); await until(locked, "owned cancellation lock");
    await click(".database-toolbar button", "读取并留证"); await uiWait("document.querySelector('.database-result h3')?.textContent==='正在读取'", "cancellable retained read");
    await click(".database-toolbar button", "取消读取"); await uiWait("document.querySelector('.database-result h3')?.textContent==='读取已取消'", "retained cancellation");
    current = await lastJob();
    check("cancelling a real read saves a cancellation record without inventing parameters", current.retention.state === "saved" && current.retention.recordText.includes("用户取消") && current.result === null && current.retention.caseId === later.caseId);
    await until(() => sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='LovelyHawk runtime review'") === "0", "cancelled backend closed");
    const view = await caseRpc("view", { caseId: firstCase.caseId });
    const entries = await caseRpc("items", { snapshotHandle: view.snapshotHandle, section: "evidence", query: "", offset: 0 });
    check("the case workspace exposes original summary text and stored-record hash scope", entries.items.length === 2 && entries.items.some(e => e.text === firstRecord.recordText && e.sha256 === firstRecord.sha256 && e.hashScope === "stored-preview") && entries.items.some(e => e.text === failedRecord));
    const report = await caseRpc("report", { snapshotHandle: view.snapshotHandle });
    const content = await page.evaluate(`window.lovelyhawk.getDisposalReportContent(${JSON.stringify(binding)},${JSON.stringify(report.report.handle)},'markdown')`);
    check("case report contains database identity, failure history and scoped integrity explanation", report.report.evidenceCount === 2 && content.content.includes(independent.cluster) && content.content.includes("读取失败") && content.content.includes("postgresql-runtime-summary/v5") && content.content.includes(firstRecord.sha256));
    await caseRpc("select", { caseId: firstCase.caseId });
    await click(".nav-item", "案件工作台"); await uiWait("document.querySelector('.case-entry')?.textContent.includes('PostgreSQL 检查摘要')", "native case page database evidence");
    check("the visible case workbench renders the persisted PostgreSQL records", await page.evaluate("document.querySelector('.case-workspace').textContent.includes('读取失败')&&document.querySelector('.case-workspace').textContent.includes('本次会话 PID')"));
    await page.shot("postgresql-case-workspace.png");
    await click(".nav-item", "数据库"); await uiWait("document.querySelector('.database-toolbar select')?.value", "return to database");
    await until(() => !locked(), "owned cancellation lock releases");
    observations.retainedCases = { originalCaseId: firstCase.caseId, laterCaseId: later.caseId, originalEvidenceCount: entries.items.length, firstSha256: firstRecord.sha256 };
  } finally { restoreCaseStore(); }
}
