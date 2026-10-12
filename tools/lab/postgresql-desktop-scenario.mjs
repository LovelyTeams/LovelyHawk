// Runs against the owned fixture supplied by probe-postgresql-native.mjs --desktop.
import fs from "node:fs";
import path from "node:path";
import { startDesktop } from "./desktop.mjs";
import { observationScenario } from "./postgresql-observation-scenario.mjs";

export async function desktopScenario({ dataRoot, evidence, name, password, check, sql, script, observations, registerAccessCanary }) {
  const errors = [];
  let app, page;
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const until = async (fn, label, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) return; await sleep(120); } throw new Error(`Timed out: ${label}`); };
  // The earlier probe read the bound SSH handle, every action name and the
  // last job handle from a wrapped main-process `postgresql.runtime` IPC handler.
  // Tauri's invoke cannot be wrapped, so the page's host commands are recorded
  // at the IPC fetch instead (desktop.mjs); requests and responses pass unchanged.
  const host = {
    lastJobHandle: async () => (await app.lastHostCall({ method: "postgresql.runtime", responseKind: "job", settled: true }))?.jobHandle ?? null,
    binding: async () => (await app.lastHostCall({ method: "postgresql.runtime" }))?.bindingHandle ?? null,
    actionCount: async action => (await app.hostCallCounts())["postgresql.runtime"]?.[action] ?? 0,
    requestWindowClose: () => app.requestClose(),
    setViewport: (width, height) => app.setViewport(width, height),
  };
  const uiWait = (expression, label) => until(() => page.evaluate(expression), label);
  const click = (selector, label) => page.evaluate(`(()=>{const button=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.includes(${JSON.stringify(label)})&&!e.disabled);if(!button)throw Error('Control missing: '+${JSON.stringify(label)});button.click();})()`);
  const field = (label, value) => page.evaluate(`(()=>{const label=[...document.querySelectorAll('.database-editor label')].find(e=>e.firstChild.textContent.trim()===${JSON.stringify(label)});const el=label?.querySelector('input,select,textarea');if(!el)throw Error('Field missing');const proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(el,${JSON.stringify(value)});el.dispatchEvent(new Event(el.tagName==='SELECT'?'change':'input',{bubbles:true}));})()`);
  const idle = () => uiWait("!document.querySelector('.database-editor') && [...document.querySelectorAll('.database-toolbar button')].some(b=>b.textContent==='编辑连接'&&!b.disabled)", "connection saved and idle");
  const read = async (expected = "读取完成", buttonLabel = "读取数据库状态") => {
    const previous = await host.lastJobHandle();
    await click(".database-toolbar button", buttonLabel);
    await until(async () => {
      if (await host.lastJobHandle() === previous) return false;
      const state = await page.evaluate("document.querySelector('.database-result h3')?.textContent ?? null");
      if (["读取完成", "读取未完成", "读取已取消", "检查结果已过期"].includes(state) && state !== expected) throw Error(`Expected ${expected}, observed ${state}`);
      return state === expected;
    }, expected);
  };
  try {
    observations.desktopPhase = "desktop startup and page attach";
    // Attached once the real main document has loaded; enabling Runtime/Log
    // replays what the page logged earlier (phase "startup").
    app = await startDesktop({ dataRoot, evidence,
      onConsoleError: entry => errors.push({ phase: entry.phase, source: entry.source, url: entry.url, detail: entry.params }) });
    const session = app.session;
    page = {
      send: (method, params) => session.send(method, params),
      shot: file => session.shot(file),
      async evaluate(expression) {
        try { return await session.evaluate(expression); }
        catch (error) { throw new Error(`CDP evaluation (page, ${observations.desktopPhase}): ${String(error)}`); }
      },
    };
    observations.desktopPhase = "record host commands and size window";
    // Only identifiers and action names are recorded; every product boundary runs unchanged.
    await app.recordHostCalls();
    await app.setViewport(1080, 700);
    observations.desktopPhase = "connection cards";
    await uiWait("document.querySelector('.connection-card') !== null", "saved SSH cards");
    observations.desktopPhase = "connect saved SSH fixture";
    await page.evaluate(`[...document.querySelectorAll('.connection-card')].find(e=>e.querySelector('strong').textContent===${JSON.stringify(`${name}-22/tcp`)}).querySelector('button').click()`);
    await uiWait("document.querySelector('[data-testid=disconnect-target]:not([disabled])')!==null", "SSH connected");
    await click(".nav-item", "数据库"); await uiWait("document.querySelector('.database-empty')!==null", "database empty state");
    check("database is an actual connected page with an empty state", await page.evaluate("document.querySelector('.database-page').textContent.includes('还没有数据库连接')"));
    await click(".database-toolbar button", "添加连接"); await uiWait("document.querySelector('.database-editor input')!==null", "new connection form");
    check("new connection focuses its name and defaults to full TLS verification", await page.evaluate("document.activeElement===document.querySelector('.database-editor input') && document.querySelector('.database-editor select').value==='verify-full'"));
    await field("连接名称", "PG native · <img src=x onerror=bad>"); await field("数据库用户名", "lr_scram");
    await field("CA 证书（PEM，可选）", fs.readFileSync(path.join(dataRoot, "fixture-ca.pem"), "utf8"));
    await field("口令处理", "replace"); await field("新口令", password);
    await click(".database-editor button", "保存连接"); await idle();
    check("saved profile is shown as text and password input is cleared", await page.evaluate("!document.querySelector('.database-page img')&&!document.querySelector('.database-page input[type=password]')&&document.querySelector('.database-page').textContent.includes('已保存口令')"));
    await read();
    check("real TLS/SCRAM result shows known finite observations and the session caveat", await page.evaluate("document.querySelector('.database-result').textContent.includes('PostgreSQL 16.')&&document.querySelector('.database-result').textContent.includes('本次检查会话主动使用只读事务')&&[...document.querySelectorAll('.database-observations article')].some(a=>a.querySelector('h4').textContent==='ssl'&&a.querySelector('strong').textContent==='on')"));
    await page.shot("beginner-1080x700.png");
    await page.evaluate("document.querySelector('.database-mode input').click()"); await uiWait("document.querySelector('[aria-label=全部参数] .database-table tbody tr')!==null", "expert table");
    check("expert parameters paginate at fifty rows", await page.evaluate("document.querySelectorAll('[aria-label=全部参数] .database-table tbody tr').length===50"));
    await click("[aria-label=全部参数] button", "下一页"); await uiWait("document.querySelector('.database-result').textContent.includes('第 51–100 项')", "second page");
    await page.evaluate("(()=>{const e=document.querySelector('[aria-label=全部参数] input[type=search]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'ssl_max_protocol_version');e.dispatchEvent(new Event('input',{bubbles:true}));})()");
    await click("[aria-label=全部参数] button", "搜索"); await uiWait("document.querySelectorAll('[aria-label=全部参数] .database-table tbody tr').length===1", "filtered SSL maximum");
    check("native empty enum option remains visible", await page.evaluate("document.querySelector('[aria-label=全部参数] .database-table').textContent.includes('（空值）')"));
    await page.evaluate("document.querySelector('[aria-label=全部参数] .database-table').scrollIntoView({block:'center'})");
    await page.shot("expert-1080x700.png");
    check("page has no document-level horizontal overflow at 1080 by 700", await page.evaluate("innerWidth===1080&&innerHeight===700&&document.documentElement.scrollWidth<=innerWidth"));
    // Read the observed binding; do not manufacture a target or replace any product service.
    const binding = await host.binding();
    const rpc = (action, fields = {}) => page.evaluate(`window.lovelyhawk.postgresqlRuntime(${JSON.stringify({ action, bindingHandle: binding, ...(action === "begin" ? { retainEvidence: false } : {}), ...fields })})`);
    const rejected = async (action, fields) => { const result = await rpc(action, fields); return result.kind === "rejected" && result.action === action; };
    let profiles = (await rpc("list")).profiles, original = profiles[0];
    const edit = await rpc("edit", { profileHandle: original.profileHandle });
    check("profile editor never returns passwords, encrypted credentials or core identities", Object.keys(edit.profile).sort().join(",") === "database,hasCa,hasPassword,host,name,port,profileHandle,tlsMode,unassigned,username" && !JSON.stringify(edit).includes(password) && !Object.hasOwn(edit, "password"));
    const input = { name: original.name, host: original.host, port: original.port, username: original.username, database: original.database, tlsMode: original.tlsMode, caPem: edit.caPem };
    const updated = await rpc("save", { profileHandle: original.profileHandle, profile: { ...input, name: "PG native updated" }, password: { action: "keep" } });
    check("stale profile edits and deletes are refused", await rejected("save", { profileHandle: original.profileHandle, profile: input, password: { action: "keep" } }) && await rejected("plan-delete", { profileHandle: original.profileHandle }));
    const updateHandle = updated.profile.profileHandle;
    const plan = await rpc("plan-delete", { profileHandle: updateHandle });
    const again = await rpc("save", { profileHandle: updateHandle, profile: { ...input, name: "PG native review" }, password: { action: "keep" } });
    check("editing invalidates a prepared deletion", await rejected("delete", { planHandle: plan.planHandle }));
    await click(".database-toolbar button", "刷新连接");
    await uiWait("document.querySelector('.database-toolbar select').selectedOptions[0].textContent==='PG native review'", "refreshed revision");
    await click(".database-toolbar button", "编辑连接"); await uiWait("document.querySelector('.database-editor')!==null", "edit connection");
    await field("口令处理", "replace"); await field("新口令", "wrong-fixture-password"); await click(".database-editor button", "保存连接"); await idle();
    await read("读取未完成");
    check("wrong credentials produce an actionable failure without echoing the supplied secret", await page.evaluate("document.querySelector('.database-result').textContent.includes('口令')&&!document.querySelector('.database-page').textContent.includes('wrong-fixture-password')"));
    await page.shot("authentication-failure.png");
    await click(".database-toolbar button", "编辑连接"); await uiWait("document.querySelector('.database-editor')!==null", "fix password");
    await field("口令处理", "replace"); await field("新口令", password); await field("数据库用户名", "lr_md5");
    await click(".database-editor button", "保存连接"); await idle(); await read();
    check("existing MD5 role also works through native TLS", await page.evaluate("document.querySelector('.database-result h3').textContent==='读取完成'"));
    // Certificate errors and explicit loopback mode use the same real API, with the real UI refreshed afterward.
    profiles = (await rpc("list")).profiles; original = profiles[0];
    let current = await rpc("save", { profileHandle: original.profileHandle, profile: { ...input, name: "Loopback review", username: "lr_scram", caPem: fs.readFileSync(path.join(dataRoot, "fixture-other-ca.pem"), "utf8") }, password: { action: "keep" } });
    let started = await rpc("begin", { profileHandle: current.profile.profileHandle });
    let done;
    await until(async () => { done = await rpc("poll", { jobHandle: started.job.jobHandle }); return done.job.state !== "reading"; }, "wrong CA failure");
    check("wrong CA is refused without downgrade", done.job.state === "failed" && done.job.result === null);
    current = await rpc("save", { profileHandle: current.profile.profileHandle, profile: { ...input, name: "Loopback review", tlsMode: "ssh-loopback", caPem: null }, password: { action: "keep" } });
    check("non-loopback hosts cannot use the SSH-only database mode", await rejected("save", { profileHandle: current.profile.profileHandle, profile: { ...input, host: "db.example", tlsMode: "ssh-loopback", caPem: null }, password: { action: "keep" } }));
    await click(".database-toolbar button", "刷新连接"); await uiWait("document.querySelector('.database-toolbar select').selectedOptions[0].textContent==='Loopback review'", "loopback profile");
    await read(); check("explicit SSH loopback succeeds and its transport is visible", await page.evaluate("document.querySelector('.database-page').textContent.includes('SSH 加密 / 数据库回环连接')"));
    // Hold pg_settings briefly using a local owned-fixture connection to test real cancellation.
    script("runuser -u postgres -- sh -c 'psql -X -w -v ON_ERROR_STOP=1 -d postgres -c \"BEGIN; LOCK TABLE pg_catalog.pg_settings IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(12); COMMIT;\" >/tmp/pg-desktop-lock.log 2>&1 &'\n");
    await until(() => Number(sql("SELECT count(*) FROM pg_locks WHERE relation='pg_catalog.pg_settings'::regclass AND mode='AccessExclusiveLock' AND granted")) > 0, "owned lock acquired");
    await click(".database-toolbar button", "读取数据库状态"); await uiWait("document.querySelector('.database-result h3')?.textContent==='正在读取'", "read in progress");
    await until(() => Number(sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='LovelyHawk runtime review' AND wait_event_type='Lock'")) > 0, "native request waits on fixture lock");
    await click(".database-toolbar button", "取消读取"); await uiWait("document.querySelector('.database-result h3')?.textContent==='读取已取消'", "cancelled UI");
    check("cancellation states its bounded server-side delay", await page.evaluate("document.querySelector('.database-result').textContent.includes('最长约 20 秒')"));
    await until(() => sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='LovelyHawk runtime review'") === "0", "cancelled native connection closes");
    // Simulate a legacy portable profile only in this isolated data root, between idle requests.
    const storeFile = path.join(dataRoot, "data/database-connections.json");
    const store = JSON.parse(fs.readFileSync(storeFile, "utf8"));
    if (store.schema_version !== 1 || store.data.profiles.length !== 1 || !store.data.profiles[0].config.ssh_connection_id) throw Error("Unexpected owned legacy fixture profile");
    delete store.data.profiles[0].config.ssh_connection_id;
    fs.writeFileSync(storeFile, JSON.stringify(store));
    await click(".database-toolbar button", "刷新连接");
    await uiWait("document.querySelector('.database-toolbar select').selectedOptions[0].textContent.includes('待关联')", "legacy profile needs association");
    const legacy = (await rpc("list")).profiles[0];
    check("legacy profiles cannot read until their SSH host is explicitly associated", legacy.unassigned && await rejected("begin", { profileHandle: legacy.profileHandle }) && await page.evaluate("[...document.querySelectorAll('.database-toolbar button')].find(b=>b.textContent==='读取数据库状态').disabled"));
    await click(".database-toolbar button", "编辑连接"); await uiWait("document.querySelector('.database-editor')!==null", "associate legacy editor");
    await click(".database-editor button", "保存并关联此主机"); await idle();
    check("explicit legacy adoption preserves credentials and records the current SSH host", !(await rpc("list")).profiles[0].unassigned && (await rpc("list")).profiles[0].hasPassword && !!JSON.parse(fs.readFileSync(storeFile,"utf8")).data.profiles[0].config.ssh_connection_id);
    await observationScenario({ dataRoot, page, host, rpc, binding, read, click, uiWait, until, sql, script, check, observations, registerAccessCanary });
    await click(".database-toolbar button", "编辑连接"); await uiWait("document.querySelector('.database-editor')!==null", "dirty editor"); await field("连接名称", "Unsaved edit");
    await click(".nav-item", "主机全景"); await uiWait("document.querySelector('[role=dialog]')!==null", "dirty navigation confirmation");
    await click("[role=dialog] button", "取消");
    check("cancelling navigation preserves the dirty database form", await page.evaluate("document.querySelector('.database-editor input')?.value==='Unsaved edit'"));
    await host.requestWindowClose();
    await uiWait("document.querySelector('[role=dialog]')!==null", "native window close confirmation");
    await click("[role=dialog] button", "取消");
    check("cancelling the real window close preserves the unsaved database editor", await page.evaluate("document.querySelector('.database-editor input')?.value==='Unsaved edit'"));

    await click(".nav-item", "主机全景"); await uiWait("document.querySelector('[role=dialog]')!==null", "discard confirmation"); await click("[role=dialog] button", "丢弃并离开");
    await uiWait("document.querySelector('.database-page')===null", "left database page");
    await click(".nav-item", "数据库"); await uiWait("document.querySelector('.database-toolbar select')?.value", "database reloaded");
    check("returning to the page discards uncommitted text and old results", await page.evaluate("!document.querySelector('.database-editor')&&!document.querySelector('.database-result')&&!document.querySelector('.database-page').textContent.includes('Unsaved edit')"));
    await click(".database-toolbar button", "删除连接"); await uiWait("document.querySelector('[role=dialog]')!==null", "delete confirmation");
    check("deletion confirmation names the target and local-only scope", await page.evaluate("document.querySelector('[role=dialog]').textContent.includes('SSH 主机')&&document.querySelector('[role=dialog]').textContent.includes('数据库内容不受影响')"));
    await click("[role=dialog] button", "取消");
    check("cancelled deletion preserves the profile", (await rpc("list")).profiles.length === 1);
    await click(".database-toolbar button", "删除连接"); await uiWait("document.querySelector('[role=dialog]')!==null", "second delete confirmation"); await click("[role=dialog] button", "删除本机连接");
    await uiWait("document.querySelector('.database-page').textContent.includes('已删除本机保存的数据库连接并核实结果')", "verified delete");
    check("verified deletion removes only the local connection", (await rpc("list")).profiles.length === 0 && sql("SELECT current_database()") === "postgres");
    await page.evaluate("document.querySelector('[data-testid=disconnect-target]').click()"); await uiWait("document.querySelector('.database-page').textContent.includes('请先连接 SSH 主机')", "disconnected database state");
    check("revoked bindings reject later database requests", await rejected("list", {}));
    // actionCounts: requests per postgresql.runtime action (the earlier probe listed each action name in order).
    observations.desktop = { observerStartedAt: app.hostCallsSince, actionCounts: (await app.hostCallCounts())["postgresql.runtime"] ?? {}, consoleErrors: [...errors], viewport: await page.evaluate("({width:innerWidth,height:innerHeight})") };
    check("normal desktop startup, host bridge and page have zero console errors", observations.desktop.consoleErrors.length === 0);
  } catch (error) {
    try { await page?.shot("failure.png"); } catch {}
    throw error;
  } finally {
    observations.desktopErrors = [...errors];
    // The close button runs the real close handshake; a page still holding
    // unsaved work after a failure is ended with its process tree instead.
    if (app) { try { await app.close(); } catch {} }
  }
}
