import { objectScenario } from "./postgresql-object-scenario.mjs";
import { roleScenario } from "./postgresql-role-scenario.mjs";
// Real page/host/core path; every SQL/file change is in the verified owned container.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

export async function accessScenario({ dataRoot, page, host, read, lastJob, rpc, click, uiWait, script, sql, check, observations, registerAccessCanary }) {
  const pg = "/var/lib/postgresql/data";
  const secret = `lr-auth-secret-${randomUUID()}`;
  registerAccessCanary(secret);
  let saved = false, failure;
  // WSL command-line forwarding can interpret dollar quoting. Keep fixture SQL
  // in stdin under a quoted delimiter; the product uses native protocol only.
  const fixtureSql = statement => script("runuser -u postgres -- psql -X -w -At -v ON_ERROR_STOP=1 -d postgres <<'LR_ACCESS_SQL'\n" + statement + "\nLR_ACCESS_SQL\n");
  const rows = async (section, query = "", offset = 0) => {
    const result = await rpc("access-rows", { jobHandle: (await lastJob()).jobHandle, section, query, offset });
    if (result.kind !== "access-rows") throw new Error(`Expected actual ${section} diagnostic page: ${JSON.stringify(result)}`);
    return result;
  };
  try {
    await read(); let current = await lastJob();
    observations.accessInitial = current.result.access;
    check("initial native object SQL covers all thirteen catalogs", Object.keys(current.result.access.objects).length === 13 && Object.values(current.result.access.objects).every(s => s.state === "available"));
    check("native access views and direct role attributes are independently available to the owned superuser", ["hba", "ident", "roles"].every(k => current.result.access[k].state === "available") && current.result.access.passwordClassification);
    const counts = JSON.parse(sql("SELECT json_build_object('hba',(SELECT count(*) FROM pg_hba_file_rules),'ident',(SELECT count(*) FROM pg_ident_file_mappings),'roles',(SELECT count(*) FROM pg_roles))"));
    check("native access counts match independent PostgreSQL view counts", Object.entries(counts).every(([k, n]) => current.result.access[k].total === n));
    const baselineRoles = await rows("roles", "lr_");
    check("database-side classification distinguishes real SCRAM and MD5 verifiers without exposing them", baselineRoles.rows.find(r => r.name === "lr_scram")?.passwordKind === "scram-sha-256" && baselineRoles.rows.find(r => r.name === "lr_md5")?.passwordKind === "md5" && !/md5[0-9a-f]{32}|SCRAM-SHA-256\$|fingerprint|rolpassword/u.test(JSON.stringify(baselineRoles)));
    script(`test ! -e /tmp/lr-access-original.hba\ntest ! -e /tmp/lr-access-original.ident\ncp '${pg}/pg_hba.conf' /tmp/lr-access-original.hba\ncp '${pg}/pg_ident.conf' /tmp/lr-access-original.ident\n`); saved = true;
    fixtureSql("SET password_encryption='md5'; CREATE ROLE lr_access_probe LOGIN CREATEROLE REPLICATION BYPASSRLS PASSWORD 'OwnedAccess#2026' VALID UNTIL '2000-01-01 00:00:00+00'; DO $$ BEGIN FOR n IN 1..55 LOOP EXECUTE format('CREATE ROLE lr_access_page_%s NOLOGIN', n); END LOOP; END $$");
    // Reject would block this very lr_scram connection if loaded. These file
    // changes are deliberately NOT reloaded; the product only reads them.
    script(`{ printf 'host all lr_scram 127.0.0.1/32 reject\n'; cat /tmp/lr-access-original.hba; printf "include lovelyres-access.inc\n"; } > '${pg}/pg_hba.conf'
cat > '${pg}/lovelyres-access.inc' <<'HBA'
host "all" "all" all md5
host all lr_access_probe 0.0.0.0/0 password
hostssl all lr_access_probe ::/0 password
local all lr_access_probe trust
host all lr_access_probe 192.0.2.0/24 ldap ldapserver=127.0.0.1 ldapbasedn="dc=example" ldapbinddn="cn=probe" ldapbindpasswd="${secret}"
host all lr_access_probe 192.0.2.0/24 radius radiusservers="127.0.0.1" radiussecrets="${secret}"
HBA
printf "include lovelyres-access-ident.inc\n" > '${pg}/pg_ident.conf'
printf 'lr_access_map system_probe lr_access_probe\n' > '${pg}/lovelyres-access-ident.inc'
chown postgres:postgres '${pg}/pg_hba.conf' '${pg}/pg_ident.conf' '${pg}/lovelyres-access.inc' '${pg}/lovelyres-access-ident.inc'
`);
    await read(); const candidate = await lastJob();
    const hba = await rows("hba"); const ident = await rows("ident"); const roles = await rows("roles", "lr_access_probe");
    observations.accessCandidate = { summary: candidate.result.access, hba, ident, roles };
    check("unreloaded first reject rule is shown as current file while original native authentication still succeeds", candidate.state === "completed" && candidate.result.session.sessionUser === "lr_scram" && candidate.result.session.configurationLoadedAt === current.result.session.configurationLoadedAt && hba.rows[0].method === "reject" && hba.rows[0].users.join() === "lr_scram");
    const included = hba.rows.filter(r => r.fileName?.endsWith("/lovelyres-access.inc"));
    check("included HBA and ident entries preserve PostgreSQL file and line origins", included.length === 6 && included.map(r => r.lineNumber).join() === "1,2,3,4,5,6" && ident.rows.some(r => r.fileName.endsWith("/lovelyres-access-ident.inc") && r.lineNumber === 1 && r.mapName === "lr_access_map"));
    check("flattened quoted all selectors do not become wildcard assertions and password transport remains conditional", included[0].databases.join() === "all" && included[0].users.join() === "all" && included[0].findings.join() === "md5-rule" && included[1].findings.includes("password-transport") && included[1].findings.includes("broad-source") && !included[2].findings.includes("password-transport") && included[3].findings.includes("trust"));
    check("LDAP and RADIUS secret options are reduced to names inside PostgreSQL", !included[4].hasIssue && !included[5].hasIssue && included[4].optionNames.includes("ldapbindpasswd") && included[5].optionNames.includes("radiussecrets") && !JSON.stringify(hba).includes(secret) && !JSON.stringify(hba).includes("fingerprint"));
    check("server-derived LDAP scope is recognized without treating it as a writable HBA option", included[4].optionNames.includes("ldapscope") && !included[4].findings.includes("unknown-option"));
    check("actual role expiry and direct elevated login attributes produce scoped findings", roles.rows.length === 1 && roles.rows[0].passwordExpired && roles.rows[0].passwordKind === "md5" && ["login-createrole", "login-replication", "login-bypassrls", "md5-verifier", "password-expired"].every(f => roles.rows[0].findings.includes(f)) && roles.rows[0].superuser === false);
    const first = await rows("roles", "lr_access_page_", 0); const next = await rows("roles", "lr_access_page_", 50);
    check("real role search and pagination cover each matching role once", first.matched === 55 && first.rows.length === 50 && next.rows.length === 5 && new Set([...first.rows,...next.rows].map(r => r.oid)).size === 55);
    await click(".database-access button", "查看 HBA 规则");
    await uiWait("document.querySelector('.database-access table')?.textContent.includes('ldapbindpasswd')", "actual HBA detail table");
    await uiWait("document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')", "HBA details focus");
    check("opening access details moves keyboard focus and scrolls to the actual result", await page.evaluate("(()=>{const r=document.activeElement.getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight&&document.activeElement.textContent==='HBA 连接规则详情';})()"));
    await page.shot("access-hba-detail-1080x700.png");
    await page.evaluate("document.querySelector('.database-access').scrollIntoView({block:'start'})"); await page.shot("access-current-file-1080x700.png");
    await click(".database-access button", "查看角色属性");
    await uiWait("document.querySelector('.database-access table')?.textContent.includes('口令状态')", "actual role detail table");
    await page.evaluate("document.querySelector('.database-access table').scrollIntoView({block:'start'})"); await page.shot("access-roles-1080x700.png");
    await page.evaluate("(()=>{const e=document.querySelector('[aria-label=访问诊断详情] form.database-toolbar input[type=search]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'lr_access_page_');e.dispatchEvent(new Event('input',{bubbles:true}));})()");
    await click(".database-access button", "搜索访问诊断");
    await uiWait("document.querySelector('.database-access caption')?.textContent.includes('匹配 55 项')&&document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')", "filtered actual role page");
    check("the real access search shows its applied filter and result count", await page.evaluate("document.querySelectorAll('.database-access tbody tr').length===50&&document.querySelector('.database-access caption').textContent.includes('lr_access_page_')&&document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')"));
    await click(".database-access button", "访问诊断下一页");
    await uiWait("document.querySelectorAll('.database-access tbody tr').length===5&&document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')", "next actual role page");
    check("actual access pagination moves focus back to the new results", await page.evaluate("document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')&&[...document.querySelectorAll('.database-access tbody tr')].every(r=>r.textContent.includes('lr_access_page_'))"));
    await page.shot("access-filtered-next-page-1080x700.png");
    // The viewport is held at the window minimum through CDP device metrics (previously a real window resize).
    await host.setViewport(1080, 700);
    await uiWait("innerWidth===1080", "minimum supported database viewport");
    const narrow = await page.evaluate("(()=>{const p=document.querySelector('.database-page');const a=document.querySelector('.database-access');return {pageWidth:p.clientWidth,pageScroll:p.scrollWidth,accessRight:a.getBoundingClientRect().right,viewport:innerWidth};})()");
    check("access details stay within the minimum supported page while their table can scroll independently", narrow.pageScroll <= narrow.pageWidth + 1 && narrow.accessRight <= narrow.viewport + 1);
    await page.evaluate("document.querySelector('.database-access').scrollIntoView({block:'start'})"); await page.shot("access-minimum-1080x700.png");
    await host.setViewport(1080, 700);
    await uiWait("innerWidth===1080", "restore database viewport");
    observations.access = { summary: candidate.result.access, includedHba: included, ident: ident.rows, reviewRole: roles.rows[0], rolePagination: { matched: first.matched, first: first.rows.length, next: next.rows.length } };
    fixtureSql("SET password_encryption='scram-sha-256'; ALTER ROLE lr_access_probe PASSWORD 'OwnedAccess#2026' VALID UNTIL 'infinity'");
    await read(); const converted = await rows("roles", "lr_access_probe");
    check("a real owned role password change is observed independently of HBA method names", converted.rows[0].passwordKind === "scram-sha-256" && !converted.rows[0].passwordExpired && !converted.rows[0].findings.includes("md5-verifier"));
    script(`printf 'host all all 127.0.0.1/32 ${secret}\n' >> '${pg}/lovelyres-access.inc'\nprintf 'lr_bad_mapping\n' >> '${pg}/lovelyres-access-ident.inc'\n`);
    await read("读取完成", "读取并留证"); current = await lastJob();
    const badHba = await rows("hba"); const badIdent = await rows("ident");
    check("malformed current authentication files retain a visible problem without raw error or secret text", badHba.rows.some(r => r.hasIssue && r.findings.includes("server-issue")) && badIdent.rows.some(r => r.hasIssue && r.findings.includes("server-issue")) && !JSON.stringify([badHba,badIdent,current]).includes(secret));
    check("case v5 retains bounded access counts and scope without rule contents or private verifier material", current.retention.state === "saved" && current.retention.recordText.includes("检查摘要 v5") && current.retention.recordText.includes("访问诊断：") && current.retention.recordText.includes("server-issue") && !current.retention.recordText.includes("lr_access_probe") && !current.retention.recordText.includes("lovelyres-access.inc"));
    await click(".database-access button", "查看 ident 映射"); await uiWait("document.querySelector('.database-access table')?.textContent.includes('服务器报告规则问题')", "actual mapping issue table");
    await page.evaluate("document.querySelector('.database-access').scrollIntoView({block:'start'})"); await page.shot("access-issues-1080x700.png");
    const savedCase = JSON.parse(fs.readFileSync(path.join(dataRoot, "data", "cases.json"), "utf8"));
    check("case store and live renderer never receive the authentication option or error canary", !JSON.stringify(savedCase).includes(secret) && !(await page.evaluate("document.body.textContent")).includes(secret));
    script(`cp /tmp/lr-access-original.hba '${pg}/pg_hba.conf'\ncp /tmp/lr-access-original.ident '${pg}/pg_ident.conf'\nfor n in $(seq 1 513); do printf 'host all lr_access_probe 192.0.2.1/32 scram-sha-256\n'; done >> '${pg}/pg_hba.conf'\nfor n in $(seq 1 513); do printf 'lr_map_%s system_probe lr_access_probe\n' "$n"; done >> '${pg}/pg_ident.conf'\n`);
    await read(); const bounded = await lastJob();
    check("real HBA and ident count overflow remains unavailable while runtime parameters and roles survive", bounded.state === "completed" && bounded.result.parameterCount > 100 && ["hba","ident"].every(k => bounded.result.access[k].reason === "limit-exceeded" && bounded.result.access[k].total === null) && bounded.result.access.roles.state === "available");
    const refused = await rpc("access-rows", { jobHandle: bounded.jobHandle, section: "hba", query: "", offset: 0 });
    check("an unavailable view cannot be retrieved as an empty successful page", refused.kind === "rejected");
    script(`cp /tmp/lr-access-original.hba '${pg}/pg_hba.conf'\ncp /tmp/lr-access-original.ident '${pg}/pg_ident.conf'\n`);
    script(`python3 -I - <<'PY'
from pathlib import Path
original = Path('/tmp/lr-access-original.hba').read_text()
Path('${pg}/pg_hba.conf').write_text(original + ('host ' + 'x' * 2048 + ' lr_access_probe 192.0.2.1/32 scram-sha-256\\n') * 200)
PY
`);
    await read(); const bytes = await lastJob();
    check("real public-view byte overflow is explicit even below the HBA row limit", bytes.state === "completed" && bytes.result.access.hba.reason === "limit-exceeded" && bytes.result.access.ident.state === "available" && Number(sql("SELECT count(*) FROM pg_hba_file_rules")) < 512);
    script(`cp /tmp/lr-access-original.hba '${pg}/pg_hba.conf'\n`);
    fixtureSql("DO $$ BEGIN FOR n IN 1..1025 LOOP EXECUTE format('CREATE ROLE lr_access_limit_%s NOLOGIN', n); END LOOP; END $$");
    await read(); const limit = await lastJob();
    check("real role count overflow does not truncate or claim password classification", limit.state === "completed" && limit.result.access.roles.reason === "limit-exceeded" && !limit.result.access.passwordClassification && limit.result.access.hba.state === "available");
    fixtureSql("DO $$ BEGIN FOR n IN 1..1025 LOOP EXECUTE format('DROP ROLE lr_access_limit_%s', n); END LOOP; END $$");
    await roleScenario({ page, read, lastJob, rpc, click, uiWait, fixtureSql, sql, check, observations });
    await objectScenario({ page, read, lastJob, rpc, click, uiWait, fixtureSql, sql, check, observations, secret });
  } catch (error) { failure = error; throw error; } finally {
    try {
    if (saved) script(`cp /tmp/lr-access-original.hba '${pg}/pg_hba.conf'\ncp /tmp/lr-access-original.ident '${pg}/pg_ident.conf'\nchown postgres:postgres '${pg}/pg_hba.conf' '${pg}/pg_ident.conf'\n`);
    // Container lifetime cleanup also handles failure before this bounded list.
    fixtureSql("DROP ROLE IF EXISTS lr_access_probe; DO $$ BEGIN FOR n IN 1..55 LOOP EXECUTE format('DROP ROLE IF EXISTS lr_access_page_%s', n); END LOOP; END $$");
    } catch (error) { observations.accessCleanupError = String(error); if (!failure) throw error; }
  }
}
