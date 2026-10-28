// Native role semantics are compared to pg_has_role and independent SQL sessions.
export async function roleScenario({ page, read, lastJob, rpc, click, uiWait, fixtureSql, sql, check, observations }) {
  const names = ["mixed", "switch", "leaf", "automatic", "inherit_super", "set_super", "super", "unrelated", "owner", "default", "grantor"];
  let failure;
  const grant = (target, member, inherit, set, suffix = "") => `GRANT ${target} TO ${member} WITH INHERIT ${inherit} ${suffix}; GRANT ${target} TO ${member} WITH SET ${set} ${suffix};`;
  const rolePage = async (oid, mode, query = "", offset = 0) => {
    const result = await rpc("role-access", { jobHandle: (await lastJob()).jobHandle, roleOid: oid, mode, query, offset });
    if (result.kind !== "role-access") throw new Error(`Native role page refused: ${JSON.stringify(result)}`);
    return result;
  };
  const allTargets = async (oid, mode) => {
    let first = await rolePage(oid,mode), targets = first.rows.map(r => r.target.oid);
    for (let offset = 20; offset < first.matched; offset += 20) targets.push(...(await rolePage(oid,mode,"",offset)).rows.map(r => r.target.oid));
    return targets;
  };
  try {
    check("owned role fixture starts with the expected postgres database owner", sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='postgres'") === "postgres");
    fixtureSql(names.map(n => `CREATE ROLE lr_path_${n} ${["mixed","inherit_super","set_super","default"].includes(n) ? "LOGIN" : "NOLOGIN"} ${n === "super" ? "SUPERUSER" : ""};`).join("\n") +
      grant("lr_path_switch","lr_path_mixed",false,true) + grant("lr_path_leaf","lr_path_switch",true,false) + grant("lr_path_automatic","lr_path_mixed",true,false) +
      grant("lr_path_super","lr_path_inherit_super",true,false) + grant("lr_path_super","lr_path_set_super",false,true) +
      grant("lr_path_leaf","lr_path_default",true,false) + "ALTER ROLE lr_path_default NOINHERIT;" +
      "GRANT lr_path_leaf TO lr_path_grantor WITH ADMIN TRUE;" + grant("lr_path_leaf","lr_path_default",false,true,"GRANTED BY lr_path_grantor") +
      "ALTER DATABASE postgres OWNER TO lr_path_owner;" +
      "DO $$ BEGIN FOR n IN 1..45 LOOP EXECUTE format('CREATE ROLE lr_path_chain_%s NOLOGIN', n); END LOOP; FOR n IN 1..44 LOOP EXECUTE format('GRANT lr_path_chain_%s TO lr_path_chain_%s', n+1,n); END LOOP; END $$;");
    await read("读取完成", "读取并留证"); const job = await lastJob();
    observations.roleGraph = job.result.access.roleGraph;
    check("native role graph is complete with a separately observed current database owner", job.result.access.memberships.state === "available" && job.result.access.roleGraph.state === "available" && job.result.access.roleGraph.database.ownerOid === Number(sql("SELECT oid FROM pg_roles WHERE rolname='lr_path_owner'")));
    const elevated = Number(sql("SELECT count(*) FROM pg_roles s WHERE s.rolcanlogin AND NOT s.rolsuper AND EXISTS (SELECT 1 FROM pg_roles t WHERE pg_has_role(s.oid,t.oid,'SET') AND (t.rolsuper OR t.rolcreaterole AND NOT s.rolcreaterole OR t.rolcreatedb AND NOT s.rolcreatedb OR t.rolreplication AND NOT s.rolreplication OR t.rolbypassrls AND NOT s.rolbypassrls))"));
    check("additional management login count agrees with the native role predicate and direct attributes", elevated === 1 && job.result.access.roleGraph.additionalManagementLogins === elevated);
    const ids = JSON.parse(sql("SELECT json_object_agg(rolname,oid::bigint) FROM pg_roles WHERE starts_with(rolname,'lr_path_')"));
    const comparisons = [];
    for (const source of ["mixed","inherit_super","set_super","super","owner","default"]) {
      for (const [mode,privilege] of [["member","MEMBER"],["inherit","USAGE"],["set","SET"]]) {
        const actual = await allTargets(ids[`lr_path_${source}`],mode);
        const expected = JSON.parse(sql(`SELECT coalesce(json_agg(oid::bigint ORDER BY oid),'[]') FROM pg_roles WHERE oid <> ${ids[`lr_path_${source}`]} AND pg_has_role(${ids[`lr_path_${source}`]}::oid,oid,'${privilege}')`));
        comparisons.push({ source, mode, actual, expected });
      }
    }
    observations.roleComparisons = comparisons;
    check("MEMBER, USAGE and SET paths agree with native PostgreSQL for six independent role combinations", comparisons.every(c => JSON.stringify(c.actual) === JSON.stringify(c.expected)));
    const after = await rolePage(ids.lr_path_mixed,"after-set");
    const afterNames = after.rows.map(r => r.target.name).sort();
    const actualSession = fixtureSql("SET SESSION AUTHORIZATION lr_path_mixed; SET ROLE lr_path_switch; SELECT json_build_object('session',session_user,'current',current_user,'leaf',pg_has_role(current_user,'lr_path_leaf','USAGE'),'automatic',pg_has_role(current_user,'lr_path_automatic','USAGE'),'canSetLeaf',pg_has_role(session_user,'lr_path_leaf','SET')); RESET SESSION AUTHORIZATION;");
    const switched = JSON.parse(actualSession.split(/\r?\n/u).find(line => line.startsWith("{")));
    check("mixed SET then INHERIT is verified by an independent session and does not preserve all previous privileges", afterNames.join() === "lr_path_leaf,lr_path_switch" && switched.session === "lr_path_mixed" && switched.current === "lr_path_switch" && switched.leaf && !switched.automatic && !switched.canSetLeaf && after.rows.find(r => r.target.name === "lr_path_leaf").steps.map(s => s.operation).join() === ",set,inherit");
    const inherited = await rolePage(ids.lr_path_inherit_super,"inherit");
    const setSuper = await rolePage(ids.lr_path_set_super,"set");
    const afterSuper = await rolePage(ids.lr_path_set_super,"after-set","lr_path_unrelated");
    check("inheriting SUPERUSER is distinguished from switching to it and from further SET authority", inherited.rows.map(r => r.target.name).join() === "lr_path_super" && (await rolePage(ids.lr_path_inherit_super,"set")).total === 0 && setSuper.rows.map(r => r.target.name).join() === "lr_path_super" && afterSuper.rows[0].steps.at(-1).via === "superuser");
    const owner = await rolePage(ids.lr_path_owner,"inherit");
    check("database-owner implicit membership has a distinct path without an invented grant OID", owner.rows.length === 1 && owner.rows[0].target.oid === 6171 && owner.rows[0].steps[1].via === "database-owner" && owner.rows[0].steps[1].grantOid === null);
    const memberships = await rpc("access-rows", { jobHandle: job.jobHandle, section: "memberships", query: "lr_path_default", offset: 0 });
    check("multiple grantors and existing per-grant inheritance survive changing the role default to NOINHERIT", memberships.kind === "access-rows" && memberships.rows.length === 2 && new Set(memberships.rows.map(r => r.grantorOid)).size === 2 && memberships.rows.some(r => r.inheritOption) && memberships.rows.some(r => r.setOption) && comparisons.find(c => c.source === "default" && c.mode === "inherit").actual.includes(ids.lr_path_leaf));
    const admin = await rpc("access-rows", { jobHandle: job.jobHandle, section: "memberships", query: "lr_path_grantor", offset: 0 });
    check("raw ADMIN findings retain explicit membership and grantor context", admin.kind === "access-rows" && admin.rows.some(r => r.adminOption && r.findings.includes("membership-admin")));
    const long = await rolePage(ids.lr_path_chain_1,"set","lr_path_chain_45");
    check("real multi-level paths report the full distance while bounding the displayed prefix", long.rows[0].hops === 44 && long.rows[0].truncated && long.rows[0].steps.length === 32);
    check("case v5 retains role counts and static scope without storing membership identities or full paths", job.retention.state === "saved" && job.retention.recordText.includes("检查摘要 v5") && job.retention.recordText.includes("成员授权：") && job.retention.recordText.includes("角色路径：已分析") && !job.retention.recordText.includes("lr_path_") && !job.retention.recordText.includes("grantorOid"));
    await click(".database-access button","查看角色属性");
    // The role list loads first and the search button stays disabled until it has.
    await uiWait("document.querySelector('[aria-label=访问诊断详情] tbody')!==null&&[...document.querySelectorAll('[aria-label=访问诊断详情] button')].some(b=>b.textContent.includes('搜索访问诊断')&&!b.disabled)","role list loaded before searching");
    await page.evaluate("(()=>{const e=document.querySelector('[aria-label=访问诊断详情] input');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'lr_path_mixed');e.dispatchEvent(new Event('input',{bubbles:true}));})()");
    await click("[aria-label=访问诊断详情] button","搜索访问诊断");
    await uiWait("document.querySelector('[aria-label=访问诊断详情] tbody')?.textContent.includes('lr_path_mixed')","selected actual role");
    await click("[aria-label=访问诊断详情] tbody button","查看权限来源");
    await uiWait("document.querySelector('[aria-label=角色权限来源] table')?.textContent.includes('lr_path_automatic')","initial actual inherited path");
    await page.evaluate("(()=>{const e=document.querySelector('[aria-label=角色权限来源] select');Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(e,'after-set');e.dispatchEvent(new Event('change',{bubbles:true}));})()");
    await uiWait("document.querySelector('[aria-label=角色权限来源] table')?.textContent.includes('lr_path_leaf')&&!document.querySelector('[aria-label=角色权限来源] table')?.textContent.includes('lr_path_automatic')","actual mixed role view");
    check("actual role selection and mode change return keyboard focus to the bounded path results", await page.evaluate("document.activeElement===document.querySelector('[aria-label=角色权限来源] h5')"));
    await page.shot("role-mixed-path-1080x700.png");
    await click(".database-access button","查看成员授权");
    await uiWait("document.querySelector('[aria-label=访问诊断详情] table')?.textContent.includes('管理成员（ADMIN）')","actual membership flags");
    check("role analysis does not steal focus when the user opens another diagnostic table", await page.evaluate("document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')"));
    await page.shot("role-memberships-1080x700.png");
    fixtureSql("DO $$ BEGIN FOR n IN 1..65 LOOP EXECUTE format('CREATE ROLE lr_path_limit_%s NOLOGIN', n); END LOOP; FOR a IN 1..64 LOOP FOR b IN (a+1)..65 LOOP EXECUTE format('GRANT lr_path_limit_%s TO lr_path_limit_%s', b,a); END LOOP; END LOOP; END $$;");
    await read(); const overflow = await lastJob();
    check("real membership count overflow leaves roles and parameters available while disabling incomplete graph analysis", overflow.result.access.memberships.reason === "limit-exceeded" && overflow.result.access.roleGraph.reason === "memberships-unavailable" && overflow.result.access.roles.state === "available" && overflow.result.parameterCount > 100);
    const refused = await rpc("role-access", { jobHandle: overflow.jobHandle, roleOid: ids.lr_path_mixed, mode: "set", query: "", offset: 0 });
    check("incomplete membership graphs cannot return empty successful role paths", refused.kind === "rejected");
  } catch (error) { failure = error; throw error; } finally {
    try {
      fixtureSql("ALTER DATABASE postgres OWNER TO postgres;" + names.map(n => `DROP ROLE IF EXISTS lr_path_${n};`).join("\n") + "DO $$ BEGIN FOR n IN 1..45 LOOP EXECUTE format('DROP ROLE IF EXISTS lr_path_chain_%s', n); END LOOP; FOR n IN 1..65 LOOP EXECUTE format('DROP ROLE IF EXISTS lr_path_limit_%s', n); END LOOP; END $$;");
    } catch (error) { observations.roleCleanupError = String(error); if (!failure) throw error; }
  }
}
