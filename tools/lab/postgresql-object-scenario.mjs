// Product reads use the native protocol; SQL writes and oracle sessions run only
// through fixtureSql after the parent harness verifies the owned container.
export async function objectScenario({ page, read, lastJob, rpc, click, uiWait, fixtureSql, sql, check, observations, secret }) {
  const roles = ["owner","login","automatic","switch","leaf","data","super","set_super"];
  const sectionNames = ["database","schemas","relations","columns","routines","types","languages","tablespaces","foreign-wrappers","foreign-servers","large-objects","parameters","defaults"];
  let failure;
  const parseLast = output => JSON.parse(output.split(/\r?\n/u).filter(line => line.startsWith("{") || line.startsWith("[")).at(-1));
  const rows = async (section, query = "", filter = "all", offset = 0) => {
    const result = await rpc("object-rows",{ jobHandle: (await lastJob()).jobHandle, section, query, filter, offset });
    if (result.kind !== "object-rows") throw new Error(`Object list refused for ${section}: ${JSON.stringify(result)}`);
    return result;
  };
  const detail = async (section, row, roleOid = null) => {
    const result = await rpc("object-detail",{ jobHandle: (await lastJob()).jobHandle, section, oid: row.oid, subId: row.subId, roleOid });
    if (result.kind !== "object-detail") throw new Error(`Object detail refused for ${section}: ${JSON.stringify(result)}`);
    return result;
  };
  const field = (scope, selector, value) => page.evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(`${scope} ${selector}`)});if(!e)throw Error('Object control missing');const p=e.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(p,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event(e.tagName==='SELECT'?'change':'input',{bubbles:true}));})()`);
  try {
    fixtureSql(roles.map(r => `CREATE ROLE lr_obj_${r} ${["login","data","set_super"].includes(r) ? "LOGIN" : "NOLOGIN"} ${r === "super" ? "SUPERUSER" : ""};`).join("\n") + `
      GRANT lr_obj_automatic TO lr_obj_login WITH INHERIT TRUE;
      GRANT lr_obj_automatic TO lr_obj_login WITH SET FALSE;
      GRANT lr_obj_switch TO lr_obj_login WITH INHERIT FALSE;
      GRANT lr_obj_switch TO lr_obj_login WITH SET TRUE;
      GRANT lr_obj_leaf TO lr_obj_switch WITH INHERIT TRUE;
      GRANT lr_obj_leaf TO lr_obj_switch WITH SET FALSE;
      GRANT pg_read_all_data,pg_write_all_data TO lr_obj_data;
      GRANT lr_obj_super TO lr_obj_set_super WITH INHERIT FALSE;
      GRANT lr_obj_super TO lr_obj_set_super WITH SET TRUE;
      CREATE SCHEMA lr_obj AUTHORIZATION lr_obj_owner;
      SET ROLE lr_obj_owner;
      CREATE TABLE lr_obj.acl_table(id integer,secret_column text);
      INSERT INTO lr_obj.acl_table VALUES (1,'${secret}'),(2,'fixture');
      REVOKE ALL ON lr_obj.acl_table FROM lr_obj_owner;
      GRANT SELECT ON lr_obj.acl_table TO lr_obj_automatic WITH GRANT OPTION;
      GRANT UPDATE(secret_column) ON lr_obj.acl_table TO lr_obj_leaf;
      GRANT SELECT(id) ON lr_obj.acl_table TO PUBLIC;
      ALTER TABLE lr_obj.acl_table ENABLE ROW LEVEL SECURITY;
      CREATE POLICY lr_one_row ON lr_obj.acl_table FOR SELECT USING (id=1);
      CREATE TABLE lr_obj.public_table(id integer);
      GRANT SELECT ON lr_obj.public_table TO PUBLIC;
      CREATE SEQUENCE lr_obj.seq;
      GRANT USAGE ON lr_obj.seq TO lr_obj_automatic;
      GRANT UPDATE ON lr_obj.seq TO lr_obj_leaf;
      CREATE VIEW lr_obj.simple_view AS SELECT 1 AS id;
      CREATE MATERIALIZED VIEW lr_obj.materialized AS SELECT 1 AS id;
      CREATE TYPE lr_obj.color AS ENUM ('red','blue');
      REVOKE ALL ON TYPE lr_obj.color FROM PUBLIC,lr_obj_owner;
      GRANT USAGE ON TYPE lr_obj.color TO lr_obj_automatic WITH GRANT OPTION;
      CREATE FUNCTION lr_obj.definer_unfixed() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN /* ${secret} */ RETURN 42; END $$;
      CREATE FUNCTION lr_obj.definer_fixed() RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ SELECT 1 $$;
      REVOKE ALL ON FUNCTION lr_obj.definer_fixed() FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION lr_obj.definer_fixed() TO lr_obj_leaf;
      SELECT lo_from_bytea(0,convert_to('${secret}','UTF8'));
      GRANT USAGE ON SCHEMA lr_obj TO lr_obj_automatic;
      ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
      ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO lr_obj_automatic;
      ALTER DEFAULT PRIVILEGES IN SCHEMA lr_obj GRANT INSERT ON TABLES TO lr_obj_leaf;
      CREATE TABLE lr_obj.future_table(id integer);
      RESET ROLE;
      -- The lab's PostgreSQL 16 refuses a custom placeholder setting from the
      -- owner role ("permission denied to set parameter"), so the superuser
      -- attaches it; the function stays lr_obj_owner's, the value in its settings.
      ALTER FUNCTION lr_obj.definer_unfixed() SET lr_probe.secret TO '${secret}';
      CREATE FOREIGN DATA WRAPPER lr_obj_wrapper OPTIONS (password '${secret}');
      CREATE SERVER lr_obj_server FOREIGN DATA WRAPPER lr_obj_wrapper OPTIONS (password '${secret}');
      GRANT USAGE ON FOREIGN DATA WRAPPER lr_obj_wrapper TO lr_obj_automatic WITH GRANT OPTION;
      GRANT USAGE ON FOREIGN SERVER lr_obj_server TO lr_obj_leaf;
      GRANT SET ON PARAMETER work_mem TO lr_obj_automatic WITH GRANT OPTION;
      GRANT ALTER SYSTEM ON PARAMETER work_mem TO lr_obj_leaf;
      GRANT CREATE ON TABLESPACE pg_default TO lr_obj_automatic;
      GRANT UPDATE ON pg_catalog.pg_class TO lr_obj_automatic WITH GRANT OPTION;
      GRANT UPDATE(relname) ON pg_catalog.pg_class TO lr_obj_automatic;
      DO $$ DECLARE n integer; lo oid; BEGIN
        SELECT oid INTO lo FROM pg_largeobject_metadata WHERE lomowner=(SELECT oid FROM pg_roles WHERE rolname='lr_obj_owner');
        EXECUTE format('GRANT SELECT ON LARGE OBJECT %s TO lr_obj_automatic',lo);
        EXECUTE format('GRANT UPDATE ON LARGE OBJECT %s TO lr_obj_leaf',lo);
        FOR n IN 1..55 LOOP EXECUTE format('CREATE TABLE lr_obj.page_%s(id integer)',n); END LOOP;
      END $$;
    `);
    await read("读取完成","读取并留证"); const job = await lastJob();
    observations.objectCoverage = job.result.access.objects;
    check("all thirteen native object catalogs are independently available", sectionNames.every(s => job.result.access.objects[s].state === "available"));
    const ids = JSON.parse(sql("SELECT json_object_agg(rolname,oid::bigint) FROM pg_roles WHERE starts_with(rolname,'lr_obj_') OR rolname='postgres'"));
    const targets = [];
    for (const section of sectionNames) {
      const result = await rows(section,["schemas","relations","columns","routines","types","foreign-wrappers","foreign-servers"].includes(section) ? "lr_obj" : "");
      if (section === "relations") targets.push(...result.rows.filter(r => !r.name.startsWith("page_")).map(r => ({ section, row: r })));
      else targets.push(...result.rows.map(row => ({ section,row })));
    }
    const catalogTable = await rows("relations","1259"), catalogColumn = await rows("columns","1259");
    targets.push({ section: "relations", row: catalogTable.rows[0] }, { section: "columns", row: catalogColumn.rows.find(r => r.name === "relname") });
    check("native object fixture includes every class, explicit columns and canonical array type metadata", sectionNames.every(s => targets.some(t => t.section === s)) && targets.some(t => t.row.detail.kind === "type" && t.row.name === "_color" && t.row.detail.aclTypeName === "color" && t.row.detail.aclTypeOid !== t.row.oid));
    const functions = { database: "has_database_privilege", schemas: "has_schema_privilege", relations: "has_table_privilege", columns: "has_column_privilege", routines: "has_function_privilege", types: "has_type_privilege", languages: "has_language_privilege", tablespaces: "has_tablespace_privilege", "foreign-wrappers": "has_foreign_data_wrapper_privilege", "foreign-servers": "has_server_privilege", parameters: "has_parameter_privilege" };
    const allowed = t => t.section === "relations" ? t.row.detail.relationKind === "S" ? ["SELECT","UPDATE","USAGE"] : ["SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER"] : ({ database: ["CREATE","CONNECT","TEMPORARY"], schemas: ["USAGE","CREATE"], columns: ["SELECT","INSERT","UPDATE","REFERENCES"], routines: ["EXECUTE"], types: ["USAGE"], languages: ["USAGE"], tablespaces: ["CREATE"], "foreign-wrappers": ["USAGE"], "foreign-servers": ["USAGE"], "large-objects": ["SELECT","UPDATE"], parameters: ["SET","ALTER SYSTEM"] })[t.section];
    const predicate = (t,role,privilege) => {
      const fn = t.row.detail.kind === "relation" && t.row.detail.relationKind === "S" ? "has_sequence_privilege" : functions[t.section];
      const object = t.section === "parameters" ? "'work_mem'" : `${t.row.oid}::oid`;
      return `pg_catalog.${fn}(${role},${object},${t.section === "columns" ? `${t.row.subId}::smallint,` : ""}'${privilege}')`;
    };
    const comparisons = [];
    for (const target of targets.filter(t => !["defaults","large-objects"].includes(t.section))) {
      for (const name of ["lr_obj_owner","lr_obj_login","lr_obj_data","lr_obj_set_super","postgres"]) {
        const result = await detail(target.section,target.row,ids[name]);
        if (result.analysis.state !== "available") throw new Error(`Object analysis gap ${target.section}: ${result.analysis.reason}`);
        const base = `${ids[name]}::oid`, rights = allowed(target);
        const array = (grantOption,later) => `coalesce((SELECT json_agg(privilege ORDER BY privilege) FROM (${rights.map(p => `SELECT '${p}'::text AS privilege WHERE ${later ? `NOT ${predicate(target,base,p+(grantOption ? " WITH GRANT OPTION" : ""))} AND EXISTS (SELECT 1 FROM pg_roles r WHERE pg_has_role(${base},r.oid,'SET') AND ${predicate(target,"r.oid",p+(grantOption ? " WITH GRANT OPTION" : ""))})` : predicate(target,base,p+(grantOption ? " WITH GRANT OPTION" : ""))}`).join(" UNION ALL ")}) q),'[]')`;
        comparisons.push({ section: target.section, oid: target.row.oid, subId: target.row.subId, source: name, actual: result.analysis, sql: `SELECT json_build_object('currentPrivileges',${array(false,false)},'currentGrantOptions',${array(true,false)},'additionalAfterSet',${array(false,true)},'additionalGrantOptionsAfterSet',${array(true,true)}) AS result` });
      }
    }
    const expected = parseLast(fixtureSql(`SELECT json_agg(result) FROM (${comparisons.map(c => c.sql).join(" UNION ALL ")}) oracle;`));
    comparisons.forEach((c,i) => { c.expected=expected[i]; delete c.sql; });
    observations.objectComparisons = comparisons;
    check("ordinary privileges, grant options and possible SET additions match native has-privilege predicates across eleven catalog classes", comparisons.every(c => Object.keys(c.expected).every(k => [...c.actual[k]].sort().join() === c.expected[k].sort().join())));
    const largeObject = targets.find(t => t.section === "large-objects");
    const loChecks = parseLast(fixtureSql(`CREATE TEMP TABLE lr_lo_checks(source text, privilege text, allowed boolean);
      DO $$ DECLARE r record; mode integer; allowed boolean; BEGIN
        FOR r IN SELECT oid,rolname FROM pg_roles WHERE rolname IN ('lr_obj_owner','lr_obj_login','lr_obj_data','lr_obj_set_super','postgres') LOOP
          FOREACH mode IN ARRAY ARRAY[262144,131072] LOOP
            EXECUTE format('SET LOCAL ROLE %I',r.rolname);
            BEGIN PERFORM pg_catalog.lo_close(pg_catalog.lo_open(${largeObject.row.oid},mode)); allowed:=true;
              EXCEPTION WHEN insufficient_privilege THEN allowed:=false; END;
            RESET ROLE;
            INSERT INTO lr_lo_checks VALUES(r.rolname,CASE WHEN mode=262144 THEN 'SELECT' ELSE 'UPDATE' END,allowed);
          END LOOP;
        END LOOP;
      END $$;
      SELECT json_agg(row_to_json(t)) FROM lr_lo_checks t;`));
    const loDetails = {};
    for (const name of [...new Set(loChecks.map(c => c.source))]) loDetails[name] = await detail("large-objects",largeObject.row,ids[name]);
    observations.largeObjectOpenChecks = loChecks;
    check("large-object SELECT and UPDATE sources agree with real read/write opens without fetching or changing content",loChecks.every(c => loDetails[c.source].analysis.currentPrivileges.includes(c.privilege) === c.allowed));
    const aclTable = targets.find(t => t.row.name === "acl_table" && t.section === "relations");
    const owner = await detail("relations",aclTable.row,ids.lr_obj_owner);
    check("revoked owner ordinary privileges remain empty while implicit regrant authority is retained", owner.analysis.currentPrivileges.length === 0 && owner.analysis.currentGrantOptions.length === 7 && owner.analysis.ownerVia === "self");
    const actualRows = parseLast(fixtureSql("SET SESSION AUTHORIZATION lr_obj_login; SELECT json_build_object('visible',count(*)) FROM lr_obj.acl_table; RESET SESSION AUTHORIZATION;"));
    const login = await detail("relations",aclTable.row,ids.lr_obj_login);
    check("real RLS limits visible rows despite inherited SELECT and is preserved as an unresolved policy condition", actualRows.visible === 1 && login.analysis.currentPrivileges.includes("SELECT") && login.object.detail.rowSecurity);
    const defaults = targets.filter(t => t.section === "defaults");
    const defaultDetails = await Promise.all(defaults.map(t => detail(t.section,t.row)));
    check("global and per-schema creation defaults retain distinct scope and reject existing-object role simulation", defaultDetails.some(d => d.object.aclSource === "future-global") && defaultDetails.some(d => d.object.aclSource === "future-schema") && defaultDetails.every(d => d.role === null && d.analysis === null && d.grants.every(g => g.via === "future-default")));
    const definer = await rows("routines","lr_obj","unfixed-definer");
    check("definition-owner execution and search-path presence are distinguished without function bodies or private GUC values", definer.matched === 1 && definer.rows[0].name === "definer_unfixed" && !JSON.stringify(await detail("routines",definer.rows[0],ids.lr_obj_login)).includes(secret));
    const column = targets.find(t => t.section === "columns" && t.row.name === "secret_column");
    const columnDetail = await detail("columns",column.row,ids.lr_obj_login);
    check("explicit column grants retain parent-table sources and mixed SET then INHERIT additions", columnDetail.tableGrants.some(g => g.via === "inherit" && g.privileges.includes("SELECT")) && columnDetail.grants.some(g => g.via === "after-set") && columnDetail.analysis.additionalAfterSet.join() === "UPDATE");
    const first = await rows("relations","page_"), second = await rows("relations","page_","all",50);
    check("real object pages preserve fifty-plus-five results with distinct identities", first.matched === 55 && first.rows.length === 50 && second.rows.length === 5 && !first.rows.some(a => second.rows.some(b => a.oid === b.oid)));
    check("v5 case summary retains only object coverage and bounded counts without object names or secret material", job.retention.state === "saved" && job.retention.recordText.includes("检查摘要 v5") && job.retention.recordText.includes("对象授权") && !job.retention.recordText.includes("lr_obj") && !job.retention.recordText.includes(secret));
    await click(".database-access button","查看角色属性"); await uiWait("document.querySelector('[aria-label=访问诊断详情] tbody')!==null&&[...document.querySelectorAll('[aria-label=访问诊断详情] button')].some(b=>b.textContent.includes('搜索访问诊断')&&!b.disabled)","role list loaded before searching"); await field("[aria-label=访问诊断详情]","input","lr_obj_login"); await click("[aria-label=访问诊断详情] button","搜索访问诊断");
    await uiWait("document.querySelector('[aria-label=访问诊断详情] tbody')?.textContent.includes('lr_obj_login')","actual object source role");
    await click("[aria-label=访问诊断详情] tbody button","查看权限来源");
    await uiWait("document.querySelector('[aria-label=角色权限来源] table')?.textContent.includes('lr_obj_automatic')","object role source loaded");
    await field("[aria-label=对象授权诊断]","input","acl_table"); await click("[aria-label=对象授权诊断] button","查看对象列表");
    await uiWait("document.querySelector('[aria-label=对象授权诊断] tbody')?.textContent.includes('acl_table')","native object list");
    check("object list focuses its own result heading without role panel focus theft",await page.evaluate("document.activeElement===document.querySelector('[aria-label=对象授权诊断]>h6')"));
    await click("[aria-label=对象授权诊断] tbody button","查看授权");
    await uiWait("document.querySelector('[aria-label=此角色的对象权限]')?.textContent.includes('当前普通权限：SELECT')","native object role details");
    check("object details focus and display actual inherited privileges in the minimum window",await page.evaluate("document.activeElement===document.querySelector('[aria-label=所选对象授权]>h6') && document.documentElement.scrollWidth<=innerWidth"));
    await page.shot("object-role-detail-1080x700.png");
    await click(".database-access button","查看成员授权");
    await uiWait("document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')","return to access details");
    check("object details do not steal focus from another diagnostic control",await page.evaluate("document.activeElement===document.querySelector('[aria-label=访问诊断详情] h5')"));
    // One catalog overflow must not claim an empty successful result or hide other catalogs.
    fixtureSql("DO $$ BEGIN FOR n IN 1..513 LOOP EXECUTE format('CREATE SCHEMA lr_obj_limit_%s',n); END LOOP; END $$;");
    await read(); const limited = await lastJob();
    check("native schema overflow stays explicit while other object catalogs and runtime parameters survive",limited.result.access.objects.schemas.reason === "limit-exceeded" && limited.result.access.objects.relations.state === "available" && limited.result.parameterCount > 100);
    check("unavailable object catalogs reject page retrieval",(await rpc("object-rows",{ jobHandle:limited.jobHandle,section:"schemas",query:"",filter:"all",offset:0 })).kind === "rejected");
    fixtureSql("DO $$ BEGIN FOR n IN 1..513 LOOP EXECUTE format('DROP SCHEMA lr_obj_limit_%s',n); END LOOP; END $$;");
  } catch (error) { failure=error; throw error; } finally {
    try {
      fixtureSql("DROP SERVER IF EXISTS lr_obj_server; DROP FOREIGN DATA WRAPPER IF EXISTS lr_obj_wrapper; DROP SCHEMA IF EXISTS lr_obj CASCADE;" +
        roles.map(r => `DROP OWNED BY lr_obj_${r}; DROP ROLE lr_obj_${r};`).join("\n"));
    } catch (error) { observations.objectCleanupError=String(error); if (!failure) throw error; }
  }
}
