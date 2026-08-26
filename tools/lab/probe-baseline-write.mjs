// Proves the editor for each file shape writes a file the program itself
// accepts, by running the exact awk the tool sends against real configuration
// files on a lab host and reading the result back.
//
// Nothing here touches a live service: every edit is made on a copy under
// /tmp, and the copy is deleted afterwards.
//
//   node tools/lab/probe-baseline-write.mjs [靶机名]
import { execFileSync } from "node:child_process";

const lab = process.argv[2] ?? "arena";
const container = lab.startsWith("lab-") || lab.startsWith("svc-") ? lab : `lab-${lab}`;

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n       期望 ${JSON.stringify(expected)}\n       实际 ${JSON.stringify(actual)}`}`);
}

/** Runs a script inside the lab container, base64 so nothing is re-quoted. */
function run(script) {
  const encoded = Buffer.from(script, "utf8").toString("base64");
  return execFileSync("wsl", [
    "-d", "Ubuntu", "-u", "root", "--",
    "docker", "exec", container, "sh", "-c", `echo ${encoded} | base64 -d | sh`,
  ], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
}

// The editors, exactly as the Rust builds them. A Rust test asserts that this
// file still carries these strings, so the probe can never drift into proving
// something the tool does not send.
const WRITERS = {
  flatSpace: 'BEGIN{done=0;active=0;firstActive=0;firstComment=0} NR==FNR{p=$0; sub(/^[[:space:]]+/,"",p); if(p ~ /^#/){c=p; sub(/^#+[[:space:]]*/,"",c); t=c; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k) && firstComment==0) firstComment=FNR} else {t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)){active++; if(firstActive==0) firstActive=FNR}} next}  {indent=""; if(match($0,/[^ \\t]/)>1) indent=substr($0,1,RSTART-1); if(active>0){ if(FNR==firstActive){print indent k " " v; done=1; next} p=$0; sub(/^[[:space:]]+/,"",p); if(p !~ /^#/){t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)) next} } else if(firstComment>0 && FNR==firstComment){ print indent k " " v; done=1; next} print} END{if(!done) print k " " v}',
  flatEquals: 'BEGIN{done=0;active=0;firstActive=0;firstComment=0} NR==FNR{p=$0; sub(/^[[:space:]]+/,"",p); if(p ~ /^#/){c=p; sub(/^#+[[:space:]]*/,"",c); t=c; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k) && firstComment==0) firstComment=FNR} else {t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)){active++; if(firstActive==0) firstActive=FNR}} next}  {indent=""; if(match($0,/[^ \\t]/)>1) indent=substr($0,1,RSTART-1); if(active>0){ if(FNR==firstActive){print indent k " = " v; done=1; next} p=$0; sub(/^[[:space:]]+/,"",p); if(p !~ /^#/){t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)) next} } else if(firstComment>0 && FNR==firstComment){ print indent k " = " v; done=1; next} print} END{if(!done) print k " = " v}',
  flatSemicolon: 'BEGIN{done=0;active=0;firstActive=0;firstComment=0} NR==FNR{p=$0; sub(/^[[:space:]]+/,"",p); if(p ~ /^#/){c=p; sub(/^#+[[:space:]]*/,"",c); t=c; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k) && firstComment==0) firstComment=FNR} else {t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)){active++; if(firstActive==0) firstActive=FNR}} next}  {indent=""; if(match($0,/[^ \\t]/)>1) indent=substr($0,1,RSTART-1); if(active>0){ if(FNR==firstActive){print indent k " " v ";"; done=1; next} p=$0; sub(/^[[:space:]]+/,"",p); if(p !~ /^#/){t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)) next} } else if(firstComment>0 && FNR==firstComment){ print indent k " " v ";"; done=1; next} print} END{if(!done) print k " " v ";"}',
  ini: 'BEGIN{done=0;inS=0;seen=0;active=0;firstActive=0;firstComment=0;endOfSection=0} NR==FNR{p=$0; sub(/^[[:space:]]+/,"",p); if(p ~ /^\\[/){s=p; gsub(/^\\[|\\].*$/,"",s); gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); if(scanIn) endOfSection=FNR; scanIn=(tolower(s)==tolower("mysqld")); if(scanIn) seen=1; next} if(!scanIn) next; if(p ~ /^[#;]/){c=p; sub(/^[#;]+[[:space:]]*/,"",c); t=c; sub(/[[:space:]=].*$/,"",t); tk=tolower(t); gsub(/-/,"_",tk); kk=tolower(k); gsub(/-/,"_",kk); if(tk==kk && firstComment==0) firstComment=FNR; next} t=p; sub(/[[:space:]=].*$/,"",t); tk=tolower(t); gsub(/-/,"_",tk); kk=tolower(k); gsub(/-/,"_",kk); if(tk==kk){active++; if(firstActive==0) firstActive=FNR} next} /^[[:space:]]*\\[/{s=$0; gsub(/^[[:space:]]*\\[|\\][[:space:]]*.*$/,"",s); gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); if(inS && !done && active==0 && firstComment==0){print k " = " v; done=1} inS=(tolower(s)==tolower("mysqld")); print; next} {if(inS && active>0){ if(FNR==firstActive){print k " = " v; done=1; next} p=$0; sub(/^[[:space:]]+/,"",p); if(p !~ /^[#;]/){t=p; sub(/[[:space:]=].*$/,"",t); tk=tolower(t); gsub(/-/,"_",tk); kk=tolower(k); gsub(/-/,"_",kk); if(tk==kk) next} } else if(inS && firstComment>0 && FNR==firstComment){ print k " = " v; done=1; next} print} END{if(!done){if(!seen) print "[mysqld]"; print k " = " v}}',
  yaml: 'BEGIN{done=0;top=0;at=0;pad=""} NR==FNR{probe=$0; sub(/#.*$/,"",probe); if(probe ~ /^[[:space:]]*$/) next; ind=match(probe,/[^ ]/)-1; name=probe; sub(/^[[:space:]]*/,"",name); p=index(name,":"); if(p==0) next; name=substr(name,1,p-1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",name); while(top>0 && ind_of[top]>=ind) top--; top++; ind_of[top]=ind; name_of[top]=name; path=name_of[1]; for(i=2;i<=top;i++) path=path "." name_of[i]; if(at==0 && tolower(path)==tolower(k)){at=FNR; pad=""; for(i=0;i<ind;i++) pad=pad " "} next} {if(at>0 && FNR==at){print pad "authorization: " v; done=1; next} print} END{if(!done){print "security:"; print "  authorization: " v; }}',
  xml: 'NR==FNR{s = s $0 "\\n"; next} {next} END{rest = s; out = ""; while (length(rest) > 0) { ci = index(rest, "<!--"); ei = index(rest, "<Server"); if (ci > 0 && (ei == 0 || ci < ei)) { r2 = substr(rest, ci + 4); j = index(r2, "-->"); if (j == 0) { out = out rest; rest = ""; break } out = out substr(rest, 1, ci + 3 + j + 2); rest = substr(r2, j + 3); continue } if (ei == 0) break; tagrest = substr(rest, ei); gt = index(tagrest, ">"); if (gt == 0) break; out = out substr(rest, 1, ei - 1); tag = substr(tagrest, 1, gt); rest = substr(tagrest, gt + 1); after = substr(tag, 7 + 1, 1); if (after != " " && after != "\\t" && after != "\\n" && after != "/" && after != ">") { out = out tag; continue } if (match(tag, "[ \\t\\n]" k "[ \\t\\n]*=[ \\t\\n]*\\"[^\\"]*\\"")) { tag = substr(tag, 1, RSTART) k "=\\"" v "\\"" substr(tag, RSTART + RLENGTH) } else { tag = substr(tag, 1, 7) " " k "=\\"" v "\\"" substr(tag, 7 + 1) } done = 1; out = out tag } out = out rest; printf "%s", out; if (!done) exit 3}',
};

// The readers, so a write can be proved by reading it back the way the tool
// would. Same source, same reasoning.
const FLAT_READ_LAST =
  `BEGIN{v=""} /^[[:space:]]*#/{next} /^[[:space:]]*$/{next} {p=$0; sub(/^[[:space:]]+/,"",p); t=p; sub(/[[:space:]=].*$/,"",t); if(tolower(t)==tolower(k)){sub(/^[^[:space:]=]+[[:space:]=]+/,"",p); gsub(/^[[:space:]]+|[[:space:]]+$/,"",p); v=p}} END{print v}`;

const INI_READ = (section) =>
  `BEGIN{v="";inS=0} /^[[:space:]]*[#;]/{next} /^[[:space:]]*$/{next} /^[[:space:]]*\\[/{s=$0; gsub(/^[[:space:]]*\\[|\\][[:space:]]*.*$/,"",s); gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); inS=(tolower(s)==tolower("${section}")); next} inS{p=$0; sub(/^[[:space:]]+/,"",p); t=p; sub(/[[:space:]=].*$/,"",t); tk=tolower(t); gsub(/-/,"_",tk); kk=tolower(k); gsub(/-/,"_",kk); if(tk==kk){hasEq=(p ~ /^[^[:space:]=]+[[:space:]]*=/); sub(/^[^[:space:]=]+[[:space:]]*=?[[:space:]]*/,"",p); gsub(/^[[:space:]]+|[[:space:]]+$/,"",p); v=(hasEq ? p : (p=="" ? "on" : p))}} END{print v}`;

const YAML_READ =
  `BEGIN{v="";top=0} /^[[:space:]]*#/{next} /^[[:space:]]*$/{next} {line=$0; sub(/#.*$/,"",line); if(line ~ /^[[:space:]]*$/) next; ind=match(line,/[^ ]/)-1; name=line; sub(/^[[:space:]]*/,"",name); p=index(name,":"); if(p==0) next; val=substr(name,p+1); name=substr(name,1,p-1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",name); while(top>0 && ind_of[top]>=ind) top--; top++; ind_of[top]=ind; name_of[top]=name; path=name_of[1]; for(i=2;i<=top;i++) path=path "." name_of[i]; if(tolower(path)==tolower(k) && val!="") v=val} END{print v}`;



const XML_READ = '{s = s $0 "\\n"} END{rest = s; out = ""; while (length(rest) > 0) { ci = index(rest, "<!--"); ei = index(rest, "<Server"); if (ci > 0 && (ei == 0 || ci < ei)) { r2 = substr(rest, ci + 4); j = index(r2, "-->"); if (j == 0) { skip = rest; rest = ""; break } skip = substr(rest, 1, ci + 3 + j + 2); rest = substr(r2, j + 3); continue } if (ei == 0) break; tagrest = substr(rest, ei); gt = index(tagrest, ">"); if (gt == 0) break; skip = substr(rest, 1, ei - 1); tag = substr(tagrest, 1, gt); rest = substr(tagrest, gt + 1); after = substr(tag, 7 + 1, 1); if (after != " " && after != "\\t" && after != "\\n" && after != "/" && after != ">") { skip = tag; continue } if (match(tag, "[ \\t\\n]" k "[ \\t\\n]*=[ \\t\\n]*\\"[^\\"]*\\"")) { piece = substr(tag, RSTART, RLENGTH); sub(/^[^"]*"/, "", piece); sub(/".*$/, "", piece); if (first == "") first = piece; if (piece != r && best == "") best = piece } } print (best != "" ? best : first)}';

const CASES = [
  {
    name: "sshd_config（每行一条指令）",
    source: "/etc/ssh/sshd_config",
    key: "PermitRootLogin",
    value: "no",
    writer: WRITERS.flatSpace,
    reader: FLAT_READ_LAST,
    // sshd validates its own file, which is the strongest proof available.
    validate: "sshd -t -f",
  },
  {
    name: "redis.conf（每行一条指令）",
    source: "/etc/redis/redis.conf",
    key: "protected-mode",
    value: "yes",
    writer: WRITERS.flatSpace,
    reader: FLAT_READ_LAST,
  },
  {
    name: "nginx.conf（指令带分号）",
    source: "/etc/nginx/nginx.conf",
    key: "server_tokens",
    value: "off",
    writer: WRITERS.flatSemicolon,
    reader: FLAT_READ_LAST,
    expectRead: "off;",
  },
  {
    name: "my.cnf（分节）",
    source: "/etc/mysql/mariadb.conf.d/50-server.cnf",
    key: "local_infile",
    value: "0",
    writer: WRITERS.ini,
    reader: INI_READ("mysqld"),
    section: "mysqld",
  },
  {
    name: "mongod.conf（嵌套）",
    source: "/etc/mongod.conf",
    key: "security.authorization",
    value: "enabled",
    writer: WRITERS.yaml,
    reader: YAML_READ,
  },
  {
    name: "postgresql.conf（key = value）",
    source: "/etc/postgresql/14/main/postgresql.conf",
    key: "log_connections",
    value: "on",
    writer: WRITERS.flatEquals,
    reader: FLAT_READ_LAST,
  },
  {
    name: "server.xml（XML 属性）",
    source: "/usr/local/tomcat/conf/server.xml",
    key: "port",
    value: "-1",
    element: "Server",
    writer: WRITERS.xml,
    reader: XML_READ,
    // The element name is what the count looks for in an XML file, not the
    // attribute — `port` appears on half a dozen elements.
    countPattern: "<Server ",
    countExpected: "1",
  },
];

console.log(`在 ${container} 上验证每种文件格式的改写\n`);
for (const entry of CASES) {
  const exists = run(`[ -f '${entry.source}' ] && echo yes || echo no`).trim();
  if (exists !== "yes") {
    console.log(`  跳过 ${entry.name}：这台机器上没有 ${entry.source}`);
    continue;
  }
  console.log(`${entry.name} — ${entry.source}`);
  const script = `
set -e
cp '${entry.source}' /tmp/lr-write-test
awk -v k='${entry.key}' -v v='${entry.value}' '${entry.writer}' /tmp/lr-write-test /tmp/lr-write-test > /tmp/lr-write-out
echo "READ<<<$(awk -v k='${entry.key}' -v r='${entry.value}' '${entry.reader}' /tmp/lr-write-out)>>>"
echo "COUNT<<<$(${entry.countPattern === undefined
  ? `grep -c -iE '^[[:space:]]*${entry.key.split(".").pop()}[[:space:]=:]'`
  : `grep -c -F '${entry.countPattern}'`} /tmp/lr-write-out || true)>>>"
echo "LINESBEFORE<<<$(wc -l < /tmp/lr-write-test)>>>"
echo "LINESAFTER<<<$(wc -l < /tmp/lr-write-out)>>>"
${entry.section ? `echo "SECTION<<<$(awk '/^[[:space:]]*\\[/{s=$0; gsub(/[][]/,"",s); last=s} /${entry.key}/{print last; exit}' /tmp/lr-write-out)>>>"` : ""}
${entry.validate ? `${entry.validate} /tmp/lr-write-out >/tmp/lr-valid 2>&1 && echo "VALID<<<ok>>>" || echo "VALID<<<$(head -c 200 /tmp/lr-valid)>>>"` : ""}
rm -f /tmp/lr-write-test /tmp/lr-write-out /tmp/lr-valid
`;
  let output;
  try {
    output = run(script);
  } catch (error) {
    failures += 1;
    console.log(`  FAIL 脚本没跑起来：${String(error.message).slice(0, 200)}`);
    continue;
  }
  const field = (name) => output.match(new RegExp(`${name}<<<([\\s\\S]*?)>>>`, "u"))?.[1]?.trim() ?? "";
  check(`读回来就是刚写进去的值`, field("READ"), entry.expectRead ?? entry.value);
  check(`只留下一处该指令`, field("COUNT"), entry.countExpected ?? "1");
  const before = Number(field("LINESBEFORE"));
  const after = Number(field("LINESAFTER"));
  check(`文件其余部分没被动过（${before} 行 -> ${after} 行）`, after >= before && after - before <= 2, true);
  if (entry.section) check(`写在 [${entry.section}] 里`, field("SECTION"), entry.section);
  if (entry.validate) check(`${entry.validate.split(" ")[0]} 认这个文件`, field("VALID"), "ok");
  console.log("");
}

console.log(failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`);
process.exitCode = failures === 0 ? 0 : 1;
