import { useEffect, useId, useRef, useState } from "react";
import { isNginxProbePath, isNginxServerName, type NginxTlsObservation } from "../shared/nginx-repair-contract";
import type { NginxRepairController, NginxRepairState } from "./nginx-repair-controller";

const VERSIONS = { TLSv1: "TLS 1.0", TLSv1_1: "TLS 1.1", TLSv1_2: "TLS 1.2", TLSv1_3: "TLS 1.3" } as const;
const DETAILS: Record<string, string> = {
  "legacy-accepted": "仍接受旧协议，请检查修补位置和默认服务器。", "identity-verified": "握手、证书信任链与站点身份校验已通过。",
  "server-protocol-alert": "服务端明确返回协议版本拒绝。", "certificate-verification-failed": "证书未通过校验，请检查信任链、有效期和站点名称。",
  "local-tls-unavailable": "目标上的 Python 缺少 TLS 能力，未自动安装工具。", "local-protocol-unavailable": "本机 TLS 客户端无法测试此版本，不能判断服务端是否接受。",
  timeout: "连接超时，未能判断。", "handshake-failed": "握手未完成；可能与密码套件、客户端认证或服务协议有关，不能据此判定旧协议已关闭。",
  "connection-failed": "连接未完成，请检查监听端口和本机网络。",
};
function outcome(row: NginxTlsObservation): string {
  if (row.outcome === "accepted") return row.detail === "legacy-accepted" ? "接受旧协议" : "握手已完成";
  return { "protocol-rejected": "明确拒绝此版本", "certificate-rejected": "证书校验失败", "local-unavailable": "本机无法测试", inconclusive: "未能判断" }[row.outcome];
}
function endpointLabel(address: string, port: number): string { return `${address.includes(":") ? `[${address}]` : address}:${port}`; }

export function NginxConnectivityPanel({ controller, state, blocked, onCopyRecord, onDiscard }: {
  controller: NginxRepairController; state: NginxRepairState; blocked: boolean;
 onCopyRecord?: ((text: string) => Promise<unknown>) | undefined;
  onDiscard(): void;
}) {
  const id = useId();
  const [endpoint, setEndpoint] = useState("");
  const [serverName, setServerName] = useState("");
  const [path, setPath] = useState("/");
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const copyGeneration = useRef(0);
  const { endpoints, connectivity } = state;
  useEffect(() => { setEndpoint(endpoints?.endpoints.length === 1 ? endpoints.endpoints[0]!.endpointHandle : ""); }, [endpoints]);
  useEffect(() => { copyGeneration.current += 1; setCopyStatus(null); return () => { copyGeneration.current += 1; }; }, [connectivity?.observationHandle]);
  const validName = isNginxServerName(serverName), validPath = isNginxProbePath(path);
  const selected = endpoints?.endpoints.find((item) => item.endpointHandle === endpoint);
  return <section className="nginx-connectivity" aria-label="TLS 连接复核">
    <header><div><h3>TLS 连接复核</h3><p>选择实际监听端口与站点，查看修补前后的连接结果。</p></div>
      <button type="button" disabled={blocked || !state.selectedInstance} onClick={() => void controller.read("listeners", state.selectedInstance!)}>读取监听端口</button></header>
    <p className="nginx-repair-note">从目标主机本机发起连接，按目标系统信任库校验证书。现代 TLS 校验成功后发送一次 HEAD 请求，只保留状态码；连接可能产生访问日志。</p>
    <p className="nginx-repair-note">完成的观察自动留存到复核开始时的当前案件；没有当前案件时新建案件。不同复核分别记录，保存重试不会再次探测。</p>
    {endpoints?.endpoints.length === 0 ? <p className="nginx-repair-empty">未发现此主进程持有的 TCP 监听端口。请检查实例运行状态；这不代表服务已关闭。</p> : null}
    {endpoints && endpoints.endpoints.length > 0 ? <form className="nginx-connectivity-form" onSubmit={(event) => {
      event.preventDefault(); if (selected && validName && validPath) void controller.probe(endpoint, serverName, path);
    }}>
      <label>监听端口<select aria-label="Nginx 监听端口" value={endpoint} disabled={blocked} onChange={(event) => { setEndpoint(event.target.value); controller.clearConnectivity(); }}>
        <option value="">请选择要检查的 TLS 端口</option>
        {endpoints.endpoints.map((item) => <option key={item.endpointHandle} value={item.endpointHandle}>{endpointLabel(item.address, item.port)}</option>)}
      </select></label>
      <label>站点域名或 IP<input aria-label="TLS 站点名称" aria-describedby={`${id}-name`} autoComplete="off" spellCheck={false} maxLength={253} value={serverName} disabled={blocked}
        placeholder="例如 www.example.com" onChange={(event) => { setServerName(event.target.value); controller.clearConnectivity(); }} /></label>
      <label>HTTP 路径<input aria-label="TLS 复核 HTTP 路径" aria-describedby={`${id}-path`} autoComplete="off" spellCheck={false} maxLength={1024} value={path} disabled={blocked}
        onChange={(event) => { setPath(event.target.value); controller.clearConnectivity(); }} /></label>
      <button type="submit" disabled={blocked || !selected || !validName || !validPath}>{state.reading === "probe" ? "正在复核…" : "开始连接复核"}</button>
      <p id={`${id}-name`} className="nginx-repair-note">名称用于证书匹配和站点选择（SNI），连接地址固定为所选端口。中文域名请填写 Punycode。{serverName && !validName ? "请输入有效名称，不含协议、端口或空格。" : ""}</p>
      <p id={`${id}-path`} className="nginx-repair-note">路径以 / 开头，不含查询参数、片段或空格；不跟随重定向，不发送账号凭据。{!validPath ? "请修正路径后重试。" : ""}</p>
    </form> : null}
    {selected ? <p className="nginx-repair-note">本次连接：{endpointLabel(selected.connectAddress, selected.port)}。未加密的 HTTP 端口无法完成 TLS 握手。</p> : null}
    {connectivity ? <div className="nginx-connectivity-result" role="status">
      <h4>连接观察结果</h4><p>{connectivity.serverName}{connectivity.path} · <time dateTime={connectivity.checkedAt}>{new Date(connectivity.checkedAt).toLocaleString()}</time></p>
      <div className={connectivity.retention.state === "saved" ? "nginx-retention-saved" : "nginx-repair-warning"}>
        <strong>{connectivity.retention.state === "saved" ? `已留存到案件：${connectivity.retention.caseTitle}` : "本次观察尚未留证"}</strong>
        <p>{connectivity.retention.detail}</p>
        {connectivity.retention.state === "unsaved" ? <p>当前结果仍可查看和复制。未保存记录仅在本次连接中暂存，5 分钟无操作后可能失效；请先处理，再开始新操作。</p> : null}
        {connectivity.retention.state === "unsaved" && connectivity.retention.canRetry && connectivity.retention.caseId === null ? <p>本次尚未确定归属案件。重试保存时使用届时的当前案件；没有当前案件时新建。</p> : null}
        <div className="nginx-retention-actions">
          {onCopyRecord && connectivity.recordText !== null ? <button type="button" onClick={() => {
            const recordText = connectivity.recordText!;
            const generation = ++copyGeneration.current;
            const show = (message: string) => { if (generation === copyGeneration.current) setCopyStatus(message); };
            void onCopyRecord(recordText).then(() => show("已复制完整观察记录。"), () => show("复制未完成，请重新尝试。"));
          }}>复制完整记录</button> : null}
          {connectivity.retention.state === "unsaved" && connectivity.retention.canRetry ? <button type="button" disabled={state.reading !== null} onClick={() => void controller.retainObservation()}>重试保存本次观察</button> : null}
          {connectivity.retention.state === "unsaved" ? <button type="button" disabled={state.reading !== null} onClick={onDiscard}>放弃未保存结果</button> : null}
        </div>
        {copyStatus ? <p>{copyStatus}</p> : null}
      </div>
      <div className="nginx-connectivity-table"><table><caption>每个协议独立复核；HTTP 状态码需要结合接口预期判断。</caption>
        <thead><tr><th>协议</th><th>连接结果</th><th>证书</th><th>HTTP</th><th>说明</th></tr></thead>
        <tbody>{connectivity.report.rows.map((row) => <tr key={row.version}>
          <th scope="row">{VERSIONS[row.version]}</th><td>{outcome(row)}</td>
          <td>{row.certificateSha256 ? "已校验" : row.outcome === "certificate-rejected" ? "未通过" : row.detail === "legacy-accepted" ? "未校验" : "未完成"}</td>
          <td>{row.httpStatus !== null ? `HTTP ${row.httpStatus}` : row.httpOutcome === "unavailable" ? "未取得状态码" : "未发送"}</td><td>{DETAILS[row.detail]}</td>
        </tr>)}</tbody></table></div>
      <details><summary>复核来源与证书摘要</summary><p>客户端：{connectivity.report.clientVersion}。证书 SHA-256 仅指本次取得的叶证书。</p>
        {connectivity.retention.evidenceId ? <p>案件证据编号：{connectivity.retention.evidenceId}</p> : null}
        {connectivity.retention.sha256 ? <p className="nginx-repair-location">案件记录 SHA-256：{connectivity.retention.sha256}</p> : null}
        {connectivity.report.rows.filter((row) => row.certificateSha256).map((row) => <p key={row.version} className="nginx-repair-location">{VERSIONS[row.version]}：{row.certificateSha256}</p>)}
        <p>旧协议仅测试握手，不校验证书或发送 HTTP。未检查证书撤销状态。结果不能证明公网、负载均衡、其他站点或业务数据已恢复；请继续从实际客户端验证业务。</p></details>
      {connectivity.recordText !== null ? <details><summary>查看完整观察记录</summary><pre className="nginx-connectivity-record">{connectivity.recordText}</pre></details> : null}
    </div> : null}
  </section>;
}
