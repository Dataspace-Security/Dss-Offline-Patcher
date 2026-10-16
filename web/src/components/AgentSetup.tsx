import { useMemo, useState } from "react";
import { api, errMsg, saveBlob } from "../api";
import type { AgentSetup } from "../types";
import { fmtBytes, useLoad } from "../util";
import { ErrorBanner, Mono } from "./ui";

type Platform = "windows" | "sim";

const TOKEN_PLACEHOLDER = "<enrollment-token>";
const LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]", "::1"];

/** Multi-line command block with a copy button. */
export function CodeBlock({ code, lang }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable over plain http on non-localhost; text is selectable */
    }
  };
  return (
    <div className="codeblock">
      <div className="codeblock-head">
        <span>{lang}</span>
        <button className="btn btn-sm" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

/**
 * Step-by-step agent installation, with the server URL, pinned signing
 * key(s) and (optionally) a freshly created enrollment token filled in.
 */
export function AgentSetupGuide({ token, groups, site }: { token?: string; groups?: string[]; site?: string }) {
  const { data, error } = useLoad(() => api.get<AgentSetup>("/api/agent-setup"), []);
  const [platform, setPlatform] = useState<Platform>("windows");
  const [serverURL, setServerURL] = useState(window.location.origin);
  const [useCA, setUseCA] = useState(false);
  const [useRoot, setUseRoot] = useState(false);
  const [simHost, setSimHost] = useState("pc-lab-01");
  const [dlError, setDlError] = useState<string | null>(null);

  const tok = token || TOKEN_PLACEHOLDER;
  const keys = data?.trusted_keys ?? [];
  const keyFile = (i: number) => (keys.length === 1 ? "bundle.pub" : `bundle-${i + 1}.pub`);
  const agentExe = data?.agent_files.find((f) => f.name.toLowerCase() === "pmagent.exe");
  const caPem = data?.ca_certificate ?? "";
  // When the server hands out a CA certificate (production / mTLS) it is always pinned.
  const hasCA = caPem.trim() !== "";
  const pinCA = hasCA || useCA;

  let host = "";
  try { host = new URL(serverURL).hostname; } catch { /* invalid URL warned below */ }
  const urlValid = /^https?:\/\/[^/\s]+\/?$/.test(serverURL.trim());
  const isLocal = LOCAL_HOSTS.includes(host);
  const isHttp = serverURL.trim().startsWith("http://");
  const url = serverURL.trim().replace(/\/$/, "");

  const winCmds = useMemo(() => {
    const pub = keys.map((_, i) => `C:\\offpatch\\${keyFile(i)}`).join(",") || "C:\\offpatch\\bundle.pub";
    const ca = pinCA ? " -ca C:\\offpatch\\ca.pem" : "";
    const root = useRoot ? " -root-pubkey C:\\offpatch\\root.pub" : "";
    const extra = [pinCA ? "ca.pem" : "", useRoot ? "root.pub" : ""].filter(Boolean);
    return {
      prep: `# Run in an elevated (Administrator) PowerShell
New-Item -ItemType Directory -Force C:\\offpatch | Out-Null
# Copy pmagent.exe and ${keys.length > 1 ? "the .pub files" : "bundle.pub"}${extra.length ? ` and ${extra.join(" and ")}` : ""} into C:\\offpatch, then:
Get-FileHash C:\\offpatch\\pmagent.exe -Algorithm SHA256${agentExe ? `   # expect ${agentExe.sha256}` : ""}`,
      enroll: `C:\\offpatch\\pmagent.exe enroll -server ${url} -token ${tok} -pubkey ${pub}${ca}${root}
C:\\offpatch\\pmagent.exe run -once`,
      service: `C:\\offpatch\\pmagent.exe service install
Start-Service offpatch-agent
Get-Service offpatch-agent`,
      remove: `Stop-Service offpatch-agent
C:\\offpatch\\pmagent.exe service uninstall
Remove-Item -Recurse -Force C:\\ProgramData\\offpatch`,
      msi: `msiexec /i offpatch-agent.msi SERVER=${url} TOKEN=${tok} /qn`,
    };
  }, [keys.length, pinCA, useRoot, url, tok, agentExe?.sha256]); // eslint-disable-line react-hooks/exhaustive-deps

  const simCmds = useMemo(() => {
    const pub = keys.map((_, i) => keyFile(i)).join(",") || "bundle.pub";
    const h = simHost.trim() || "pc-lab-01";
    return {
      enroll: `./bin/pmagent enroll -server ${url} -token ${tok} -pubkey ${pub}${hasCA ? " -ca ca.pem" : ""}${useRoot ? " -root-pubkey root.pub" : ""} \\
  -platform sim -hostname ${h} -state-dir agent-state/${h}`,
      run: `./bin/pmagent run -state-dir agent-state/${h}`,
    };
  }, [keys.length, url, tok, simHost, hasCA, useRoot]); // eslint-disable-line react-hooks/exhaustive-deps

  const downloadKeys = () => {
    keys.forEach((k, i) => saveBlob(new Blob([k.public_key], { type: "application/x-pem-file" }), keyFile(i)));
  };
  const downloadAgent = async () => {
    setDlError(null);
    try {
      saveBlob(await api.blob("/api/agent-setup/files/pmagent.exe"), "pmagent.exe");
    } catch (e) {
      setDlError(errMsg(e));
    }
  };

  return (
    <div className="setup">
      <ErrorBanner error={error} />

      <div className="tabs">
        <button className={`tab ${platform === "windows" ? "tab-on" : ""}`} onClick={() => setPlatform("windows")}>Windows endpoint</button>
        <button className={`tab ${platform === "sim" ? "tab-on" : ""}`} onClick={() => setPlatform("sim")}>Simulated endpoint (lab)</button>
      </div>

      <div className="form-grid">
        <label className="field">
          <span>Server URL <em className="muted">as the endpoint reaches this server</em></span>
          <input className="mono" value={serverURL} onChange={(e) => setServerURL(e.target.value)} />
        </label>
        {platform === "sim" ? (
          <label className="field">
            <span>Simulated hostname</span>
            <input className="mono" value={simHost} onChange={(e) => setSimHost(e.target.value)} />
          </label>
        ) : hasCA ? (
          <div className="hint setup-ca">
            This server issues agent certificates; <Mono>-ca C:\offpatch\ca.pem</Mono> is added to the commands automatically.
          </div>
        ) : (
          <label className="check setup-ca">
            <input type="checkbox" checked={useCA} onChange={(e) => setUseCA(e.target.checked)} />
            Pin a CA certificate (<Mono>-ca ca.pem</Mono>) for HTTPS
          </label>
        )}
      </div>
      <label className="check setup-root">
        <input type="checkbox" checked={useRoot} onChange={(e) => setUseRoot(e.target.checked)} />
        <span>
          Pin root key for key rotation (<Mono>-root-pubkey {platform === "windows" ? "C:\\offpatch\\root.pub" : "root.pub"}</Mono>)
          <span className="hint"> — only if you have the offline root public key; it lets the agent accept rotated bundle-signing keys via signed trust documents.</span>
        </span>
      </label>
      {!urlValid && <div className="banner banner-error">Enter the URL as <Mono>http(s)://host:port</Mono> with no path.</div>}
      {hasCA && isHttp && (
        <div className="banner banner-warn">
          This server uses agent client certificates (mTLS), which require HTTPS. Use the <Mono>https://</Mono> address of the server.
        </div>
      )}
      {platform === "windows" && isLocal && (
        <div className="banner banner-warn">
          <b>{host}</b> only works on this machine. Use this server's LAN address or internal DNS name, and make sure
          pmserver's <Mono>listen</Mono> setting isn't bound to 127.0.0.1.
        </div>
      )}
      {platform === "windows" && isHttp && !isLocal && !hasCA && (
        <div className="banner banner-warn">
          Plain HTTP is acceptable on an isolated lab network only. In production set <Mono>tls_cert</Mono>/<Mono>tls_key</Mono> on the server and pin the CA.
        </div>
      )}
      {!token && (
        <div className="banner banner-info">
          The commands below show <Mono>{TOKEN_PLACEHOLDER}</Mono>. Create an enrollment token on the Endpoints page; each token enrolls one device.
        </div>
      )}

      <ol className="steps">
        <li>
          <h3>Get the files</h3>
          <div className="step-row">
            <button className="btn" onClick={downloadKeys} disabled={keys.length === 0}>
              Download {keys.length > 1 ? `${keys.length} signing keys` : "bundle.pub"}
            </button>
            <span className="hint">
              Public key the agent pins to verify every update{keys.length > 0 && <>: {keys.map((k) => <Mono key={k.key_id}>{k.key_id}</Mono>)}</>}
            </span>
          </div>
          {platform === "windows" && (
            <div className="step-row">
              {agentExe ? (
                <>
                  <button className="btn" onClick={downloadAgent}>Download pmagent.exe</button>
                  <span className="hint">{fmtBytes(agentExe.size)} · sha256 <Mono>{agentExe.sha256.slice(0, 16)}…</Mono></span>
                </>
              ) : (
                <div className="banner banner-info">
                  No agent binary is staged on this server. Build it with <Mono>make windows</Mono> and copy{" "}
                  <Mono>bin/windows/pmagent.exe</Mono> to <Mono>{data?.agent_dist_dir ?? "<data_dir>/agent-dist"}</Mono>, then reload, or carry it to the endpoint on approved media.
                </div>
              )}
            </div>
          )}
          {hasCA && (
            <div className="step-row">
              <button className="btn" onClick={() => saveBlob(new Blob([caPem], { type: "application/x-pem-file" }), "ca.pem")}>Download ca.pem</button>
              <span className="hint">The server's CA certificate. The agent pins it for TLS and uses it to verify its own client certificate.</span>
            </div>
          )}
          {platform === "sim" && <div className="hint">Build the agent on the lab machine with <Mono>make build</Mono> (creates <Mono>bin/pmagent</Mono>).</div>}
          <ErrorBanner error={dlError} />
        </li>

        {platform === "windows" ? (
          <>
            <li>
              <h3>Prepare the endpoint</h3>
              <CodeBlock lang="PowerShell" code={winCmds.prep} />
            </li>
            <li>
              <h3>Enroll and run one check-in</h3>
              <CodeBlock lang="PowerShell" code={winCmds.enroll} />
              <div className="hint">
                Enrollment stores the device identity in <Mono>C:\ProgramData\offpatch</Mono>. Each enrollment uses up one use of the token.
                {hasCA && <> The agent generates its own private key (it never leaves the endpoint) and receives a <b>client certificate</b> signed by this server's CA; it authenticates with it (mTLS) and <b>renews it automatically</b> before it expires.</>}
              </div>
            </li>
            <li>
              <h3>Install as a Windows service</h3>
              <CodeBlock lang="PowerShell" code={winCmds.service} />
              <div className="hint">
                The service starts automatically at boot, checks in every {data?.checkin_interval_seconds ?? 60}s and logs to{" "}
                <Mono>C:\ProgramData\offpatch\agent.log</Mono>. It reboots only when a deployment's reboot policy allows it (inside a maintenance window or at the deadline); otherwise it reports <i>pending reboot</i>.
              </div>
            </li>
          </>
        ) : (
          <>
            <li>
              <h3>Enroll</h3>
              <CodeBlock lang="shell" code={simCmds.enroll} />
            </li>
            <li>
              <h3>Keep it checking in</h3>
              <CodeBlock lang="shell" code={simCmds.run} />
              <div className="hint">The simulated agent pretends to be Windows 10 22H2 x64 and records "installs" in its state directory.</div>
            </li>
          </>
        )}

        <li>
          <h3>Confirm</h3>
          <div className="hint">
            The endpoint appears on the Endpoints page after its first check-in
            {groups && groups.length > 0 && <> in group(s) {groups.map((g) => <span key={g} className="tag">{g}</span>)}</>}
            {site && <> at site <b>{site}</b></>}. It only receives a deployment when one of the deployment's rings includes one of its groups (or <span className="tag">all</span>).
          </div>
        </li>
      </ol>

      {platform === "windows" && (
        <details className="setup-more">
          <summary>Mass rollout (MSI)</summary>
          <div className="hint">
            For GPO / SCCM / Intune: the MSI (built from <Mono>packaging/windows</Mono>) installs the service and enrolls in one
            step. Use a multi-use enrollment token with a short expiry.
          </div>
          <CodeBlock lang="cmd" code={winCmds.msi} />
        </details>
      )}
      {platform === "windows" && (
        <details className="setup-more">
          <summary>Remove the agent</summary>
          <CodeBlock lang="PowerShell" code={winCmds.remove} />
        </details>
      )}
    </div>
  );
}
