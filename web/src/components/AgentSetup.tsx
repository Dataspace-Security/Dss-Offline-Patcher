import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
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

/** Shows content directly, or folded away behind a native disclosure when a quicker path exists. */
function ManualWrap({ collapsed, summary = "Manual install (step by step)", children }: { collapsed: boolean; summary?: string; children: ReactNode }) {
  if (!collapsed) return <>{children}</>;
  return (
    <details className="setup-more">
      <summary>{summary}</summary>
      {children}
    </details>
  );
}

/**
 * One line for an elevated Windows PowerShell. It trusts the server only if
 * the certificate chain is valid apart from the (not yet trusted) root, the
 * host name matches, and the root is exactly this server's CA (SHA-256 pin).
 * On a public-certificate name (`web`), a chain Windows fully trusts for that
 * name is accepted too: PowerShell cannot ask for the agent certificate there.
 * It then runs the installer the server generates for this enrollment token.
 *
 * The check is compiled C# (Add-Type): Windows PowerShell 5.1 cannot run a
 * script-block certificate callback on the TLS thread ("no Runspace available").
 */
const PIN_CSHARP =
  "using System;using System.Net;using System.Net.Security;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;" +
  "public static class OffpatchPin2{public static void Install(string pin,bool web){" +
  "ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;" +
  "ServicePointManager.ServerCertificateValidationCallback=delegate(object s,X509Certificate c,X509Chain ch,SslPolicyErrors e){" +
  "if(web&&e==SslPolicyErrors.None)return true;" +
  "if((e&(SslPolicyErrors.RemoteCertificateNotAvailable|SslPolicyErrors.RemoteCertificateNameMismatch))!=0)return false;" +
  "foreach(X509ChainStatus st in ch.ChainStatus){X509ChainStatusFlags f=st.Status;" +
  "if(f!=X509ChainStatusFlags.NoError&&f!=X509ChainStatusFlags.UntrustedRoot&&f!=X509ChainStatusFlags.RevocationStatusUnknown&&f!=X509ChainStatusFlags.OfflineRevocation)return false;}" +
  "X509Certificate2 root=ch.ChainElements[ch.ChainElements.Count-1].Certificate;" +
  "using(SHA256 h=SHA256.Create()){return BitConverter.ToString(h.ComputeHash(root.RawData)).Replace(\"-\",\"\")==pin;}};}}";

/**
 * `agentURL` is the agent URL from /api/agent-setup (by default the server's
 * IP), never the address this console is open on: endpoints need no DNS or
 * hosts-file entry. The line changes nothing on the PC besides the agent.
 */
export function windowsOneLiner(agentURL: string, token: string, caSha256: string, opts: { web?: boolean } = {}): string {
  return (
    `$t='${token}'; Add-Type -TypeDefinition '${PIN_CSHARP}'; [OffpatchPin2]::Install('${caSha256.toUpperCase()}', $${opts.web ? "true" : "false"}); ` +
    `iex (irm '${agentURL}/api/agent-setup/bootstrap/windows.ps1' -Headers @{'X-Enrollment-Token'=$t})`
  );
}

/**
 * cmd.exe equivalent of windowsOneLiner, for endpoints where PowerShell itself is blocked by
 * policy (AppLocker/SRP, not just a cautious admin). PowerShell's trick of pinning the whole
 * process before `irm`/`iex` runs doesn't carry over: curl.exe is a new process per call, so the
 * CA has to be written to a file first and pinned with `--cacert` on every call, starting with
 * the one that fetches windows.cmd itself. windows.cmd pins its own download of pmagent.exe the
 * same way once it is running (see the server template), so the file written here is only ever
 * needed for this first fetch, and is deleted right after.
 *
 * --ssl-no-revoke: Windows' bundled curl.exe uses the Schannel TLS backend, which always
 * attempts an online CRL/OCSP revocation check by default and fails closed when one isn't
 * reachable -- guaranteed on an air-gapped network, for a self-signed CA that never had a
 * revocation endpoint to begin with. windowsOneLiner's PowerShell callback already tolerates
 * exactly this (RevocationStatusUnknown is an explicitly accepted X509ChainStatus there).
 */
export function windowsOneLinerCmd(agentURL: string, token: string, _caPem?: string): string {
  const bootFile = "%TEMP%\\offpatch-boot.cmd";
  return `curl -k -fsS -H "X-Enrollment-Token: ${token}" "${agentURL}/api/agent-setup/bootstrap/windows.cmd" -o "${bootFile}" && call "${bootFile}" & del /f /q "${bootFile}" >nul 2>&1`;
}

/**
 * Removes the agent wherever it was installed (manual folder, MSI under
 * Program Files, one-command install): the service's own path and
 * -state-dir tell where; an MSI install is removed through Windows Installer.
 */
const REMOVE_AGENT_PS = String.raw`# Run in an elevated (Administrator) PowerShell
$svc = Get-CimInstance Win32_Service -Filter "Name='offpatch-agent'"
$msi = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -eq 'offpatch Endpoint Agent' -and $_.PSChildName -like '{*}' } | Select-Object -First 1
if (-not $svc -and -not $msi) { 'The agent is not installed on this PC.'; return }
$exe = $null; $dir = Join-Path $env:ProgramData 'offpatch'
if ($svc) {
  $m = [regex]::Match($svc.PathName, '^\s*"?(?<exe>[^"]+?\.exe)"?(?:.*-state-dir\s+"?(?<dir>[^"]+?)"?\s*$)?')
  $exe = $m.Groups['exe'].Value
  if ($m.Groups['dir'].Success) { $dir = $m.Groups['dir'].Value }
  "Agent: $exe  (data: $dir)"
  Stop-Service offpatch-agent -Force -ErrorAction SilentlyContinue
}
if ($msi) {
  Start-Process msiexec.exe -Wait -ArgumentList '/x', $msi.PSChildName, '/qn'
} elseif ($exe -and (Test-Path $exe)) {
  & $exe service uninstall
} else {
  sc.exe delete offpatch-agent | Out-Null
}
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
'Agent removed.'`;

/**
 * cmd.exe equivalent of REMOVE_AGENT_PS, for endpoints where PowerShell itself is blocked.
 * pmagent.exe's own "service uninstall" just calls the Windows service manager's Delete() --
 * exactly what `sc delete` does too -- so there's no need to locate the exe on disk at all, only
 * to decide whether an MSI uninstall (which also removes its own service registration) applies
 * instead. Every install path shown in this console uses the compiled-in default state
 * directory, so this assumes %ProgramData%\offpatch rather than parsing -state-dir out of the
 * service's registered path the way windows.ps1 does; it warns instead of guessing if the
 * registered path doesn't actually match that default.
 *
 * Deliberately goto-gated rather than wrapped in `if (...)`/`for (...) do (...)` blocks wherever
 * a pipe or redirect needs to reach a nested command literally (the reg query | findstr calls):
 * cmd.exe's parser consumes one layer of ^-escaping when it pre-scans a parenthesized block, so a
 * singly-escaped pipe/redirect that would be correct standalone breaks once nested a level deeper.
 * A flat, label-based sequence never nests, so it never needs that second layer of escaping.
 */
const REMOVE_AGENT_CMD = String.raw`:: Run in an elevated Command Prompt
set "SERVICE=offpatch-agent"
set "DIR=%ProgramData%\offpatch"
set "SVCFOUND=0"
sc query "%SERVICE%" >nul 2>&1
if not errorlevel 1 set "SVCFOUND=1"

rem Broad candidate search first (substring match over all Uninstall value data, not just
rem DisplayName), then verify below by querying just that one candidate's own DisplayName --
rem narrower than a single /s /f /d sweep could ever be on its own, and avoids a pipe nested in a
rem FOR loop's own do-block, which would hit the same escaping trap as above.
set "MSIGUID="
for /f "delims=" %%K in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "offpatch Endpoint Agent" /d 2^>nul ^| findstr /B /C:"HKEY_LOCAL_MACHINE"') do (
  for %%A in ("%%K") do set "MSIGUID=%%~nxA"
)
if not defined MSIGUID goto :msiverified
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%MSIGUID%" /v DisplayName 2>nul | findstr /L /C:"offpatch Endpoint Agent" >nul 2>nul
if errorlevel 1 set "MSIGUID="
:msiverified

if "%SVCFOUND%"=="0" if not defined MSIGUID (
  echo The agent is not installed on this PC.
  goto :eof
)

echo Data: %DIR%
if not "%SVCFOUND%"=="1" goto :afterinfo
for /f "tokens=2,*" %%P in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE%" /v ImagePath 2^>nul ^| findstr /I "ImagePath"') do set "BINPATH=%%Q"
echo Agent: %BINPATH%
echo %BINPATH% | findstr /I /C:"%DIR%" >nul 2>&1
if errorlevel 1 echo   ! this service was registered with a different -state-dir than %DIR%; its real data folder was not removed -- check with: sc qc %SERVICE%
net stop "%SERVICE%" >nul 2>&1
:afterinfo

if defined MSIGUID (
  msiexec /x "%MSIGUID%" /qn
) else if "%SVCFOUND%"=="1" (
  sc delete "%SERVICE%" >nul
)

if exist "%DIR%" rd /s /q "%DIR%"
echo Agent removed.`;

/**
 * Step-by-step agent installation, with the server URL, pinned signing
 * key(s) and (optionally) a freshly created enrollment token filled in.
 */
export function AgentSetupGuide({ token, groups, site }: { token?: string; groups?: string[]; site?: string }) {
  const { data, error } = useLoad(() => api.get<AgentSetup>("/api/agent-setup"), []);
  const [platform, setPlatform] = useState<Platform>("windows");
  // Agents connect to the agent URL the server hands out (https://<server IP>:<port> unless
  // agent_url is set), never to the address this console is open on (often the server name).
  const [serverURL, setServerURL] = useState("");
  const [urlEdited, setUrlEdited] = useState(false);
  const publicNames = data?.public_names ?? [];
  useEffect(() => {
    if (!urlEdited && data?.agent_url) setServerURL(data.agent_url);
  }, [data?.agent_url, urlEdited]);
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
  // Plain host[:port] only: the URL is embedded in commands.
  const urlValid = /^https?:\/\/([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:\d{1,5})?\/?$/.test(serverURL.trim());
  const isLocal = LOCAL_HOSTS.includes(host);
  const isHttp = serverURL.trim().startsWith("http://");
  const url = serverURL.trim().replace(/\/$/, "");
  const certHosts = data?.server_cert_hosts ?? [];
  const hostInCert = certHosts.length === 0 || certHosts.includes(host.replace(/^\[|\]$/g, ""));
  const hostIsPublic = publicNames.includes(host.toLowerCase());
  const canOneLiner = hasCA && !isHttp && urlValid && hostInCert && !!data?.windows_bootstrap && !!data?.ca_sha256;

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
      prepCmd: `:: Run in an elevated Command Prompt (PowerShell blocked? this needs none)
mkdir C:\\offpatch 2>nul
:: Copy pmagent.exe and ${keys.length > 1 ? "the .pub files" : "bundle.pub"}${extra.length ? ` and ${extra.join(" and ")}` : ""} into C:\\offpatch (the console's download buttons above work in any browser), then:
certutil -hashfile C:\\offpatch\\pmagent.exe SHA256${agentExe ? `   :: expect ${agentExe.sha256}` : ""}`,
      enroll: `C:\\offpatch\\pmagent.exe enroll -server ${url} -token ${tok} -pubkey ${pub}${ca}${root}
C:\\offpatch\\pmagent.exe run -once`,
      service: `C:\\offpatch\\pmagent.exe service install
Start-Service offpatch-agent
Get-Service offpatch-agent`,
      serviceCmd: `C:\\offpatch\\pmagent.exe service install
net start offpatch-agent
sc query offpatch-agent`,
      remove: REMOVE_AGENT_PS,
      removeCmd: REMOVE_AGENT_CMD,
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
          <span>Agent URL <em className="muted">agents connect by the server's IP (from the server's agent_url)</em></span>
          <input className="mono" value={serverURL} onChange={(e) => { setUrlEdited(true); setServerURL(e.target.value); }} />
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
      {data && !urlValid && <div className="banner banner-error">Enter the URL as <Mono>http(s)://host:port</Mono> with no path.</div>}
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

      {platform === "windows" && canOneLiner && (
        <div className="setup-quick">
          <h3>One-command install</h3>
          <div className="hint">
            On the endpoint, open <b>Windows PowerShell as Administrator</b> (not PowerShell 7) and paste this line. It
            checks the server against this CA fingerprint, downloads and verifies <Mono>pmagent.exe</Mono>, enrolls the
            computer and starts the <Mono>offpatch-agent</Mono> service. To repair or reinstall later, run it again with a new
            token; the existing enrollment is kept. Routine agent upgrades go through signed agent packages.
          </div>
          {token ? (
            <CodeBlock lang="PowerShell (Administrator)" code={windowsOneLiner(url, tok, data?.ca_sha256 ?? "", { web: hostIsPublic })} />
          ) : (
            <div className="banner banner-info">
              The command contains an enrollment token. <Link to="/endpoints">Endpoints → Create enrollment token</Link> shows
              it ready to paste (set <i>max uses</i> to enroll several machines with one command).
            </div>
          )}
          <div className="hint">CA SHA-256 <Mono>{data?.ca_sha256}</Mono></div>
          <ManualWrap collapsed summary="PowerShell blocked?">
            <div className="hint">
              For endpoints where PowerShell itself is blocked by policy (not just avoided). Paste this into an{" "}
              <b>elevated Command Prompt</b> instead — same checks, same result. It needs <Mono>curl.exe</Mono>, which
              ships with Windows 10 1803+ and Server 2019+; older images without it should use the manual,
              cmd.exe-only install steps below instead.
            </div>
            {token && <CodeBlock lang="cmd.exe (Administrator)" code={windowsOneLinerCmd(url, tok, caPem)} />}
          </ManualWrap>
        </div>
      )}
      {platform === "windows" && hasCA && urlValid && !hostInCert && (
        <div className="banner banner-warn">
          <b>{host}</b> is not in this server's certificate ({certHosts.join(", ")}), so endpoints would refuse the connection.
          Use one of those addresses, or reissue the certificate with <Mono>pmserver reissue-server-cert -hosts …</Mono>.
        </div>
      )}
      {platform === "windows" && data && !canOneLiner && (!hasCA || isHttp) && (
        <div className="banner banner-info">
          <b>One-command install is not available on this server</b>: it needs HTTPS, because the command pins this server's
          certificate so a PC can never be handed a fake agent. {isHttp ? "This server runs plain HTTP (a lab setup)" : "This server has no certificate authority configured"},
          so follow the steps below. A server set up with <Mono>install-ubuntu.sh</Mono> uses HTTPS and shows the one command here.
        </div>
      )}
      {platform === "windows" && hasCA && !data?.windows_bootstrap && data && (
        <div className="banner banner-info">
          One-command install is unavailable: stage <Mono>pmagent.exe</Mono> in <Mono>{data.agent_dist_dir}</Mono>, and serve a
          certificate issued by this server's CA (<Mono>pki_dir</Mono>).
        </div>
      )}

      <ManualWrap collapsed={platform === "windows" && canOneLiner}>
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
              <div className="hint">PowerShell blocked? <Mono>cmd.exe</Mono> equivalent:</div>
              <CodeBlock lang="cmd.exe" code={winCmds.prepCmd} />
            </li>
            <li>
              <h3>Enroll and run one check-in</h3>
              <CodeBlock lang="PowerShell / cmd.exe" code={winCmds.enroll} />
              <div className="hint">
                Enrollment stores the device identity in <Mono>C:\ProgramData\offpatch</Mono>. Each enrollment uses up one use of the token.
                {hasCA && <> The agent generates its own private key (it never leaves the endpoint) and receives a <b>client certificate</b> signed by this server's CA; it authenticates with it (mTLS) and <b>renews it automatically</b> before it expires.</>}
                {" "}These two lines are plain <Mono>pmagent.exe</Mono> invocations and work the same in cmd.exe.
              </div>
            </li>
            <li>
              <h3>Install as a Windows service</h3>
              <CodeBlock lang="PowerShell" code={winCmds.service} />
              <div className="hint">PowerShell blocked? <Mono>cmd.exe</Mono> equivalent:</div>
              <CodeBlock lang="cmd.exe" code={winCmds.serviceCmd} />
              <div className="hint">
                The service starts automatically at boot, checks in every {data?.checkin_interval_seconds ?? 60}s and logs to{" "}
                <Mono>C:\ProgramData\offpatch\agent.log</Mono>. It reboots only when a deployment's reboot policy allows it (inside a maintenance window or at the deadline); otherwise the machine shows <i>Restart needed</i>.
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
            {site && <> at site <b>{site}</b></>}. It only receives a deployment when one of the deployment's stages includes one of its groups (or <span className="tag">all</span>).
          </div>
        </li>
      </ol>
      </ManualWrap>

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
          <div className="hint">PowerShell blocked? <Mono>cmd.exe</Mono> equivalent:</div>
          <CodeBlock lang="cmd.exe" code={winCmds.removeCmd} />
        </details>
      )}
    </div>
  );
}
