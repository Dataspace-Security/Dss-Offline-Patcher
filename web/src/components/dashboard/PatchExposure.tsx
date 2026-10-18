import { useState } from "react";
import { Link } from "react-router-dom";
import { paths } from "../../paths";
import type { Endpoint, Package, PackageFleet } from "../../types";
import { PatchThis } from "../PatchThis";
import { DashCard, EmptyState, HBars, Skeleton, SrOnly, useWidth } from "./charts";
import { SEVERITIES, SEVERITY_FILL, bySeverity, missingSplit, neededPackages, plural, pctFloor } from "./model";

const SEV_LABEL: Record<string, string> = { critical: "Critical", important: "Important", moderate: "Moderate", low: "Low" };
const TOP_N = 5;

type Props = {
  packages: Package[] | null;
  needs: Record<string, PackageFleet> | null;
  endpoints: Endpoint[] | null;
  /** User, Admin or Super admin: may start "Patch this". */
  canPatch: boolean;
  onChanged: () => void;
};

/** Patch exposure: what is missing, by severity and by kind, and the five patches most machines need. */
export function PatchExposure({ packages, needs, endpoints, canPatch, onChanged }: Props) {
  const [patching, setPatching] = useState<string | null>(null);
  const loading = !packages || !needs || !endpoints;
  const list = neededPackages(packages, needs);
  const sev = bySeverity(list);
  const split = missingSplit(endpoints);
  const top = list.slice(0, TOP_N);
  const noIntel = !!endpoints && endpoints.length > 0 && endpoints.every((e) => !e.missing);

  return (
    <>
      <DashCard title="Missing updates" className="dash-span-1"
                sub="Machine-patches still to install"
                action={<Link to={paths.needed()} className="dash-link">Needed →</Link>}>
        {loading ? <Skeleton lines={5} /> : (
          <>
            <div className="dash-subhead">By severity <span className="muted">· catalog packages</span></div>
            {list.length === 0
              ? <EmptyState title="No catalog package is needed">Updates that are not in the catalog yet show under Windows and applications below.</EmptyState>
              : (
                <HBars label="Missing machine-patches by severity" unit="machine-patches"
                       bars={SEVERITIES.map((s) => ({
                         key: s, value: sev[s].missing, fill: SEVERITY_FILL[s],
                         label: <span className={`sev-${s}`}>{SEV_LABEL[s]}</span>,
                       }))} />
              )}
            <div className="dash-subhead">By kind <span className="muted">· from inventory</span></div>
            {noIntel
              ? <EmptyState title="No update information yet">It arrives through the transfer from the acquisition zone.</EmptyState>
              : <KindSplit os={split.os} apps={split.apps} osMachines={split.osMachines} appMachines={split.appMachines} />}
            <SrOnly>
              <table>
                <caption>Missing machine-patches by severity</caption>
                <tbody>{SEVERITIES.map((s) => <tr key={s}><td>{SEV_LABEL[s]}</td><td>{sev[s].missing}</td><td>{plural(sev[s].packages, "package")}</td></tr>)}</tbody>
              </table>
            </SrOnly>
          </>
        )}
      </DashCard>

      <DashCard title="Most needed patches" className="dash-span-2"
                sub="Catalog packages, by how many machines still need them"
                action={<Link to={paths.catalog()} className="dash-link">Catalog →</Link>}>
        {loading ? <Skeleton lines={5} /> : top.length === 0 ? (
          <EmptyState title="Nothing in the catalog is waiting to be installed">
            New needs show up on <Link to={paths.needed()}>Patches → Needed</Link>.{canPatch && " Import them from there."}
          </EmptyState>
        ) : (
          <ol className="dash-top">
            {top.map(({ pkg, fleet }) => {
              const active = fleet.active_deployment_id;
              const totalSeen = fleet.needed + fleet.up_to_date;
              return (
                <li key={pkg.package_id} className="dash-top-row">
                  <div className="dash-top-main">
                    <Link to={paths.catalog(pkg.package_id)} className="dash-top-title">{pkg.title || pkg.package_id}</Link>
                    <div className="dash-top-meta">
                      <span className={`dash-sev dash-sev-${pkg.severity}`}>{SEV_LABEL[pkg.severity] ?? pkg.severity}</span>
                      {pkg.kb && <span className="muted">{pkg.kb}</span>}
                      {pkg.state === "quarantined" && <span className="muted">· waiting for approval</span>}
                    </div>
                  </div>
                  <div className="dash-top-count">
                    <span className="num"><b>{fleet.needed.toLocaleString()}</b></span>
                    <span className="muted small">{fleet.needed === 1 ? "machine" : "machines"}</span>
                    <div className="dash-mini-meter" aria-hidden="true">
                      <span style={{ width: `${pctFloor(fleet.needed, Math.max(1, totalSeen))}%` }} />
                    </div>
                  </div>
                  <div className="dash-top-act">
                    {active
                      ? <Link className="btn btn-sm" to={paths.deployment(active)}>View rollout</Link>
                      : canPatch && <button type="button" className="btn btn-sm btn-primary" onClick={() => setPatching(pkg.package_id)}>Patch this</button>}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </DashCard>
      {patching && <PatchThis packageId={patching} onClose={() => setPatching(null)} onChanged={onChanged} />}
    </>
  );
}

function KindSplit({ os, apps, osMachines, appMachines }: { os: number; apps: number; osMachines: number; appMachines: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const total = os + apps;
  if (total === 0) return <div className="dash-ok-line">Nothing missing on machines that report.</div>;
  const gap = 2;
  const osW = width > 0 ? (apps > 0 ? Math.max(4, (os / total) * (width - gap)) : width) : 0;
  return (
    <div className="dash-kind" ref={ref} role="img" aria-label={`${os} Windows updates on ${osMachines} machines, ${apps} application updates on ${appMachines} machines`}>
      {width > 0 && (
        <svg width={width} height="10" aria-hidden="true" className="dash-kind-svg">
          {os > 0 && <rect x="0" y="0" height="10" rx="4" width={osW} fill="var(--blue-solid)" />}
          {apps > 0 && <rect x={os > 0 ? osW + gap : 0} y="0" height="10" rx="4" width={Math.max(4, width - (os > 0 ? osW + gap : 0))} fill="var(--purple-solid)" />}
        </svg>
      )}
      <div className="dash-kind-legend">
        <Link to="/endpoints?outdated=1"><span className="dash-swatch" style={{ ["--sw" as string]: "var(--blue-solid)" }} />
          Windows <b className="num">{os.toLocaleString()}</b> <span className="muted">· {plural(osMachines, "machine")}</span></Link>
        <Link to="/endpoints?outdated=1"><span className="dash-swatch" style={{ ["--sw" as string]: "var(--purple-solid)" }} />
          Applications <b className="num">{apps.toLocaleString()}</b> <span className="muted">· {plural(appMachines, "machine")}</span></Link>
      </div>
    </div>
  );
}
