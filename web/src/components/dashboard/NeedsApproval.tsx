import { Link } from "react-router-dom";
import { enc } from "../../api";
import { deploymentApprovalsRequired, deploymentApprovalStatus, hasRole, useMe } from "../../auth";
import { paths } from "../../paths";
import type { Deployment, Package, Policy } from "../../types";
import { approvalsRequired, approvedBy, isAgentPackage } from "../patchPlan";

const SHOWN = 6;

type Row = { key: string; to: string; kind: string; name: string; have: number; need: number; unit: string; mine: boolean; canAct: boolean };

/**
 * "Needs approval" at the top of the dashboard: every package and every
 * deployment or rollback still waiting for approvals, with how many it has
 * and needs. Users and Admins get a link to approve; others see the list.
 */
export function NeedsApproval({ packages, deployments, policy }: {
  packages: Package[] | null; deployments: Deployment[] | null; policy: Policy | null;
}) {
  const me = useMe();
  const approver = hasRole(me, "user");
  const vendor = hasRole(me, "super_admin");
  const rows: Row[] = [];
  for (const p of packages ?? []) {
    if (p.state !== "quarantined" || (isAgentPackage(p) && !vendor)) continue;
    const have = (p.approvals ?? []).length;
    const done = approvedBy(p, me);
    rows.push({
      key: `p-${p.package_id}`, to: paths.catalog(p.package_id), kind: "package", name: p.title || p.package_id,
      have, need: approvalsRequired(p, policy), unit: "approval", mine: done, canAct: approver && !done,
    });
  }
  for (const d of deployments ?? []) {
    if (d.state !== "pending_approval") continue;
    const st = deploymentApprovalStatus(d, me, policy);
    rows.push({
      key: `d-${d.deployment_id}`, to: `/deployments/${enc(d.deployment_id)}`, kind: d.operation === "rollback" ? "rollback" : "deployment",
      // The creator is the first of the people a deployment needs.
      name: d.name || d.deployment_id, have: st.approvals.length + 1, need: deploymentApprovalsRequired(policy, d) + 1, unit: "person",
      mine: st.iApproved || st.mine, canAct: st.canApprove,
    });
  }
  if (rows.length === 0) return null;
  const forMe = rows.filter((r) => r.canAct).length;
  return (
    <div className="banner banner-warn needs-approval" role="status">
      <b>Needs approval: {rows.length} item{rows.length === 1 ? "" : "s"}</b>
      {approver && <span className="muted"> · {forMe > 0 ? `${forMe} waiting for you` : "none waiting for you"}</span>}
      <ul className="plain small">
        {rows.slice(0, SHOWN).map((r) => (
          <li key={r.key}>
            <span className="tag">{r.kind}</span> <Link to={r.to}>{r.name}</Link>{" "}
            <span className="muted">· {r.have} of {r.need} {r.unit === "person" ? (r.need === 1 ? "person" : "people") : `approval${r.need === 1 ? "" : "s"}`}{r.mine ? " · you approved or created it" : ""}</span>
            {r.canAct && <> <Link className="btn btn-sm btn-primary" to={r.to}>Review &amp; approve</Link></>}
          </li>
        ))}
      </ul>
      {rows.length > SHOWN && (
        <div className="small">
          and {rows.length - SHOWN} more: <Link to={`${paths.catalog()}?state=quarantined`}>packages</Link> · <Link to="/deployments">deployments</Link>
        </div>
      )}
    </div>
  );
}
