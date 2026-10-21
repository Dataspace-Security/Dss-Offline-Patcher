import { Link } from "react-router-dom";
import { deploymentApprovalStatus, deploymentApprovalsRequired, personName, useMe } from "../../auth";
import { paths } from "../../paths";
import type { Deployment, Policy } from "../../types";
import { stageLabel } from "../deployLabels";
import { isLiveDeployment } from "../rollout";
import { RelTime } from "../ui";
import { DashCard, EmptyState, ProgressBar, Skeleton } from "./charts";
import { plural, rolloutProgress } from "./model";

const MAX_ROWS = 5;

type Props = { deployments: Deployment[] | null; policy: Policy | null; canPlan: boolean };

/** Rollouts: running deployments with live progress, and deployments waiting for approval. */
export function Rollouts({ deployments, policy, canPlan }: Props) {
  const me = useMe();
  const live = (deployments ?? []).filter(isLiveDeployment);
  const pending = (deployments ?? []).filter((d) => d.state === "pending_approval");
  return (
    <DashCard title="Rollouts" className="dash-a-roll"
              sub={deployments ? <>{plural(live.length, "running")} · {pending.length.toLocaleString()} waiting for approval</> : undefined}
              action={<Link to={paths.deployments} className="dash-link">Deployments →</Link>}>
      {!deployments ? <Skeleton lines={5} /> : (
        <div className="dash-rollouts">
          <div>
            <div className="dash-subhead">Running</div>
            {live.length === 0
              ? <EmptyState title="Nothing is being installed right now">{canPlan ? <>Start one with <b>Patch this</b> on a needed patch.</> : null}</EmptyState>
              : (
                <ul className="dash-list">
                  {live.slice(0, MAX_ROWS).map((d) => <LiveRow key={d.deployment_id} d={d} />)}
                  {live.length > MAX_ROWS && <li className="dash-more"><Link to={paths.deployments}>+{live.length - MAX_ROWS} more running</Link></li>}
                </ul>
              )}
          </div>
          <div>
            <div className="dash-subhead">Waiting for approval</div>
            {pending.length === 0
              ? <EmptyState title="Nothing is waiting for approval" />
              : (
                <ul className="dash-list">
                  {pending.slice(0, MAX_ROWS).map((d) => {
                    const st = deploymentApprovalStatus(d, me, policy);
                    const required = deploymentApprovalsRequired(policy, d);
                    const got = (d.approvals ?? []).length;
                    return (
                      <li key={d.deployment_id} className="dash-row">
                        <div className="dash-row-main">
                          <Link to={paths.deployment(d.deployment_id)} className="dash-row-title">
                            {d.name || d.deployment_id}{d.operation === "rollback" && <span className="muted"> (rollback)</span>}
                          </Link>
                          <div className="dash-row-meta">
                            <span className="num"><b>{got}</b> of <b>{required}</b> approvals</span>
                            <span className="muted"> · by {personName(d.created_by)} · <RelTime value={d.created_at} /></span>
                          </div>
                          <ApprovalDots got={got} required={required} />
                        </div>
                        <div className="dash-row-act">
                          {st.canApprove
                            ? <Link className="btn btn-sm btn-primary" to={paths.deployment(d.deployment_id)}>Review</Link>
                            : st.mine ? <span className="muted small">yours</span> : null}
                        </div>
                      </li>
                    );
                  })}
                  {pending.length > MAX_ROWS && <li className="dash-more"><Link to={paths.deployments}>+{pending.length - MAX_ROWS} more waiting</Link></li>}
                </ul>
              )}
          </div>
        </div>
      )}
    </DashCard>
  );
}

function LiveRow({ d }: { d: Deployment }) {
  const p = rolloutProgress(d);
  const stages = d.rings?.length ?? 0;
  return (
    <li className="dash-row">
      <div className="dash-row-main">
        <div className="dash-row-line">
          <Link to={paths.deployment(d.deployment_id)} className="dash-row-title">
            {d.name || d.deployment_id}{d.operation === "rollback" && <span className="muted"> (rollback)</span>}
          </Link>
          <span className="dash-row-pct num">{p.applicable ? `${p.pct}%` : "—"}</span>
        </div>
        <ProgressBar done={p.done} working={p.working} failed={p.failed} waiting={p.waiting} label={`Progress of ${d.name || d.deployment_id}`} />
        <div className="dash-row-meta">
          {d.state === "paused" && <span className="dash-flag dash-flag-red">Paused</span>}
          {stages > 1 && <span>{stageLabel(d.rings[d.current_ring]?.name, d.current_ring)} (of {stages}) · </span>}
          <span className="num">{p.done} done</span>
          {p.working > 0 && <span className="num"> · {p.working} in progress</span>}
          {p.failed > 0 && <span className="num text-red"> · {p.failed} failed</span>}
          {p.waiting > 0 && <span className="num muted"> · {p.waiting} waiting</span>}
        </div>
      </div>
    </li>
  );
}

function ApprovalDots({ got, required }: { got: number; required: number }) {
  return (
    <svg width={required * 14} height="10" aria-hidden="true" className="dash-dots">
      {Array.from({ length: required }, (_, i) => (
        <circle key={i} cx={i * 14 + 5} cy="5" r="4" fill={i < got ? "var(--green-solid)" : "none"}
                stroke={i < got ? "var(--green-solid)" : "var(--border-strong)"} strokeWidth="1.5" />
      ))}
    </svg>
  );
}
