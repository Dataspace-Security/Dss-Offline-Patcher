import { useState } from "react";
import { api, enc } from "../api";
import { deploymentApprovalStatus, deploymentApprovalsRequired, personName, useMe } from "../auth";
import type { Deployment, Policy } from "../types";
import { fmtTime } from "../util";
import { Pill, ReasonModal, Time } from "./ui";

/** "Waiting for approval (1 of 2 people)": the creator counts as the first person. */
export function waitingText(d: Deployment, policy?: Policy | null): string {
  const n = (d.approvals ?? []).length;
  return `Waiting for approval (${n + 1} of ${deploymentApprovalsRequired(policy, d) + 1} people)`;
}

/** State pill for lists: amber "Waiting for approval (N of M)" with who approved, or the plain state. */
export function DeploymentStatePill({ d, policy }: { d: Deployment; policy?: Policy | null }) {
  if (d.state === "pending_approval") {
    const names = (d.approvals ?? []).map((a) => personName(a.by));
    return (
      <>
        <Pill state="pending_approval" label={waitingText(d, policy)} />
        {names.length > 0 && <div className="cell-sub">approved by {names.join(", ")}</div>}
      </>
    );
  }
  if (d.state === "rejected") {
    return (
      <>
        <Pill state="rejected" label="Rejected" />
        {d.rejected_by && <div className="cell-sub">by {personName(d.rejected_by)}</div>}
      </>
    );
  }
  return <Pill state={d.state} />;
}

type Decision = "approve" | "reject";

/**
 * Deployment page: who approved, and Approve / Reject for people who may
 * (User or Admin, not the creator, not already approved). Shows nothing for
 * deployments that are neither waiting nor rejected.
 */
export function ApprovalPanel({ d, policy, onChanged }: { d: Deployment; policy?: Policy | null; onChanged: () => void | Promise<void> }) {
  const me = useMe();
  const [decision, setDecision] = useState<Decision | null>(null);
  const rollback = d.operation === "rollback";
  const what = rollback ? "rollback" : "deployment";

  if (d.state === "rejected") {
    return (
      <section className="approval-box approval-rejected">
        <h2>Rejected</h2>
        <div>
          {d.rejected_by ? <>Rejected by <b>{personName(d.rejected_by)}</b></> : "Rejected"}
          {d.rejected_at && <> · <Time value={d.rejected_at} /></>}.
          {d.state_reason && <> Reason: {d.state_reason}</>}
        </div>
        <div className="small muted">Nothing was installed. Create a new {what} if it is still needed.</div>
        <ApprovalList d={d} />
      </section>
    );
  }
  if (d.state !== "pending_approval") return null;

  const st = deploymentApprovalStatus(d, me, policy);
  const left = Math.max(st.required - st.approvals.length, 0);

  return (
    <section className="approval-box">
      <h2>{waitingText(d, policy)}</h2>
      <div>
        This {what} needs <b>{st.required + 1} people</b>: <b>{personName(d.created_by)}</b> created it (the first person), and
        {" "}{st.required === 1 ? "one other person approves it" : `${st.required} other people approve it`} before it starts. {left > 0 && <>{left} more needed.</>}
      </div>
      <ApprovalList d={d} />
      {st.canApprove ? (
        <div className="form-actions">
          <button className="btn btn-danger-ghost" onClick={() => setDecision("reject")}>Reject…</button>
          <button className="btn btn-primary" onClick={() => setDecision("approve")}>Approve…</button>
        </div>
      ) : st.mine ? (
        <div className="small"><b>You created this, so you are the first person. {st.required === 1 ? "Another person" : `${st.required} other people`} must approve.</b></div>
      ) : st.iApproved ? (
        <div className="small"><b>You approved this.</b> Waiting for someone else.</div>
      ) : me && me.role !== "viewer" ? (
        <div className="small muted">{st.whyNot}</div>
      ) : null}
      {decision && (
        <ReasonModal
          title={decision === "approve" ? `Approve this ${what}` : `Reject this ${what}`}
          description={decision === "approve"
            ? <>Your approval is recorded with your name.{" "}
                {st.approvals.length + 1 >= st.required
                  ? <b>This is the last approval needed: the {what} starts right away.</b>
                  : <>After you, {st.required - st.approvals.length - 1} more approval{st.required - st.approvals.length - 1 === 1 ? " is" : "s are"} needed.</>}</>
            : <>Rejecting stops this {what} for good. Nothing is installed.</>}
          confirmLabel={decision === "approve" ? "Approve" : `Reject ${what}`}
          danger={decision === "reject"}
          onClose={() => setDecision(null)}
          onSubmit={async (reason) => {
            await api.post(`/api/deployments/${enc(d.deployment_id)}/${decision}`, { reason });
            await onChanged();
          }}
        />
      )}
    </section>
  );
}

function ApprovalList({ d }: { d: Deployment }) {
  const approvals = d.approvals ?? [];
  return (
    <ul className="small">
      <li>Created by <b>{personName(d.created_by)}</b> <span className="muted">{fmtTime(d.created_at)}</span> <span className="muted">(first person)</span></li>
      {approvals.length === 0 && <li className="muted">No other approval yet.</li>}
      {approvals.map((a, i) => (
        <li key={`${a.by}-${i}`}>
          Approved by <b>{personName(a.by)}</b> <span className="muted">{fmtTime(a.at)}</span>{a.reason && <> — {a.reason}</>}
        </li>
      ))}
    </ul>
  );
}
