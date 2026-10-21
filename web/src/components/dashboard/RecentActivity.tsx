import { Link } from "react-router-dom";
import { personName } from "../../auth";
import { paths } from "../../paths";
import type { AuditEvent, Summary } from "../../types";
import { RelTime } from "../ui";
import { DashCard, EmptyState, Skeleton } from "./charts";

/** Plain words for the audit actions people see most; anything else falls back to its name. */
const ACTION_WORDS: Record<string, string> = {
  "auth.login": "signed in",
  "auth.logout": "signed out",
  "auth.login_failed": "failed to sign in",
  "auth.locked": "account locked after wrong passwords",
  "package.quarantined": "imported a package (waiting for approval)",
  "package.approval_recorded": "approved a package",
  "package.approved": "package published",
  "package.rejected": "rejected a package",
  "package.revoked": "revoked a package",
  "package.reimported": "package imported again",
  "bundle.validated": "bundle checked and accepted",
  "bundle.rejected": "bundle rejected",
  "deployment.created": "planned a deployment",
  "deployment.created_rollback": "planned a rollback",
  "deployment.created_emergency": "planned an emergency deployment",
  "deployment.approved": "approved a deployment",
  "deployment.rejected": "rejected a deployment",
  "deployment.activated": "deployment started",
  "deployment.advanced": "deployment moved to the next stage",
  "deployment.paused": "paused a deployment",
  "deployment.auto_paused": "deployment paused itself (too many failures)",
  "deployment.resumed": "resumed a deployment",
  "deployment.cancelled": "cancelled a deployment",
  "deployment.completed": "deployment finished",
  "target.verified": "update confirmed on a machine",
  "target.failed": "install failed on a machine",
  "endpoint.enrolled": "machine enrolled",
  "endpoint.retired": "retired a machine",
  "endpoint.reboot_requested": "asked a machine to restart",
  "exception.created": "added an exception",
  "exception.revoked": "ended an exception",
  "alert.acknowledged": "acknowledged an alert",
  "alert.resolved": "alert closed",
  "intel.accepted": "new update information arrived",
  "intel.rejected": "update information rejected",
  "acquisition.request_exported": "asked the acquisition zone for updates",
  "acquisition.status": "download report arrived",
  "user.created": "added a user",
  "user.role_changed": "changed a user's role",
  "user.disabled": "disabled a user",
  "user.enabled": "enabled a user",
  "user.password_changed": "changed their password",
  "user.password_reset": "reset a user's password",
  "access.denied": "was refused an action (no permission)",
  "report.exported": "exported a report",
  "audit.exported": "exported the audit trail",
};

function words(action: string): string {
  return ACTION_WORDS[action] ?? action.replace(/[._]/g, " ");
}

function who(actor: string): string {
  if (!actor) return "Someone";
  if (actor.startsWith("system:")) return "System";
  if (actor.startsWith("device:") || actor.startsWith("endpoint:")) return "Agent";
  return personName(actor);
}

function objectText(e: AuditEvent): string {
  if (e.action.startsWith("auth.")) return "";
  const d = e.details ?? {};
  const name = typeof d.name === "string" ? d.name : typeof d.hostname === "string" ? d.hostname : typeof d.title === "string" ? d.title : "";
  return name || e.package_id || e.object_id || "";
}

type Props = { events: AuditEvent[] | null; error: string | null; summary: Summary | null };

/** Recent activity: the last audit events in plain words, newest first. */
export function RecentActivity({ events, error, summary }: Props) {
  return (
    <DashCard title="Recent activity" className="dash-a-recent"
              sub={summary ? (summary.audit.ok
                ? <>Audit trail intact · <span className="num">{summary.audit.count.toLocaleString()}</span> events</>
                : <span className="text-red"><b>Audit trail check failed.</b> Open the audit trail.</span>) : undefined}
              action={<Link to={paths.audit()} className="dash-link">Audit trail →</Link>}>
      {error ? <EmptyState title="Activity is not available">{error}</EmptyState>
        : !events ? <Skeleton lines={6} />
          : events.length === 0 ? <EmptyState title="No activity recorded yet" />
            : (
              <ol className="dash-feed">
                {events.map((e) => {
                  const obj = objectText(e);
                  return (
                    <li key={e.seq} className={`dash-feed-item ${e.outcome === "failure" ? "dash-feed-fail" : ""}`}>
                      <span className="dash-feed-dot" aria-hidden="true" />
                      <div className="dash-feed-body">
                        <span className="dash-feed-text">
                          <b>{who(e.actor)}</b> {words(e.action)}
                          {obj && <> · <span className="dash-feed-obj" title={obj}>{obj}</span></>}
                          {e.outcome === "failure" && <span className="text-red"> (failed)</span>}
                        </span>
                        <span className="dash-feed-time"><RelTime value={e.ts} /></span>
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
    </DashCard>
  );
}
