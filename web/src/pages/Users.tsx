import { useState } from "react";
import { api, enc } from "../api";
import { useMe } from "../auth";
import { Empty, ErrorBanner, PageHeader, Pill, ReasonModal, RelTime, Time } from "../components/ui";
import type { User } from "../types";
import { useLoad } from "../util";

export default function Users() {
  const me = useMe();
  const { data, error, reload } = useLoad(() => api.get<User[]>("/api/users"), [], 30000);
  const [action, setAction] = useState<{ user: User; op: "disable" | "enable" } | null>(null);

  const rows = [...(data ?? [])].sort((a, b) =>
    Number(a.disabled) - Number(b.disabled) || a.username.localeCompare(b.username));

  return (
    <>
      <PageHeader title="Users" sub="People who have signed in to this console">
        <button className="btn" onClick={() => void reload()}>Refresh</button>
      </PageHeader>
      <div className="banner banner-info">
        Users and their roles come from the identity provider's groups and are refreshed at every sign-in — change
        membership there. <b>Disabling</b> a user here blocks access to offpatch locally (and ends their active sessions)
        regardless of what the identity provider says.
      </div>
      <ErrorBanner error={error} />
      {data && rows.length === 0 && <Empty>Nobody has signed in yet.</Empty>}
      {rows.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>User</th><th>Role</th><th>Source</th><th>Email</th><th>MFA</th>
              <th>First login</th><th>Last login</th><th className="num">Sessions</th><th>Status</th><th />
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => (
              <tr key={u.username} className={u.disabled ? "row-disabled" : ""}>
                <td className="cell-title">{u.username}{me?.user === u.username && <span className="muted small"> (you)</span>}</td>
                <td><span className={`role role-${u.role}`}>{u.role}</span></td>
                <td>{u.source || <span className="muted">—</span>}</td>
                <td>{u.email || <span className="muted">—</span>}</td>
                <td>{u.mfa ? <Pill state="verified" label="yes" /> : <span className="muted">no</span>}</td>
                <td className="nowrap"><Time value={u.first_login} hideRel /></td>
                <td className="nowrap"><RelTime value={u.last_login} /></td>
                <td className="num">{u.active_sessions}</td>
                <td>
                  {u.disabled ? (
                    <>
                      <Pill state="failed" label="disabled" />
                      {u.disabled_reason && <div className="cell-sub">{u.disabled_reason}</div>}
                    </>
                  ) : <Pill state="compliant" label="active" />}
                </td>
                <td className="right nowrap">
                  {u.disabled ? (
                    <button className="btn btn-sm" onClick={() => setAction({ user: u, op: "enable" })}>Enable…</button>
                  ) : (
                    <button className="btn btn-sm btn-danger-ghost" disabled={me?.user === u.username}
                            title={me?.user === u.username ? "You cannot disable yourself" : undefined}
                            onClick={() => setAction({ user: u, op: "disable" })}>Disable…</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {action && (
        <ReasonModal
          title={action.op === "disable" ? `Disable ${action.user.username}` : `Enable ${action.user.username}`}
          description={action.op === "disable"
            ? <>Blocks <b>{action.user.username}</b> from signing in and revokes their {action.user.active_sessions} active session(s) immediately. Their identity-provider account is not changed.</>
            : <>Allows <b>{action.user.username}</b> to sign in again. Their role still comes from identity-provider groups.</>}
          confirmLabel={action.op === "disable" ? "Disable user" : "Enable user"}
          danger={action.op === "disable"}
          onClose={() => setAction(null)}
          onSubmit={async (reason) => {
            await api.post(`/api/users/${enc(action.user.username)}/${action.op}`, { reason });
            await reload();
          }}
        />
      )}
    </>
  );
}
