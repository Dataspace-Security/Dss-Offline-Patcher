import { useState } from "react";
import { api, enc } from "../api";
import { samePerson, useCan, useMe } from "../auth";
import { Empty, ErrorBanner, PageHeader, Pill, ReasonModal, RelTime, RoleBadge } from "../components/ui";
import {
  assignableRoles, ChangeRoleModal, CreateUserModal, isLocalUser, mfaEnrolled, ResetPasswordModal, TempPasswordModal, userId,
} from "../components/UserDialogs";
import type { User } from "../types";
import { TwoStepSection } from "../mfa/TwoStepSection";
import { parseTime, useLoad } from "../util";

type Dialog =
  | { kind: "create" }
  | { kind: "role"; user: User }
  | { kind: "reset"; user: User }
  | { kind: "disable" | "enable" | "delete" | "reset_mfa"; user: User }
  | { kind: "temp"; email: string; password: string };

function Status({ u }: { u: User }) {
  if (u.disabled) {
    return <><Pill state="failed" label="Disabled" />{u.disabled_reason && <div className="cell-sub">{u.disabled_reason}</div>}</>;
  }
  const locked = parseTime(u.locked_until);
  if (locked && locked.getTime() > Date.now()) return <Pill state="pending_reboot" label="Locked (too many wrong passwords)" />;
  if (u.must_change_password) return <Pill state="pending" label="Must change password" />;
  return <Pill state="compliant" label="Active" />;
}

/** Authenticator-app MFA: required for bank roles, optional for the super admin. SSO users use the identity provider's MFA. */
function MfaCell({ u }: { u: User }) {
  if (!isLocalUser(u)) return <span className="muted small" title="Single sign-on users use the identity provider's MFA">via SSO</span>;
  if (mfaEnrolled(u)) return <Pill state="compliant" label="On" />;
  return u.role === "super_admin"
    ? <span className="muted small">Not set up (optional)</span>
    : <Pill state="pending" label="Not set up" />;
}

/** Settings → Users (Admins and the super admin). */
export default function Users() {
  const me = useMe();
  const isSuper = useCan("super_admin");
  const { data, error, reload } = useLoad(() => api.get<User[]>("/api/users"), [], 30000);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const roles = assignableRoles(isSuper);

  // Admins never see (or act on) the vendor's super admin accounts.
  const rows = [...(data ?? [])]
    .filter((u) => isSuper || u.role !== "super_admin")
    .sort((a, b) => Number(a.disabled) - Number(b.disabled) || userId(a).localeCompare(userId(b)));
  const isMe = (u: User) => samePerson(userId(u), me) || (!!u.username && samePerson(u.username, me));
  const close = () => setDialog(null);

  return (
    <>
      <PageHeader title="Users" sub="People who can sign in to this console">
        <button className="btn" onClick={() => void reload()}>Refresh</button>
        <button className="btn btn-primary" onClick={() => setDialog({ kind: "create" })}>Add user</button>
      </PageHeader>
      <TwoStepSection />
      <ErrorBanner error={error} />
      {data && rows.length === 0 && <Empty>No users yet. Use <b>Add user</b>.</Empty>}
      {rows.length > 0 && (
        <table className="table">
          <thead>
            <tr><th>Name</th><th>Role</th><th>Signs in with</th><th title="Who last set this account's credentials. Accounts set up by the same person (or one set up by the other) don't count as two approvers.">Set up by</th><th>MFA</th><th>Last sign-in</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((u) => {
              const local = isLocalUser(u);
              const mine = isMe(u);
              // Another admin's password, MFA and role: the super admin only
              // (an admin who could sign in as a colleague could approve twice).
              const creds = local && (isSuper || u.role !== "admin");
              return (
                <tr key={userId(u)} className={u.disabled ? "row-disabled" : ""}>
                  <td>
                    <div className="cell-title">{u.display_name || userId(u)}{mine && <span className="muted small"> (you)</span>}</div>
                    {u.display_name && <div className="cell-sub">{userId(u)}</div>}
                  </td>
                  <td><RoleBadge role={u.role} /></td>
                  <td>{local ? "E-mail and password" : "Single sign-on"}</td>
                  <td className="small">{local ? (u.cred_set_by ? u.cred_set_by.replace(/^user:/, "") : <span className="muted">—</span>) : <span className="muted">identity provider</span>}</td>
                  <td><MfaCell u={u} /></td>
                  <td className="nowrap">{u.last_login ? <RelTime value={u.last_login} /> : <span className="muted">never</span>}</td>
                  <td><Status u={u} /></td>
                  <td className="right nowrap">
                    {mine ? <span className="muted small">use Change password at the top</span> : (
                      <>
                        {creds && !u.disabled && <button className="btn btn-sm" onClick={() => setDialog({ kind: "role", user: u })}>Change role…</button>}{" "}
                        {creds && !u.disabled && <button className="btn btn-sm" onClick={() => setDialog({ kind: "reset", user: u })}>Reset password…</button>}{" "}
                        {creds && mfaEnrolled(u) && <button className="btn btn-sm" onClick={() => setDialog({ kind: "reset_mfa", user: u })}>Reset MFA…</button>}{" "}
                        {local && !creds && <span className="muted small" title="Only the Super admin resets an Admin's password or MFA or changes an Admin's role">role, password, MFA: Super admin</span>}{" "}
                        {u.disabled
                          ? <button className="btn btn-sm" onClick={() => setDialog({ kind: "enable", user: u })}>Enable…</button>
                          : <button className="btn btn-sm btn-danger-ghost" onClick={() => setDialog({ kind: "disable", user: u })}>Disable…</button>}{" "}
                        {local && <button className="btn btn-sm btn-danger-ghost" onClick={() => setDialog({ kind: "delete", user: u })}>Delete…</button>}
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {rows.some((u) => !isLocalUser(u)) && (
        <p className="hint">Single sign-on users get their role from the identity provider each time they sign in; you can still disable them here.</p>
      )}

      {dialog?.kind === "create" && (
        <CreateUserModal roles={roles} onClose={close}
          onCreated={(email, password) => { void reload(); setDialog({ kind: "temp", email, password }); }} />
      )}
      {dialog?.kind === "role" && <ChangeRoleModal user={dialog.user} roles={roles} onClose={close} onDone={reload} />}
      {dialog?.kind === "reset" && (
        <ResetPasswordModal user={dialog.user} onClose={close}
          onReset={(email, password) => { void reload(); setDialog({ kind: "temp", email, password }); }} />
      )}
      {dialog?.kind === "temp" && <TempPasswordModal email={dialog.email} password={dialog.password} onClose={close} />}
      {dialog?.kind === "delete" && (
        <ReasonModal
          title={`Delete ${dialog.user.display_name || userId(dialog.user)}`}
          description={<>
            The account, its sessions and its two-step sign-in are removed now. This cannot be undone; their past actions stay in the audit log
            and the e-mail address can be used again.
            {" "}<b>Disable</b> is the gentler option if they may need access again.
          </>}
          confirmLabel="Delete user"
          danger
          required={false}
          onClose={close}
          onSubmit={async (reason) => {
            await api.post(`/api/users/${enc(userId(dialog.user))}/delete`, { reason });
            await reload();
          }}
        />
      )}
      {dialog?.kind === "reset_mfa" && (
        <ReasonModal
          title={`Reset MFA: ${dialog.user.display_name || userId(dialog.user)}`}
          description={dialog.user.role === "super_admin"
            ? <>Their authenticator app and recovery codes stop working. They can set up two-step sign-in again from their account.</>
            : <>Their authenticator app and recovery codes stop working. At their next sign-in they must set up two-step sign-in again before they can continue.</>}
          confirmLabel="Reset MFA"
          danger
          onClose={close}
          onSubmit={async (reason) => {
            await api.post(`/api/users/${enc(userId(dialog.user))}/reset_mfa`, { reason });
            await reload();
          }}
        />
      )}
      {(dialog?.kind === "disable" || dialog?.kind === "enable") && (
        <ReasonModal
          title={`${dialog.kind === "disable" ? "Disable" : "Enable"} ${dialog.user.display_name || userId(dialog.user)}`}
          description={dialog.kind === "disable"
            ? <>They can no longer sign in, and anyone signed in as them is signed out now.</>
            : <>They can sign in again.</>}
          confirmLabel={dialog.kind === "disable" ? "Disable user" : "Enable user"}
          danger={dialog.kind === "disable"}
          onClose={close}
          onSubmit={async (reason) => {
            await api.post(`/api/users/${enc(userId(dialog.user))}/${dialog.kind}`, { reason });
            await reload();
          }}
        />
      )}
    </>
  );
}
