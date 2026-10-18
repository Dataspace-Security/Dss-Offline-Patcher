import { useState, type FormEvent } from "react";
import { api, enc, errMsg } from "../api";
import { ROLE_HELP, roleLabel } from "../auth";
import { emailProblems, generateTempPassword, normalizeEmail, passwordProblems } from "../passwords";
import type { Role, User, UserWriteResponse } from "../types";
import { CopyBox, ErrorBanner, Modal } from "./ui";

/** The id used in /api/users/{id}/…: e-mail for local users, username for SSO users. */
export function userId(u: User): string {
  return u.email || u.username || "";
}

export function isLocalUser(u: User): boolean {
  const s = (u.source ?? "").toLowerCase();
  return s === "local" || s === "password";
}

/** Roles the signed-in person may give: Admins never see or give Super admin. */
export function assignableRoles(isSuper: boolean): Role[] {
  return isSuper ? ["viewer", "user", "admin", "super_admin"] : ["viewer", "user", "admin"];
}

function RolePicker({ value, onChange, roles }: { value: Role; onChange: (r: Role) => void; roles: Role[] }) {
  return (
    <label className="field">
      <span>Role</span>
      <select value={value} onChange={(e) => onChange(e.target.value as Role)}>
        {roles.map((r) => <option key={r} value={r}>{roleLabel(r)}</option>)}
      </select>
      <small className="hint">{ROLE_HELP[value]}</small>
    </label>
  );
}

/** Shows a temporary password exactly once, with Copy. */
export function TempPasswordModal({ email, password, onClose }: { email: string; password: string; onClose: () => void }) {
  return (
    <Modal title="Temporary password" onClose={onClose} footer={<button className="btn btn-primary" onClick={onClose}>Done</button>}>
      <div className="modal-desc">
        Give this temporary password to <b>{email}</b> in person or by phone. <b>It is shown only now.</b>{" "}
        They must choose their own password the first time they sign in.
      </div>
      <div className="temp-password"><CopyBox value={password} /></div>
    </Modal>
  );
}

/** Create a local user: e-mail, name, role, temporary password. */
export function CreateUserModal({ roles, onClose, onCreated }: {
  roles: Role[]; onClose: () => void; onCreated: (email: string, tempPassword: string) => void;
}) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [password, setPassword] = useState(generateTempPassword);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const id = normalizeEmail(email);
  const problems = [
    ...(email ? emailProblems(id) : []),
    ...(!name.trim() && email ? ["Type the person's name."] : []),
    ...passwordProblems(password, id),
  ];
  const ok = !!id && !!name.trim() && problems.length === 0;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<UserWriteResponse>("/api/users", { email: id, display_name: name.trim(), role, password });
      onCreated(id, r?.temp_password || password);
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <Modal title="Add a user" onClose={onClose}>
      <form onSubmit={submit}>
        <label className="field">
          <span>E-mail <em className="muted">they sign in with this</em></span>
          <input type="email" autoFocus autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="field">
          <span>Name</span>
          <input autoComplete="off" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <RolePicker value={role} onChange={setRole} roles={roles} />
        <label className="field">
          <span>Temporary password <em className="muted">they change it at first sign-in</em></span>
          <div className="copybox">
            <input className="mono" autoComplete="off" spellCheck={false} value={password} onChange={(e) => setPassword(e.target.value)} />
            <button type="button" className="btn" onClick={() => setPassword(generateTempPassword())}>New one</button>
          </div>
        </label>
        {problems.length > 0 && email && <ul className="problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
        <ErrorBanner error={error} />
        <div className="form-actions">
          <button type="button" className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn btn-primary" disabled={!ok || busy}>{busy ? "Adding…" : "Add user"}</button>
        </div>
      </form>
    </Modal>
  );
}

/** Change a user's role (within what the signed-in person may give). */
export function ChangeRoleModal({ user, roles, onClose, onDone }: {
  user: User; roles: Role[]; onClose: () => void; onDone: () => void | Promise<void>;
}) {
  const [role, setRole] = useState<Role>(roles.includes(user.role) ? user.role : "viewer");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = role !== user.role && reason.trim().length > 0;

  const submit = async () => {
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/api/users/${enc(userId(user))}/set_role`, { role, reason: reason.trim() });
      await onDone();
      onClose();
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <Modal title={`Change role: ${user.display_name || userId(user)}`} onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn btn-primary" onClick={() => void submit()} disabled={!ok || busy}>{busy ? "Saving…" : "Change role"}</button>
      </>
    }>
      <div className="modal-desc">Now: <b>{roleLabel(user.role)}</b>.</div>
      <RolePicker value={role} onChange={setRole} roles={roles} />
      <label className="field">
        <span>Reason <em className="req">required</em></span>
        <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the audit log" />
      </label>
      <ErrorBanner error={error} />
    </Modal>
  );
}

/** Reset a local user's password: a new temporary one, shown once afterwards. */
export function ResetPasswordModal({ user, onClose, onReset }: {
  user: User; onClose: () => void; onReset: (email: string, tempPassword: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = userId(user);

  const submit = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    const password = generateTempPassword();
    try {
      const r = await api.post<UserWriteResponse>(`/api/users/${enc(id)}/reset_password`, { password });
      onReset(id, r?.temp_password || r?.password || password);
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <Modal title={`Reset password: ${user.display_name || id}`} onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn btn-danger" onClick={() => void submit()} disabled={busy}>{busy ? "Resetting…" : "Reset password"}</button>
      </>
    }>
      <div className="modal-desc">
        Their current password stops working and they are signed out. You get a temporary password to give them;
        they must choose their own at the next sign-in.
      </div>
      <ErrorBanner error={error} />
    </Modal>
  );
}
