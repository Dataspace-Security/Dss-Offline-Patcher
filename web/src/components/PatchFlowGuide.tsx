import { useState } from "react";
import { normalizeRole, roleLabel, useMe } from "../auth";
import type { Role } from "../types";
import { fetchPolicy } from "./patchPlan";
import { useLoad } from "../util";
import "../patch.css";

const HIDDEN_KEY = "offpatch.patch-flow-hidden";

type FlowStep = { name: string; text: string };

/** What the signed-in role can do at each step, in plain words. */
export function flowSteps(role: Role, approvals: number): FlowStep[] {
  const others = approvals === 1 ? "another person's approval" : `${approvals} other people's approval`;
  switch (role) {
    case "viewer":
      return [
        { name: "Needed", text: "You can see what your machines need and how each update stands." },
        { name: "Imports", text: "Users and Admins import what is needed and follow it until it arrives." },
        { name: "Catalog", text: "You can see what was received and what is approved (read only)." },
        { name: "Deployments", text: "You can follow deployments; Users and Admins plan and approve them." },
      ];
    case "user":
    case "admin":
      return [
        { name: "Needed", text: "Import what your machines need. Software no machine has yet is added by the vendor." },
        { name: "Imports", text: "Follow each import until it arrives from the acquisition zone; ask again if it was not picked up." },
        {
          name: "Catalog",
          text: role === "admin"
            ? "Approve or reject a received package (one person is enough). You can also revoke an approved package."
            : "Approve or reject a received package (one person is enough).",
        },
        {
          name: "Deployments",
          text: `Patch this… plans a deployment; it starts only after ${others}. You approve other people's deployments.`
            + (role === "admin" ? " You also create and revoke exceptions." : ""),
        },
      ];
    case "super_admin":
      return [
        { name: "Needed / Library", text: "Import what machines need, or anything from the Library (the vendor's tool)." },
        { name: "Imports", text: "Follow each import until it arrives from the acquisition zone; ask again if it was not picked up." },
        { name: "Catalog", text: "Approve or reject packages. Agent versions are yours alone (Settings → Agent versions)." },
        { name: "Deployments", text: `You can plan deployments, but you cannot approve bank deployments: they need ${others} from the bank.` },
      ];
  }
}

/** Patches: a compact, dismissible "How patches flow" guide for the signed-in role. */
export function PatchFlowGuide() {
  const me = useMe();
  const role = normalizeRole(me?.role);
  const [hidden, setHidden] = useState(() => localStorage.getItem(HIDDEN_KEY) === "1");
  const policy = useLoad(fetchPolicy, []);
  const approvals = policy.data?.deployment_approvals ?? 1;
  const setHide = (v: boolean) => {
    if (v) localStorage.setItem(HIDDEN_KEY, "1");
    else localStorage.removeItem(HIDDEN_KEY);
    setHidden(v);
  };

  if (hidden) {
    return (
      <div className="flow-guide-reopen">
        <button type="button" className="btn-link" onClick={() => setHide(false)}>How patches flow</button>
      </div>
    );
  }
  return (
    <section className="flow-guide" aria-labelledby="flow-guide-title">
      <div className="flow-guide-head">
        <h2 id="flow-guide-title" className="flow-guide-title">How patches flow · <span className="muted">what you can do as {roleLabel(role)}</span></h2>
        <button type="button" className="btn btn-sm btn-ghost" onClick={() => setHide(true)} aria-label="Hide the guide">Hide</button>
      </div>
      <ol className="flow-guide-steps">
        {flowSteps(role, approvals).map((s, i) => (
          <li key={s.name} className="flow-guide-step">
            <div className="flow-guide-name"><span className="flow-guide-n">{i + 1}</span>{s.name}</div>
            <div className="flow-guide-text">{s.text}</div>
          </li>
        ))}
      </ol>
    </section>
  );
}
