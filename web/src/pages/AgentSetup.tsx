import { Link } from "react-router-dom";
import { AgentSetupGuide } from "../components/AgentSetup";
import { PageHeader } from "../components/ui";
import { useCan } from "../auth";

export default function AgentSetupPage() {
  const canEnroll = useCan("operator");
  return (
    <>
      <PageHeader
        title="Agent setup"
        sub="Install the offpatch agent on an endpoint. It talks only to this server and has no internet or Windows Update fallback."
      >
        {canEnroll && <Link className="btn btn-primary" to="/endpoints?enroll=1">Create enrollment token</Link>}
      </PageHeader>
      <div className="card">
        <AgentSetupGuide />
      </div>
    </>
  );
}
