import { Link } from "react-router-dom";
import { AgentSetupGuide } from "../components/AgentSetup";
import { PageHeader } from "../components/ui";
import { useCan } from "../auth";
import { paths } from "../paths";

export default function AgentSetupPage() {
  const canEnroll = useCan("user");
  return (
    <>
      <PageHeader
        title="Agent setup"
        sub="Install the DSS Patcher agent on an endpoint. It talks only to this server and has no internet or Windows Update fallback."
      >
        {canEnroll && <Link className="btn btn-primary" to={`${paths.endpoints}?enroll=1`}>Create enrollment token</Link>}
      </PageHeader>
      <div className="card">
        <AgentSetupGuide />
      </div>
    </>
  );
}
