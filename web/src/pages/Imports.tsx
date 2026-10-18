import { PageHeader } from "../components/ui";
import { useLoad } from "../util";
import { DownloadsSection, fetchAcqRequests, fetchAcquisition } from "./Acquisition";
import { ReceivedSection, fetchBundles, fetchReconciliation } from "./Intake";

/**
 * Patches → Imports (was Transfers): what was asked for, what the
 * acquisition zone downloaded, and what arrived through the one-way transfer.
 */
export default function Imports() {
  const acq = useLoad(fetchAcquisition, [], 30000);
  const requests = useLoad(fetchAcqRequests, [], 30000);
  const bundles = useLoad(fetchBundles, [], 15000);
  const recon = useLoad(fetchReconciliation, [], 30000);
  const refresh = () => { void acq.reload(); void requests.reload(); void bundles.reload(); void recon.reload(); };

  return (
    <>
      <PageHeader title="Imports" sub="What you asked for, what the acquisition zone downloaded, and what arrived through the one-way transfer.">
        <button className="btn" onClick={refresh}>Refresh</button>
      </PageHeader>
      <div className="banner banner-info">
        This server cannot reach the acquisition zone (one-way transfer by design), so it cannot start a download run. Downloads run on a
        schedule there, and each run sends a report back with the next transfer. If something is urgent, ask the acquisition team to run it now.
      </div>
      <section className="section">
        <h2>Downloaded in the acquisition zone</h2>
        <DownloadsSection data={acq.data} error={acq.error} requests={requests.data} requestsError={requests.error}
                          onChanged={() => void requests.reload()} />
      </section>
      <section className="section">
        <h2>Arrived through the transfer</h2>
        <ReceivedSection data={bundles.data} error={bundles.error} recon={recon.data} reconError={recon.error} />
      </section>
    </>
  );
}
