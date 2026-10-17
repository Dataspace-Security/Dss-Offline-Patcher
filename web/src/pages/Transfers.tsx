import { Mono, PageHeader } from "../components/ui";
import { useLoad } from "../util";
import { DownloadsSection, fetchAcqRequests, fetchAcquisition } from "./Acquisition";
import { ReceivedSection, fetchBundles, fetchReconciliation } from "./Intake";

/**
 * Patches → Transfers: both ends of the one-way transfer on one page —
 * what the acquisition zone downloaded (and the tracked requests), and what
 * arrived through the transfer (reconciliation and bundles).
 */
export default function Transfers() {
  const acq = useLoad(fetchAcquisition, [], 30000);
  const requests = useLoad(fetchAcqRequests, [], 30000);
  const bundles = useLoad(fetchBundles, [], 15000);
  const recon = useLoad(fetchReconciliation, [], 30000);
  const refresh = () => { void acq.reload(); void requests.reload(); void bundles.reload(); void recon.reload(); };

  return (
    <>
      <PageHeader title="Transfers" sub="Downloads in the connected acquisition zone and the signed bundles that arrived through the one-way transfer.">
        <button className="btn" onClick={refresh}>Refresh</button>
      </PageHeader>
      <div className="banner banner-info">
        The isolated server cannot contact the acquisition host (one-way transfer by design), so it cannot start a run.
        Each <Mono>pmctl auto</Mono> run sends a signed status report inward; this page shows the latest one.
        To run now, on the acquisition host: <Mono>pmctl auto -config acquire.json</Mono> (or <Mono>launchctl kickstart gui/$(id -u)/com.offpatch.acquire</Mono>).
      </div>
      <section className="section">
        <h2>Downloaded in the acquisition zone</h2>
        <DownloadsSection data={acq.data} error={acq.error} requests={requests.data} requestsError={requests.error} />
      </section>
      <section className="section">
        <h2>Arrived through the transfer</h2>
        <ReceivedSection data={bundles.data} error={bundles.error} recon={recon.data} reconError={recon.error} />
      </section>
    </>
  );
}
