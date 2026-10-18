import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { paths } from "../../paths";
import type { AcquisitionRequestRecord, Summary } from "../../types";
import { RelTime } from "../ui";
import { DashCard, Skeleton } from "./charts";

/** Subset of GET /api/acquisition used here (declared locally on purpose). */
export type AcquisitionOverview = {
  sources: { source: string; stale: boolean; age_hours: number;
    last: { finished_at: string; outcome: string; report: { host: string; outcome: "ok" | "partial" | "failed"; new_packages: string[] } } }[];
  stale_after_hours: number;
};

type Props = {
  summary: Summary | null;
  acquisition: AcquisitionOverview | null;
  acquisitionError: string | null;
  requests: AcquisitionRequestRecord[] | null;
  /** Imports (download runs, requests) are User and up; viewers see the update information and bundles only. */
  showImports?: boolean;
};

const OPEN_ITEM = new Set(["requested", "seen", "stale", "failed"]);

/** Supply chain: last download run, age of the update information, imports waiting, bundles received. */
export function SupplyChain({ summary, acquisition, acquisitionError, requests, showImports = true }: Props) {
  return (
    <DashCard title="Supply chain" className="dash-span-1" sub="How updates reach this offline network"
              action={showImports ? <Link to={paths.imports} className="dash-link">Imports →</Link> : undefined}>
      {!summary ? <Skeleton lines={5} /> : (
        <ul className="dash-facts">
          {showImports && <LastRun acquisition={acquisition} error={acquisitionError} />}
          <IntelAge summary={summary} />
          {showImports && <ImportsWaiting requests={requests} />}
          <Bundles summary={summary} />
        </ul>
      )}
    </DashCard>
  );
}

function Fact({ tone, label, value, children }: { tone: "green" | "amber" | "red" | "grey"; label: string; value: ReactNode; children?: ReactNode }) {
  return (
    <li className="dash-fact">
      <span className={`dash-fact-mark dash-fact-${tone}`} aria-hidden="true" />
      <div className="dash-fact-body">
        <div className="dash-fact-label">{label}</div>
        <div className="dash-fact-value">{value}</div>
        {children && <div className="dash-fact-note">{children}</div>}
      </div>
    </li>
  );
}

function LastRun({ acquisition, error }: { acquisition: AcquisitionOverview | null; error: string | null }) {
  if (error) return <Fact tone="grey" label="Last download run" value="Could not be checked">{error}</Fact>;
  if (!acquisition) return <Fact tone="grey" label="Last download run" value="…" />;
  const latest = [...acquisition.sources].sort((a, b) => (b.last.finished_at > a.last.finished_at ? 1 : -1))[0];
  if (!latest) {
    return <Fact tone="amber" label="Last download run" value="No report yet">Reports arrive with the next transfer from the acquisition zone.</Fact>;
  }
  const anyStale = acquisition.sources.some((s) => s.stale);
  const outcome = latest.last.report?.outcome ?? latest.last.outcome;
  const tone = anyStale || outcome === "failed" ? "red" : outcome === "partial" ? "amber" : "green";
  const news = latest.last.report?.new_packages?.length ?? 0;
  return (
    <Fact tone={tone} label="Last download run" value={<RelTime value={latest.last.finished_at} />}>
      {anyStale
        ? <>No report for more than {acquisition.stale_after_hours} h. Ask the acquisition team to check the downloads.</>
        : <>{outcome === "ok" ? "Finished" : outcome === "partial" ? "Partly finished" : "Failed"} · {news} new package{news === 1 ? "" : "s"}</>}
    </Fact>
  );
}

function IntelAge({ summary }: { summary: Summary }) {
  const intel = summary.intel;
  if (!intel) return <Fact tone="amber" label="Update information" value="None yet">It arrives through the transfer. Until then nothing is known about missing updates.</Fact>;
  const days = Math.floor((intel.age_hours ?? 0) / 24);
  const age = days >= 1 ? `${days} day${days === 1 ? "" : "s"} old` : `${Math.max(0, Math.round(intel.age_hours))} h old`;
  return (
    <Fact tone={intel.stale ? "red" : "green"} label="Update information" value={age}>
      {intel.stale ? "Too old: newer updates may be missing. Ask for fresh update information." : <>Made <RelTime value={intel.generated_at} /></>}
    </Fact>
  );
}

function ImportsWaiting({ requests }: { requests: AcquisitionRequestRecord[] | null }) {
  if (!requests) return <Fact tone="grey" label="Imports waiting" value="…" />;
  const items = requests.flatMap((r) => r.items ?? []).filter((i) => OPEN_ITEM.has(i.status));
  const notPicked = items.filter((i) => i.status === "stale" || i.status === "failed").length;
  return (
    <Fact tone={notPicked ? "amber" : items.length ? "grey" : "green"} label="Imports waiting" value={<span className="num">{items.length.toLocaleString()}</span>}>
      {items.length === 0 ? "Everything asked for has arrived." : notPicked ? `${notPicked} not picked up or failed: ask again on Imports.` : "Asked for, not arrived yet."}
    </Fact>
  );
}

function Bundles({ summary }: { summary: Summary }) {
  const b = summary.bundles ?? {};
  const validated = b.validated ?? 0;
  const rejected = b.rejected ?? 0;
  const received = b.received ?? 0;
  const total = validated + rejected + received;
  return (
    <Fact tone={rejected ? "amber" : total ? "green" : "grey"} label="Bundles received" value={<span className="num">{total.toLocaleString()}</span>}>
      <span className="num">{validated}</span> checked and accepted
      {rejected > 0 && <> · <span className="num">{rejected}</span> rejected</>}
      {received > 0 && <> · <span className="num">{received}</span> being checked</>}
    </Fact>
  );
}
