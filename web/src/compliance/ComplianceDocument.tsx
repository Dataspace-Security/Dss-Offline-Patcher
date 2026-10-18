import type { CompliancePack } from "./types";
import { ControlMatrixSection, Cover, ExecutiveSummarySection, RegulatorySection, ScopeSection } from "./ReportFront";
import { EvidenceSection, FindingsSection, ReferencesSection, SignOffSection, TimelinessSection } from "./ReportBack";

/** The auditor report as a print-ready document (template sections 1–9; §10 is not part of the output). */
export function ComplianceDocument({ pack, printing }: { pack: CompliancePack; printing: boolean }) {
  return (
    <article className="crep" aria-label="Patch Management Compliance Report">
      <Cover pack={pack} />
      <ExecutiveSummarySection pack={pack} />
      <ScopeSection pack={pack} />
      <ControlMatrixSection pack={pack} />
      <RegulatorySection pack={pack} />
      <TimelinessSection pack={pack} printing={printing} />
      <EvidenceSection pack={pack} />
      <FindingsSection pack={pack} />
      <SignOffSection pack={pack} />
      <ReferencesSection pack={pack} />
    </article>
  );
}
