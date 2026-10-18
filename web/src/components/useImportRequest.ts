import { useState } from "react";
import { api, errMsg, saveBlob } from "../api";
import type { AcquisitionRequest, AcquisitionRequestRecord, AcquisitionRequestRef } from "../types";

/**
 * What one Import asks for: winget ids and KB numbers. app_archs (P2) names
 * the architecture for apps no endpoint has installed yet (Library import).
 */
export type ImportItems = { apps: string[]; kbs: string[]; app_archs?: Record<string, string> };

/**
 * "Import" = POST /api/acquisition-requests. When the server could not queue
 * the request directly (strict one-way mode, queued_to empty) the operator
 * carries the downloaded file to the acquisition host instead.
 */
export function useImportRequest(onDone?: () => void) {
  const [busy, setBusy] = useState<string | null>(null); // row key / bulk key in flight
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AcquisitionRequest | null>(null);

  const send = async (items: ImportItems, busyKey: string): Promise<AcquisitionRequest | null> => {
    if (items.apps.length + items.kbs.length === 0 || busy !== null) return null;
    setBusy(busyKey);
    setError(null);
    try {
      const body = items.app_archs && Object.keys(items.app_archs).length
        ? items : { apps: items.apps, kbs: items.kbs };
      const req = await api.post<AcquisitionRequest>("/api/acquisition-requests", body);
      if (!req.queued_to) {
        const { queued_to: _omit, ...doc } = req; // the carried file is the plain request document
        saveBlob(new Blob([JSON.stringify(doc, null, 2) + "\n"], { type: "application/json" }), `${req.request_id}.json`);
      }
      setResult(req);
      onDone?.();
      return req;
    } catch (e) {
      setError(errMsg(e));
      return null;
    } finally {
      setBusy(null);
    }
  };

  return { busy, error, result, send, dismiss: () => setResult(null) };
}

/** Latest tracked request per item, keyed "app:<winget id>" / "kb:<KB>" (case-insensitive). */
export function latestRequests(records: AcquisitionRequestRecord[] | null | undefined): Map<string, AcquisitionRequestRef> {
  const m = new Map<string, AcquisitionRequestRef>();
  for (const rec of records ?? []) {
    for (const it of rec.items ?? []) {
      const k = `${it.kind}:${it.key.toLowerCase()}`;
      const prev = m.get(k);
      if (!prev || prev.at < rec.created_at) m.set(k, { request_id: rec.request_id, at: rec.created_at, status: it.status, reason: it.reason });
    }
  }
  return m;
}
