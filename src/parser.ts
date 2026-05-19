export interface CvssV31Metrics {
  version: '3.1';
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'R';
  S: 'U' | 'C';
  C: 'N' | 'L' | 'H';
  I: 'N' | 'L' | 'H';
  A: 'N' | 'L' | 'H';
}

export interface CvssV40Metrics {
  version: '4.0';
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  AT: 'N' | 'P';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'P' | 'A';
  VC: 'N' | 'L' | 'H';
  VI: 'N' | 'L' | 'H';
  VA: 'N' | 'L' | 'H';
  SC: 'N' | 'L' | 'H';
  SI: 'N' | 'L' | 'H';
  SA: 'N' | 'L' | 'H';
}

export type CvssMetrics = CvssV31Metrics | CvssV40Metrics;

function parseKV(parts: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const part of parts) {
    const idx = part.indexOf(':');
    if (idx < 0) throw new Error(`Invalid metric component: ${part}`);
    map[part.slice(0, idx)] = part.slice(idx + 1);
  }
  return map;
}

const V31_VALID: Record<string, string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S:  ['U', 'C'],
  C:  ['N', 'L', 'H'],
  I:  ['N', 'L', 'H'],
  A:  ['N', 'L', 'H'],
};

const V40_VALID: Record<string, string[]> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  AT: ['N', 'P'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'P', 'A'],
  VC: ['N', 'L', 'H'],
  VI: ['N', 'L', 'H'],
  VA: ['N', 'L', 'H'],
  SC: ['N', 'L', 'H'],
  SI: ['N', 'L', 'H'],
  SA: ['N', 'L', 'H'],
};

function parseV31(parts: string[]): CvssV31Metrics {
  const kv = parseKV(parts);
  for (const [k, valid] of Object.entries(V31_VALID)) {
    if (!kv[k]) throw new Error(`Missing CVSS v3.1 metric: ${k}`);
    if (!valid.includes(kv[k])) throw new Error(`Invalid value for ${k}: ${kv[k]}`);
  }
  return { version: '3.1', ...kv } as unknown as CvssV31Metrics;
}

function parseV40(parts: string[]): CvssV40Metrics {
  const kv = parseKV(parts);
  for (const [k, valid] of Object.entries(V40_VALID)) {
    if (!kv[k]) throw new Error(`Missing CVSS v4.0 metric: ${k}`);
    if (!valid.includes(kv[k])) throw new Error(`Invalid value for ${k}: ${kv[k]}`);
  }
  return { version: '4.0', ...kv } as unknown as CvssV40Metrics;
}

export function parseVector(vector: string): CvssMetrics {
  if (!vector || typeof vector !== 'string') throw new Error('Vector must be a non-empty string');
  const parts = vector.split('/');
  const prefix = parts[0];
  if (prefix === 'CVSS:3.1') return parseV31(parts.slice(1));
  if (prefix === 'CVSS:4.0') return parseV40(parts.slice(1));
  throw new Error(`Unsupported CVSS version prefix: ${prefix}. Expected CVSS:3.1 or CVSS:4.0`);
}
