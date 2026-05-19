import type { CvssMetrics, CvssV31Metrics, CvssV40Metrics } from './parser.js';

export type Severity = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface CvssResult {
  score: number;
  severity: Severity;
  version: '3.1' | '4.0';
  vector: string;
}

// --- CVSS v3.1 ---
const W31 = {
  AV:   { N: 0.85, A: 0.62, L: 0.55, P: 0.2  } as Record<string, number>,
  AC:   { L: 0.77, H: 0.44 }                    as Record<string, number>,
  PR_U: { N: 0.85, L: 0.62, H: 0.27 }           as Record<string, number>,
  PR_C: { N: 0.85, L: 0.68, H: 0.50 }           as Record<string, number>,
  UI:   { N: 0.85, R: 0.62 }                    as Record<string, number>,
  CIA:  { N: 0,    L: 0.22, H: 0.56 }           as Record<string, number>,
};

// Official FIRST roundup function for CVSS 3.1
function roundUp(x: number): number {
  const intInput = Math.round(x * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function scoreV31(m: CvssV31Metrics): number {
  const av = W31.AV[m.AV];
  const ac = W31.AC[m.AC];
  const pr = m.S === 'C' ? W31.PR_C[m.PR] : W31.PR_U[m.PR];
  const ui = W31.UI[m.UI];
  const c  = W31.CIA[m.C];
  const i  = W31.CIA[m.I];
  const a  = W31.CIA[m.A];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  if (iss <= 0) return 0;

  const impact = m.S === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  if (impact <= 0) return 0;

  const exploitability = 8.22 * av * ac * pr * ui;

  return m.S === 'U'
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

function severityFromScore(score: number): Severity {
  if (score === 0)    return 'None';
  if (score <  4.0)  return 'Low';
  if (score <  7.0)  return 'Medium';
  if (score <  9.0)  return 'High';
  return 'Critical';
}

// --- CVSS v4.0 (macrovector lookup per FIRST spec appendix) ---
const MACROVECTOR_SCORES: Record<string, number> = {
  '000000': 10.0, '000001': 9.9, '000010': 9.8, '000011': 9.5,
  '000020': 9.5,  '000021': 9.2, '000100': 10.0,'000101': 9.6,
  '000110': 9.3,  '000111': 8.7, '000120': 9.1, '000121': 8.1,
  '000200': 9.3,  '000201': 9.0, '000210': 8.9, '000211': 8.0,
  '000220': 8.1,  '000221': 6.8, '001000': 9.8, '001001': 9.5,
  '001010': 9.5,  '001011': 9.2, '001020': 9.2, '001021': 8.7,
  '001100': 9.5,  '001101': 9.1, '001110': 9.0, '001111': 8.3,
  '001120': 8.4,  '001121': 7.1, '001200': 9.2, '001201': 8.1,
  '001210': 8.2,  '001211': 7.1, '001220': 7.2, '001221': 5.3,
  '002001': 9.2,  '002011': 8.2, '002021': 7.2, '002101': 7.9,
  '002111': 6.9,  '002121': 5.0, '002201': 6.9, '002211': 5.5,
  '002221': 2.7,  '010000': 9.9, '010001': 9.7, '010010': 9.5,
  '010011': 9.2,  '010020': 9.2, '010021': 8.5, '010100': 9.5,
  '010101': 9.1,  '010110': 9.0, '010111': 8.3, '010120': 8.4,
  '010121': 7.1,  '010200': 9.2, '010201': 8.1, '010210': 8.2,
  '010211': 7.1,  '010220': 7.2, '010221': 5.3, '011000': 9.5,
  '011001': 9.3,  '011010': 9.2, '011011': 8.5, '011020': 9.0,
  '011021': 7.3,  '011100': 9.2, '011101': 8.2, '011110': 8.0,
  '011111': 7.2,  '011120': 7.0, '011121': 5.9, '011200': 8.4,
  '011201': 7.0,  '011210': 7.0, '011211': 5.4, '011220': 6.1,
  '011221': 2.0,  '012001': 8.7, '012011': 7.5, '012021': 5.2,
  '012101': 7.2,  '012111': 5.7, '012121': 2.4, '012201': 6.1,
  '012211': 2.4,  '012221': 1.4, '020000': 9.6, '020001': 9.3,
  '020010': 9.1,  '020011': 8.1, '020020': 8.1, '020021': 6.5,
  '020100': 9.1,  '020101': 8.1, '020110': 8.1, '020111': 6.8,
  '020120': 6.5,  '020121': 4.8, '020200': 8.1, '020201': 6.8,
  '020210': 6.8,  '020211': 5.0, '020220': 5.0, '020221': 2.0,
  '021001': 8.6,  '021011': 7.5, '021021': 5.2, '021101': 7.2,
  '021111': 5.7,  '021121': 2.4, '021201': 6.1, '021211': 2.4,
  '021221': 1.4,  '022001': 7.5, '022011': 5.2, '022021': 2.7,
  '022101': 6.1,  '022111': 2.4, '022121': 1.0, '022201': 6.1,
  '022211': 2.4,  '022221': 0.4,
};

function getEQ1(m: CvssV40Metrics): number {
  if (m.AV === 'N' && m.PR === 'N' && m.UI === 'N') return 0;
  if (m.AV !== 'P' && (m.AV === 'N' || m.PR === 'N' || m.UI === 'N')) return 1;
  return 2;
}
function getEQ2(m: CvssV40Metrics): number {
  return (m.AC === 'L' && m.AT === 'N') ? 0 : 1;
}
function getEQ3(m: CvssV40Metrics): number {
  if (m.VC === 'H' && m.VI === 'H') return 0;
  if (m.VC === 'H' || m.VI === 'H' || m.VA === 'H') return 1;
  return 2;
}
function getEQ4(m: CvssV40Metrics): number {
  if (m.SC === 'H' || m.SI === 'H' || m.SA === 'H') return 0;
  if (m.SC === 'L' || m.SI === 'L' || m.SA === 'L') return 1;
  return 2;
}
function getEQ5(_m: CvssV40Metrics): number { return 0; } // base metrics default E=A
function getEQ6(m: CvssV40Metrics): number {
  return ((m.VC === 'H' || m.VI === 'H') && m.AT === 'N') ? 0 : 1;
}

function scoreV40(m: CvssV40Metrics): number {
  const key = `${getEQ1(m)}${getEQ2(m)}${getEQ3(m)}${getEQ4(m)}${getEQ5(m)}${getEQ6(m)}`;
  return MACROVECTOR_SCORES[key] ?? 0;
}

function metricsToVector(m: CvssMetrics): string {
  if (m.version === '3.1') {
    return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
  }
  return `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;
}

export function score(metrics: CvssMetrics): CvssResult {
  const s = metrics.version === '3.1' ? scoreV31(metrics) : scoreV40(metrics as CvssV40Metrics);
  return { score: s, severity: severityFromScore(s), version: metrics.version, vector: metricsToVector(metrics) };
}
