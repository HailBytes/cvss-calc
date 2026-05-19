export { parseVector } from './parser.js';
export { score } from './scorer.js';
export type { CvssMetrics, CvssV31Metrics, CvssV40Metrics } from './parser.js';
export type { CvssResult, Severity } from './scorer.js';

import { parseVector } from './parser.js';
import { score } from './scorer.js';
import type { CvssResult } from './scorer.js';

export function calculate(vector: string): CvssResult {
  return score(parseVector(vector));
}
