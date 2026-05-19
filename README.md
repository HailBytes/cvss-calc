# @hailbytes/cvss-calc

> Zero-dependency CVSS v3.1 and v4.0 calculator.

## Install

```bash
npm install @hailbytes/cvss-calc
```

## Quick Start

```typescript
import { calculate } from '@hailbytes/cvss-calc';

const r = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
console.log(r.score, r.severity); // 9.8 Critical
```

## Result Shape

```typescript
interface CvssResult {
  score: number;
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
  version: '3.1' | '4.0';
  vector: string;
}
```

## Severity Ratings

| Severity | Score Range |
|----------|-------------|
| None | 0.0 |
| Low | 0.1-3.9 |
| Medium | 4.0-6.9 |
| High | 7.0-8.9 |
| Critical | 9.0-10.0 |

## Who Is This For?

- Security teams building vulnerability dashboards
- Developers integrating CVSS scoring into CI pipelines

## See Also

- HailBytes/sbom-diff
- HailBytes/asm-scope-parser
- hailbytes.com/asm

*Built with care by HailBytes - security tooling for humans.*
