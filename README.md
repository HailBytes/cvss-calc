# @hailbytes/cvss-calc

> Zero-dependency CVSS v3.1 and v4.0 calculator. Parse and score vulnerability vectors as a library or embedded web component — no network calls, no build step required.

[![npm version](https://img.shields.io/npm/v/%40hailbytes%2Fcvss-calc.svg)](https://www.npmjs.com/package/@hailbytes/cvss-calc)
[![npm downloads](https://img.shields.io/npm/dw/%40hailbytes%2Fcvss-calc.svg)](https://www.npmjs.com/package/@hailbytes/cvss-calc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero deps](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](#)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/%40hailbytes%2Fcvss-calc)](https://bundlephobia.com/package/@hailbytes/cvss-calc)

---

## What it does

Parse and score any CVSS v3.1 or v4.0 vector string in milliseconds — fully offline, zero dependencies. Use the `calculate()` function in your CI pipeline, vuln management tool, or ticketing integration, or drop the `<hailbytes-cvss-calc>` web component directly into any page.

---

## Install

```bash
npm install @hailbytes/cvss-calc
```

---

## Quick Start

### Library

```ts
import { calculate } from '@hailbytes/cvss-calc';

// Score a CVSS v3.1 vector
const result = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
console.log(result.score);    // 9.8
console.log(result.severity); // 'Critical'
console.log(result.version);  // '3.1'

// Score a CVSS v4.0 vector
const v4 = calculate('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
console.log(v4.score);    // 10.0
console.log(v4.severity); // 'Critical'
```

### Lower-level API

```ts
import { parseVector, score } from '@hailbytes/cvss-calc';

const metrics = parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
const result = score(metrics);
```

### Web Component

```html
<!-- via npm -->
<script type="module">
  import '@hailbytes/cvss-calc/element';
</script>

<!-- or CDN -->
<script type="module" src="https://cdn.jsdelivr.net/npm/@hailbytes/cvss-calc/dist/element.js"></script>

<hailbytes-cvss-calc></hailbytes-cvss-calc>

<!-- Pre-populate with a vector -->
<hailbytes-cvss-calc vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"></hailbytes-cvss-calc>

<!-- Listen for results -->
<script>
document.querySelector('hailbytes-cvss-calc').addEventListener('cvss-calculated', (e) => {
  console.log(e.detail.score, e.detail.severity);
});
</script>
```

---

## Result Shape

```ts
interface CvssResult {
  score: number;           // 0.0 – 10.0
  severity: Severity;      // 'None' | 'Low' | 'Medium' | 'High' | 'Critical'
  version: '3.1' | '4.0'; // CVSS version parsed from the vector
  vector: string;          // Normalized vector string
}
```

---

## Severity Ratings

| Severity | Score Range |
|---|---|
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

Scoring follows the official [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document).

---

## Who Is This For

Security engineers and DevSecOps teams building vuln management tooling, ticketing integrations, SIEM dashboards, or any tool that needs to parse and display CVSS scores without a third-party API or server call.

---

## See Also

- [`@hailbytes/sbom-diff`](https://github.com/HailBytes/sbom-diff) — Diff CycloneDX/SPDX SBOMs and surface new CVEs
- [`@hailbytes/asm-scope-parser`](https://github.com/HailBytes/asm-scope-parser) — Parse and normalize attack surface scope definitions
- [HailBytes ASM](https://hailbytes.com/asm) — Attack Surface Management platform

---

*Part of the [HailBytes](https://hailbytes.com) open-source security toolkit.*
