---
title: "Score Any CVSS Vector Offline — v3.1 and v4.0, Zero Dependencies"
published: false
description: A 4 KB JavaScript library that parses and scores CVSS vectors with no network calls, no build step, and no third-party API. Use it in CI or drop a web component into any page.
tags: security, javascript, webdev, opensource
cover_image: <COVER_IMAGE_URL>
canonical_url: https://github.com/hailbytes/cvss-calc
published_at: 2026-05-19 13:00 +0000
---

<!--
COVER IMAGE PROMPT (1000x420, 2.4:1 banner):

Flat vector illustration, isometric perspective. A clean digital severity gauge / speedometer
showing a needle pointed at "Critical" with the value 9.8 visible on the dial. Arc segments
graduate from green (low) through amber (medium/high) to red (critical). Subtle floating
geometric polygons in the background suggesting binary data or a vulnerability lattice.
Dark navy (#0a1628) background, electric cyan (#00d4ff) primary accent, amber (#ffb347)
secondary accent, soft white highlights. Minimalist tech aesthetic, generous negative space,
banner composition (centered subject, asymmetric depth). No text in the image.

Suggested generators: Midjourney v6+ with `--ar 1000:420 --style raw`, DALL-E 3, or Flux.
After generation, host on Cloudinary or GitHub raw and replace <COVER_IMAGE_URL> above.
-->

Every vuln management tool eventually needs to score a CVSS vector. Most of them either call out to NVD's API (slow, rate-limited, requires network egress from your scanner) or pull in a fat dependency that drags an old crypto library along for the ride.

I built [`@hailbytes/cvss-calc`](https://www.npmjs.com/package/@hailbytes/cvss-calc) because I wanted to score vectors inside a CI runner that didn't have internet access. It's a single, zero-dependency package that handles both CVSS v3.1 and v4.0.

## Score a vector in two lines

```ts
import { calculate } from '@hailbytes/cvss-calc';

const result = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
// { score: 9.8, severity: 'Critical', version: '3.1', vector: '...' }
```

v4.0 works the same way — the library parses the version from the vector string and dispatches to the right scorer. No flag, no branching at the call site:

```ts
const v4 = calculate('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
// { score: 10.0, severity: 'Critical', version: '4.0', vector: '...' }
```

## Or drop it into any page as a web component

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/@hailbytes/cvss-calc/dist/element.js"></script>

<hailbytes-cvss-calc vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"></hailbytes-cvss-calc>
```

The component renders a full interactive calculator. Listen for `cvss-calculated` events to read the score from JS.

## Where I'm using it

- A pre-deploy CI gate that fails the build if any new CVE in the SBOM scores ≥ 7.0
- A ticketing integration that auto-prioritizes Jira issues by severity
- A static status page where each disclosed CVE renders a live, interactive calculator

Scoring follows the official [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) and [v4.0](https://www.first.org/cvss/v4.0/specification-document) specs.

```bash
npm install @hailbytes/cvss-calc
```

Source and docs: [github.com/hailbytes/cvss-calc](https://github.com/hailbytes/cvss-calc) — MIT licensed.
