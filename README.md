# VaultScrub

> **Zero-egress, 100% client-side PII & secret detection, redaction, and compliance-auditing workbench.**

VaultScrub scans text, logs, CSV/TSV, JSON, and PDF files for sensitive personal data and secrets — then redacts, masks, hashes, or tokenizes them **entirely inside your browser**. Nothing is ever uploaded or sent over the network.

---

## Features

| Capability | Description |
| --- | --- |
| **16 Detector Categories** | Private keys, API keys/secrets, Luhn-validated credit cards, Verhoeff-validated Aadhaar, Indian PAN, GSTIN, UPI ID, IFSC, US SSN, IBAN, JWT, URL credentials, emails, phones, IPv4, and IPv6. |
| **4 Redaction Modes** | Consistent pseudonym tokens (`[EMAIL_1]`), partial masking (`j***@domain.com`), deterministic FNV-1a hashes (`[EMAIL#...]`), and full removal (`[REDACTED]`). |
| **Multi-Format Input** | Auto-detects plain text, RFC-4180 CSV/TSV, JSON arrays/objects, and locally extracts PDF text via bundled `pdfjs-dist` worker — zero CDN calls. |
| **Interactive Table View** | Per-column redact/keep toggles and per-cell whitelisting for structured datasets. |
| **Encrypted Key Vault** | AES-GCM-256 + PBKDF2-SHA256 (250 000 iterations) encrypted `.vault.json` export of pseudonym mappings for safe LLM prompting. |
| **AI Re-hydration** | Paste an AI response containing `[EMAIL_1]`, `[PAN_1]` etc., upload the `.vault.json` key + passphrase, and restore original values locally. |
| **Risk Scoring** | Diminishing-returns `0–100` exposure score (`none` → `critical`) with per-severity breakdown and explanations. |
| **Column Classification** | Header-hinted + content-scanned per-column risk levels and recommended actions for CSV/JSON data. |
| **Audit Certificates** | SHA-256-stamped JSON/PDF compliance certificates with tamper-evident integrity hashes (raw PII omitted). |
| **Sanitized PDF Export** | Generate clean, multi-page PDF documents from scrubbed output via `jsPDF`. |
| **Offline PWA** | Service Worker pre-caches all assets; works fully offline after the first load. |
| **Zero-Trust Proof** | Strict CSP (`connect-src 'self'`), live `0 Bytes Sent` privacy panel, online/offline status, and verifiable proof modal. |
| **Theme Switcher** | Auto / Light / Dark themes persisted in `localStorage`. |

---

## Architecture

```
index.html          Landing page (3D Fibonacci sphere, lightbox, intro)
├── landing.css      Landing styles
├── landing.js       Sphere renderer, drag, scroll, grid, lightbox, menu

workbench.html      Full scrubbing workbench
├── styles.css       Workbench styles (design-token-driven, no hardcoded colors)
├── app.js           State orchestrator, render functions, event wiring
├── motion.js        Kinetic micro-interactions (spotlight, counters, toasts)
│
├── detectors.js     16-category regex + validation detection engine
├── verhoeff.js      Verhoeff checksum for Aadhaar validation
├── redact.js        4-mode redaction with diff segments and mapping registry
├── classify.js      Risk scoring and per-column classification
├── report.js        Structured audit report builder and serializers
├── csvParser.js     RFC-4180 CSV/TSV parser and serializer
├── cryptoVault.js   AES-GCM + PBKDF2 encrypted vault and re-hydration
├── auditReport.js   SHA-256 audit certificate generator
├── pdfExtractor.js  Client-side PDF text extraction and PDF generation
│
├── public/
│   ├── manifest.json   PWA manifest
│   ├── sw.js            Service Worker (dev; Vite generates production version)
│   ├── icon.svg         App icon
│   ├── fonts/           Bundled web fonts (Playfair, Inter, Archivo, Onest)
│   └── cards/           Landing page card assets (SVG frames, photos)
│
├── samples/            Sample input files for testing
│   ├── sample-customers.csv
│   ├── sample-incident.txt
│   └── sample-resume.pdf
│
└── tests/
    ├── architecture.test.js   Structural and integration tests
    └── logic.test.js          Pure-logic unit tests (16 tests)
```

### Design Principles

- **Pure logic / zero DOM coupling** — Detection, redaction, classification, CSV parsing, crypto vault, and report modules have zero `document`, `window`, `fetch`, or `navigator` references. This is enforced by the architecture test suite.
- **Single state object** — The workbench renders from one immutable state snapshot via six focused render functions (`renderInput`, `renderDiff`, `renderCounts`, `renderRisk`, `renderColumns`, `renderPrivacy`).
- **Design-token-driven CSS** — All colors, radii, shadows, spacing, and durations are defined as CSS custom properties in `:root`. No hardcoded color values appear outside `:root`, enforced by test.
- **No inline styles** — Zero `style=` attributes or `.style.` mutations in HTML or JS, enforced by test.
- **Stable selectors** — All DOM queries use `data-testid` attributes, ensuring test and UI decoupling.

---

## Getting Started

### Prerequisites

- **Node.js** ≥ 18.0.0
- **npm** ≥ 9.0.0

### Installation

```bash
git clone https://github.com/Pratham2112008/VaultScrub.git
cd VaultScrub
npm install
```

### Development

```bash
npm run dev        # Start Vite dev server with HMR
```

### Production Build

```bash
npm run build      # Output to dist/
npm run preview    # Preview the production build locally
```

### Testing

```bash
npm test           # Run all tests (Node.js built-in test runner)
```

All 16 tests must pass:

```
✔ pure logic modules have zero DOM or network API references
✔ styles.css keeps all color values inside :root design tokens
✔ no inline styles appear in index.html, workbench.html, app.js, or motion.js
✔ every stable data-testid selector used by app.js exists in workbench.html
✔ the six render functions populate the DOM cleanly from a single state object
✔ detectSensitiveData detects core PII and secret types with accurate positions
✔ credit card Luhn validation rejects invalid sequences and accepts valid cards
✔ category filtering disables specific detectors cleanly
✔ redactText supports token, mask, hash, and remove modes with consistent tokens
✔ detectStructuredFormat parses CSV and JSON arrays and classifyColumns evaluates risk
✔ classifyRisk and buildReport produce safe audit summaries without leaking raw secrets
✔ Verhoeff algorithm validates genuine Aadhaar numbers and rejects random 12-digit numbers
✔ Indian PII detectors match Aadhaar, PAN, UPI ID, GSTIN, IFSC, and +91 phone
✔ RFC-4180 CSV parser handles quoted commas and selective whitelisting
✔ AES-GCM + PBKDF2 encrypted key vault round-trips and re-hydrates AI responses
✔ Audit Certificate computes real SHA-256 hashes and omits raw PII
```

---

## Deployment

### Netlify (Recommended)

1. Connect your GitHub repository on [app.netlify.com](https://app.netlify.com).
2. Set **Build command**: `npm run build`
3. Set **Publish directory**: `dist`
4. Deploy.

### Manual

Run `npm run build` and serve the `dist/` directory with any static file server.

---

## Security Model

| Layer | Implementation |
| --- | --- |
| **Network isolation** | Strict CSP: `default-src 'self'; connect-src 'self'` — blocks all external requests. |
| **Encryption** | AES-GCM-256 + PBKDF2-SHA256 (250 000 iterations) via Web Crypto API (`crypto.subtle`). |
| **Integrity** | Real SHA-256 digests of raw and sanitized content in audit certificates. |
| **Storage** | Memory-only processing; theme preference is the only `localStorage` item. |
| **Offline** | Service Worker pre-caches all assets for full offline operation. |

---

## Technology Stack

| Tool | Purpose |
| --- | --- |
| [Vite](https://vite.dev) | Build tool and dev server |
| [pdfjs-dist](https://github.com/nicbarker/pdfjs-dist) | Client-side PDF text extraction (bundled worker) |
| [jsPDF](https://github.com/parallax/jsPDF) | Client-side PDF generation |
| [Node.js Test Runner](https://nodejs.org/api/test.html) | Native test framework (zero test dependencies) |

---

## License

[MIT](./LICENSE)
