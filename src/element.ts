import { calculate } from './index.js';
import type { CvssResult, Severity } from './scorer.js';

const SEVERITY_COLORS: Record<Severity, string> = {
  None:     '#6b7280',
  Low:      '#3b82f6',
  Medium:   '#f59e0b',
  High:     '#f97316',
  Critical: '#ef4444',
};

const STYLES = `
:host { display: block; font-family: system-ui, -apple-system, sans-serif; }
.container { background: #1a1a2e; border: 1px solid #2d2d4e; border-radius: 12px; padding: 24px; max-width: 600px; color: #e2e8f0; }
.input-row { display: flex; gap: 8px; margin-bottom: 20px; }
input { flex: 1; padding: 10px 14px; background: #0f0f23; border: 1px solid #3d3d5e; border-radius: 8px; color: #e2e8f0; font-size: 13px; font-family: monospace; }
input:focus { outline: 2px solid #6366f1; }
button { padding: 10px 16px; background: #6366f1; color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; }
button:hover { background: #4f46e5; }
.score-wrap { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }
.score-num { font-size: 56px; font-weight: 700; line-height: 1; }
.badge { padding: 6px 16px; border-radius: 20px; font-weight: 600; font-size: 16px; color: white; }
.ver { font-size: 12px; color: #94a3b8; margin-bottom: 4px; }
.vector { font-family: monospace; font-size: 12px; color: #94a3b8; word-break: break-all; background: #0f0f23; padding: 8px 12px; border-radius: 6px; margin-bottom: 16px; }
.err { color: #f87171; font-size: 13px; padding: 8px 12px; background: rgba(239,68,68,0.1); border-radius: 6px; border: 1px solid rgba(239,68,68,0.3); }
.brand { margin-top: 16px; text-align: right; font-size: 11px; color: #4a5568; }
.brand a { color: #6366f1; text-decoration: none; }
`;

export class HailbytesCvssCalc extends HTMLElement {
  private _shadow: ShadowRoot;
  static get observedAttributes() { return ['vector', 'branding']; }

  constructor() {
    super();
    this._shadow = this.attachShadow({ mode: 'open' });
    this._render('');
  }

  connectedCallback() {
    const v = this.getAttribute('vector');
    if (v) this._render(v);
  }

  attributeChangedCallback(name: string, _old: string | null, newVal: string | null) {
    if (name === 'vector') this._render(newVal ?? '');
  }

  private _render(initial: string) {
    const hideBrand = this.getAttribute('branding') === 'off';
    this._shadow.innerHTML = `<style>${STYLES}</style>
<div class="container">
  <div class="input-row">
    <input type="text" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" value="${initial}" />
    <button>Score</button>
  </div>
  <div class="result"></div>
  <div class="brand"${hideBrand ? ' style="display:none"' : ''}>by <a href="https://hailbytes.com" target="_blank" rel="noopener">HailBytes</a></div>
</div>`;

    const input = this._shadow.querySelector('input') as HTMLInputElement;
    const btn   = this._shadow.querySelector('button') as HTMLButtonElement;
    const out   = this._shadow.querySelector('.result') as HTMLDivElement;

    const run = () => {
      const v = input.value.trim();
      if (!v) return;
      try {
        const r = calculate(v);
        this._showResult(out, r);
        this.dispatchEvent(new CustomEvent('cvss-calculated', { detail: r, bubbles: true, composed: true }));
      } catch (e) {
        out.innerHTML = `<div class="err">${(e as Error).message}</div>`;
      }
    };

    btn.addEventListener('click', run);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    if (initial) { try { this._showResult(out, calculate(initial)); } catch { /**/ } }
  }

  private _showResult(container: HTMLElement, r: CvssResult) {
    const color = SEVERITY_COLORS[r.severity];
    container.innerHTML = `
<div class="score-wrap">
  <div class="score-num" style="color:${color}">${r.score.toFixed(1)}</div>
  <div><div class="ver">CVSS ${r.version}</div><div class="badge" style="background:${color}">${r.severity}</div></div>
</div>
<div class="vector">${r.vector}</div>`;
  }
}

if (typeof customElements !== 'undefined' && !customElements.get('hailbytes-cvss-calc')) {
  customElements.define('hailbytes-cvss-calc', HailbytesCvssCalc);
}
