import { describe, it, expect } from 'vitest';
import { calculate } from '../src/index.js';
import { parseVector } from '../src/parser.js';

describe('CVSS v3.1 scoring', () => {
  it('scores a critical vector 9.8', () => {
    const r = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(r.score).toBe(9.8);
    expect(r.severity).toBe('Critical');
    expect(r.version).toBe('3.1');
  });

  it('scores scope-changed critical as 10.0', () => {
    const r = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    expect(r.score).toBe(10.0);
    expect(r.severity).toBe('Critical');
  });

  it('scores a high vector 8.8', () => {
    const r = calculate('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H');
    expect(r.score).toBe(8.8);
    expect(r.severity).toBe('High');
  });

  it('scores a medium vector 5.4', () => {
    const r = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N');
    expect(r.score).toBe(5.4);
    expect(r.severity).toBe('Medium');
  });

  it('scores zero-impact vector as 0 / None', () => {
    const r = calculate('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N');
    expect(r.score).toBe(0);
    expect(r.severity).toBe('None');
  });

  it('returns the normalised vector string', () => {
    const r = calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(r.vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });
});

describe('parseVector error cases', () => {
  it('throws on invalid metric value', () => {
    expect(() => calculate('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow();
  });
  it('throws on missing metric', () => {
    expect(() => calculate('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toThrow();
  });
  it('throws on unsupported version', () => {
    expect(() => calculate('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P')).toThrow();
  });
  it('throws on empty string', () => {
    expect(() => calculate('')).toThrow();
  });
});

describe('CVSS v4.0 scoring', () => {
  it('scores a critical v4.0 vector', () => {
    const r = calculate('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(r.score).toBeGreaterThanOrEqual(9.0);
    expect(r.severity).toBe('Critical');
    expect(r.version).toBe('4.0');
  });
  it('throws on missing v4.0 metric', () => {
    expect(() => calculate('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N')).toThrow();
  });
});

describe('parseVector', () => {
  it('returns correct version for v3.1', () => {
    expect(parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').version).toBe('3.1');
  });
  it('returns correct version for v4.0', () => {
    expect(parseVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').version).toBe('4.0');
  });
});
