import { incidentCaseManager, type IOCType } from './incidentCaseManager';

const HASH_PATTERN = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIpv6(value: string): boolean {
  return value.includes(':')
    && /^[a-f0-9:]+$/i.test(value)
    && value.split(':').length >= 3
    && value.length <= 45;
}

export function inferIOCType(value: string): IOCType {
  const cleaned = value.trim();
  if (HASH_PATTERN.test(cleaned)) return 'hash';
  if (isIpv4(cleaned) || isIpv6(cleaned)) return 'ip';
  if (cleaned.startsWith('/') || cleaned.startsWith('./') || cleaned.startsWith('../')) return 'path';
  if (DOMAIN_PATTERN.test(cleaned)) return 'domain';
  return 'other';
}

export function normalizeIOCValues(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const cleaned = String(value ?? '').trim().slice(0, 2048);
    if (!cleaned) continue;
    const key = inferIOCType(cleaned) === 'path' ? `path:${cleaned}` : cleaned.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(cleaned);
  }
  return result;
}

export function activeCaseIOCValues(): string[] {
  return incidentCaseManager.getActiveCase()?.iocs.map(item => item.value) ?? [];
}

export function mergeWithActiveCaseIOCs(values: Iterable<string>): string[] {
  return normalizeIOCValues([...values, ...activeCaseIOCValues()]);
}

export function persistIOCsToActiveCase(values: Iterable<string>, source: string): number {
  const normalized = normalizeIOCValues(values);
  const before = new Set(activeCaseIOCValues().map(value => {
    const type = inferIOCType(value);
    return type === 'path' ? `path:${value}` : value.toLowerCase();
  }));
  let added = 0;
  for (const value of normalized) {
    const type = inferIOCType(value);
    const key = type === 'path' ? `path:${value}` : value.toLowerCase();
    if (before.has(key)) continue;
    incidentCaseManager.addIOC(type, value, source);
    before.add(key);
    added += 1;
  }
  return added;
}
