import { activeTargetContext, stableTargetKey, type TargetIdentity } from '../core/targetContext';
import { logger } from '../core/logger';
import type { OperationEntry } from '../core/operationJournal';

const STORAGE_KEY = 'lovelyres-incident-cases-v1';
const MAX_CASES = 30;
const MAX_IOCS = 500;
const MAX_EVIDENCE = 500;
const MAX_TIMELINE = 1000;
const MAX_PREVIEW_LENGTH = 4096;

export type IOCType = 'ip' | 'domain' | 'hash' | 'path' | 'process' | 'user' | 'other';
export type EvidenceKind = 'finding' | 'path' | 'command-output' | 'snapshot' | 'pcap' | 'log' | 'note' | 'other';
export type TimelineEventType = 'case-created' | 'finding' | 'evidence' | 'ioc' | 'action' | 'verification' | 'note';

export interface CaseIOC {
  id: string;
  type: IOCType;
  value: string;
  source: string;
  addedAt: number;
  target: TargetIdentity;
}

export interface EvidenceArtifact {
  id: string;
  kind: EvidenceKind;
  label: string;
  source: string;
  locator?: string;
  preview: string;
  sha256: string;
  hashScope: 'stored-preview' | 'external-artifact';
  collectedAt: number;
  target: TargetIdentity;
}

export interface CaseTimelineEvent {
  id: string;
  type: TimelineEventType;
  title: string;
  detail?: string;
  source: string;
  timestamp: number;
  target: TargetIdentity;
  evidenceId?: string;
  iocId?: string;
  operationId?: string;
}

export interface IncidentCase {
  id: string;
  title: string;
  status: 'open' | 'closed';
  targetKey: string;
  target: TargetIdentity;
  lastTarget: TargetIdentity;
  createdAt: number;
  updatedAt: number;
  iocs: CaseIOC[];
  evidence: EvidenceArtifact[];
  timeline: CaseTimelineEvent[];
}

interface CaseStore {
  version: 1;
  cases: IncidentCase[];
  activeCaseByTarget: Record<string, string>;
}

export interface AddEvidenceInput {
  kind: EvidenceKind;
  label: string;
  source: string;
  preview?: string;
  locator?: string;
  externalSha256?: string;
}

export interface AddFindingInput {
  title: string;
  description: string;
  severity: string;
  recommendation?: string;
  details?: unknown;
  source: string;
}

const log = logger.module('IncidentCase');

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function newId(prefix: string): string {
  const random = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${random}`;
}

function cleanText(value: unknown, maxLength: number): string {
  return String(value ?? '').trim().slice(0, maxLength);
}

function normalizeSha256(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/^sha256:/, '');
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    throw new Error('外部证据 SHA-256 必须是 64 位十六进制值');
  }
  return normalized;
}

async function sha256(value: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('当前运行环境不支持 WebCrypto，无法生成可信证据哈希');
  }
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

export { stableTargetKey } from '../core/targetContext';

function exactTarget(target: TargetIdentity): TargetIdentity {
  return {
    sessionId: target.sessionId,
    hostKeyFingerprint: target.hostKeyFingerprint,
    host: target.host,
    port: target.port,
    username: target.username,
  };
}

export class IncidentCaseManager {
  private loaded = false;
  private store: CaseStore = { version: 1, cases: [], activeCaseByTarget: {} };

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    if (typeof localStorage === 'undefined') return;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw) as Partial<CaseStore>;
      if (parsed.version === 1 && Array.isArray(parsed.cases)) {
        this.store = {
          version: 1,
          cases: parsed.cases.slice(0, MAX_CASES),
          activeCaseByTarget: parsed.activeCaseByTarget && typeof parsed.activeCaseByTarget === 'object'
            ? parsed.activeCaseByTarget
            : {},
        };
      }
    } catch (error) {
      log.warn('案件存储读取失败，将使用空案件库', error);
    }
  }

  private save(): void {
    if (typeof localStorage === 'undefined') return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.store));
    } catch (error) {
      log.error('案件存储写入失败', error);
      throw new Error('案件无法持久化，请检查本地存储空间');
    }
  }

  private requireTarget(): TargetIdentity {
    const target = activeTargetContext.get();
    if (!target) throw new Error('请先连接目标主机再操作案件');
    return exactTarget(target);
  }

  private requireActiveCase(): { incident: IncidentCase; target: TargetIdentity } {
    const target = this.requireTarget();
    const incident = this.ensureActiveCase();
    if (incident.targetKey !== stableTargetKey(target)) {
      throw new Error('案件目标与当前目标不一致');
    }
    const stored = this.store.cases.find(item => item.id === incident.id);
    if (!stored) throw new Error('案件不存在');
    stored.lastTarget = target;
    return { incident: stored, target };
  }

  ensureActiveCase(title?: string): IncidentCase {
    this.load();
    const target = this.requireTarget();
    const targetKey = stableTargetKey(target);
    const selectedId = this.store.activeCaseByTarget[targetKey];
    let incident = this.store.cases.find(item => item.id === selectedId && item.status === 'open');
    if (!incident) {
      const now = Date.now();
      incident = {
        id: newId('case'),
        title: cleanText(title, 160) || `应急案件 · ${target.username}@${target.host}`,
        status: 'open',
        targetKey,
        target,
        lastTarget: target,
        createdAt: now,
        updatedAt: now,
        iocs: [],
        evidence: [],
        timeline: [{
          id: newId('event'), type: 'case-created', title: '创建案件', source: 'case-workspace',
          timestamp: now, target,
        }],
      };
      this.store.cases.unshift(incident);
      this.store.cases = this.store.cases.slice(0, MAX_CASES);
      this.store.activeCaseByTarget[targetKey] = incident.id;
      this.save();
    }
    return clone(incident);
  }

  createCase(title?: string): IncidentCase {
    this.load();
    const target = this.requireTarget();
    delete this.store.activeCaseByTarget[stableTargetKey(target)];
    return this.ensureActiveCase(title);
  }

  getActiveCase(): IncidentCase | null {
    this.load();
    const target = activeTargetContext.get();
    if (!target) return null;
    const id = this.store.activeCaseByTarget[stableTargetKey(target)];
    const incident = this.store.cases.find(item => item.id === id && item.status === 'open');
    return incident ? clone(incident) : null;
  }

  getCasesForActiveTarget(): IncidentCase[] {
    this.load();
    const target = activeTargetContext.get();
    if (!target) return [];
    const key = stableTargetKey(target);
    return this.store.cases.filter(item => item.targetKey === key).map(clone);
  }

  selectCase(caseId: string): IncidentCase {
    this.load();
    const target = this.requireTarget();
    const targetKey = stableTargetKey(target);
    const incident = this.store.cases.find(item => item.id === caseId && item.targetKey === targetKey && item.status === 'open');
    if (!incident) throw new Error('只能打开当前目标的未结案件');
    incident.lastTarget = target;
    incident.updatedAt = Date.now();
    this.store.activeCaseByTarget[targetKey] = incident.id;
    this.save();
    return clone(incident);
  }

  addIOC(type: IOCType, value: string, source: string): CaseIOC {
    this.load();
    const { incident, target } = this.requireActiveCase();
    const cleanedValue = cleanText(value, 2048);
    if (!cleanedValue) throw new Error('IOC 值不能为空');
    const cleanedSource = cleanText(source, 160) || 'manual';
    const comparable = type === 'path' ? cleanedValue : cleanedValue.toLowerCase();
    const existing = incident.iocs.find(item => item.type === type
      && (type === 'path' ? item.value : item.value.toLowerCase()) === comparable);
    if (existing) return clone(existing);

    const now = Date.now();
    const ioc: CaseIOC = {
      id: newId('ioc'), type, value: cleanedValue, source: cleanedSource, addedAt: now, target,
    };
    incident.iocs.unshift(ioc);
    incident.iocs = incident.iocs.slice(0, MAX_IOCS);
    incident.timeline.unshift({
      id: newId('event'), type: 'ioc', title: `加入 IOC：${cleanedValue}`,
      source: cleanedSource, timestamp: now, target, iocId: ioc.id,
    });
    incident.timeline = incident.timeline.slice(0, MAX_TIMELINE);
    incident.updatedAt = now;
    this.save();
    return clone(ioc);
  }

  async addEvidence(input: AddEvidenceInput): Promise<EvidenceArtifact> {
    this.load();
    const { incident, target } = this.requireActiveCase();
    const label = cleanText(input.label, 256);
    if (!label) throw new Error('证据名称不能为空');
    const source = cleanText(input.source, 160) || 'manual';
    const locator = cleanText(input.locator, 2048) || undefined;
    const preview = cleanText(input.preview, MAX_PREVIEW_LENGTH);
    const hashScope = input.externalSha256 ? 'external-artifact' : 'stored-preview';
    const digest = input.externalSha256
      ? normalizeSha256(input.externalSha256)
      : await sha256(JSON.stringify({ kind: input.kind, label, source, locator, preview }));
    const duplicate = incident.evidence.find(item => item.kind === input.kind
      && item.sha256 === digest && item.hashScope === hashScope);
    if (duplicate) return clone(duplicate);

    const now = Date.now();
    const evidence: EvidenceArtifact = {
      id: newId('evidence'), kind: input.kind, label, source, locator, preview,
      sha256: digest, hashScope, collectedAt: now, target,
    };
    incident.evidence.unshift(evidence);
    incident.evidence = incident.evidence.slice(0, MAX_EVIDENCE);
    incident.timeline.unshift({
      id: newId('event'), type: input.kind === 'finding' ? 'finding' : 'evidence',
      title: `收集证据：${label}`, detail: locator, source, timestamp: now, target,
      evidenceId: evidence.id,
    });
    incident.timeline = incident.timeline.slice(0, MAX_TIMELINE);
    incident.updatedAt = now;
    this.save();
    return clone(evidence);
  }

  async addFinding(input: AddFindingInput): Promise<EvidenceArtifact> {
    let details = '';
    if (input.details !== undefined) {
      try { details = typeof input.details === 'string' ? input.details : JSON.stringify(input.details, null, 2); }
      catch { details = String(input.details); }
    }
    return this.addEvidence({
      kind: 'finding',
      label: `[${cleanText(input.severity, 32)}] ${cleanText(input.title, 220)}`,
      source: input.source,
      preview: [input.description, input.recommendation ? `建议：${input.recommendation}` : '', details]
        .filter(Boolean).join('\n\n'),
    });
  }

  async addNote(note: string): Promise<EvidenceArtifact> {
    const cleaned = cleanText(note, MAX_PREVIEW_LENGTH);
    if (!cleaned) throw new Error('笔记不能为空');
    const evidence = await this.addEvidence({
      kind: 'note', label: cleaned.slice(0, 60), source: 'case-workspace', preview: cleaned,
    });
    const incident = this.store.cases.find(item => item.id === this.getActiveCase()?.id);
    const event = incident?.timeline.find(item => item.evidenceId === evidence.id);
    if (event) event.type = 'note';
    this.save();
    return evidence;
  }

  /** 将当前可信目标已有的操作回执并入案件；不会接纳旧记录或其他目标的数据。 */
  syncOperationEntries(entries: OperationEntry[]): number {
    this.load();
    const target = activeTargetContext.get();
    const incident = this.getActiveCase();
    if (!target || !incident) return 0;
    const stored = this.store.cases.find(item => item.id === incident.id);
    if (!stored) return 0;

    let added = 0;
    for (const entry of entries) {
      if (!entry.target || stableTargetKey(entry.target) !== stableTargetKey(target)) continue;
      if (!stored.timeline.some(event => event.operationId === entry.id)) {
        stored.timeline.push({
          id: newId('event'), type: 'action',
          title: `${entry.success ? '处置成功' : '处置失败'}：${cleanText(entry.title, 240)}`,
          detail: cleanText(entry.command, 2048), source: `operation:${entry.source}`,
          timestamp: entry.timestamp, target: exactTarget(entry.target), operationId: entry.id,
        });
        added += 1;
      }
      const rollbackId = `${entry.id}:rollback`;
      if (entry.rolledBack && !stored.timeline.some(event => event.operationId === rollbackId)) {
        stored.timeline.push({
          id: newId('event'), type: 'action', title: `已回滚：${cleanText(entry.title, 240)}`,
          detail: cleanText(entry.restoreCommand, 2048), source: 'operation:rollback',
          timestamp: Date.now(), target: exactTarget(target), operationId: rollbackId,
        });
        added += 1;
      }
    }
    if (added > 0) {
      stored.timeline.sort((left, right) => right.timestamp - left.timestamp);
      stored.timeline = stored.timeline.slice(0, MAX_TIMELINE);
      stored.updatedAt = Date.now();
      this.save();
    }
    return added;
  }

  exportActiveCase(): string {
    const incident = this.getActiveCase();
    if (!incident) throw new Error('当前目标没有活动案件');
    return JSON.stringify({
      schema: 'lovelyres-incident-case/v1',
      exportedAt: new Date().toISOString(),
      manifest: {
        caseId: incident.id,
        targetKey: incident.targetKey,
        evidenceCount: incident.evidence.length,
        iocCount: incident.iocs.length,
        evidenceHashes: incident.evidence.map(item => ({
          id: item.id, sha256: item.sha256, hashScope: item.hashScope,
        })),
      },
      case: incident,
    }, null, 2);
  }

  /** 仅供测试或显式清空全部案件数据。 */
  clearAll(): void {
    this.loaded = true;
    this.store = { version: 1, cases: [], activeCaseByTarget: {} };
    this.save();
  }
}

export const incidentCaseManager = new IncidentCaseManager();
