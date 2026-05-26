import {
  STORE_TTL_MS, STORE_CLEANUP_INTERVAL_MS, MAX_STORE_ENTRIES,
  MAX_IDENTITY_VALUES_PER_KEY, MAX_IDENTITY_SEARCH_RESULTS,
  DEFAULT_DLP_TAINT, DLP_TAINT_DECAY_MS,
  DLP_TAINT_RANK, EGRESS_TOOLS,
} from './constants.js';
import { classifyPath, scanContent } from './classify.js';

export const VISITOR_STORE = new Map();
export const SESSION_STORE = new Map();

export function getSessionProfile(sessionId, visitorId) {
  if (SESSION_STORE.size >= MAX_STORE_ENTRIES) {
    const oldest = SESSION_STORE.entries().next().value;
    if (oldest) SESSION_STORE.delete(oldest[0]);
  }
  if (!SESSION_STORE.has(sessionId)) {
    let baseRisk = 0;
    if (visitorId) {
      const visitor = getVisitorProfile(visitorId);
      baseRisk = visitor.risk * 0.3;
    }
    SESSION_STORE.set(sessionId, {
      id: sessionId, created: Date.now(), lastActive: Date.now(),
      visitorId: visitorId || null,
      risk: baseRisk, stepCount: 0, phase: 'exploration', locked: false,
      tags: [], blockedCount: 0, lastTool: null,
      policyRisk: 0, semanticRisk: 0, behaviorRisk: 0,
      dataTaint: 0, dataTaintTime: 0,
    });
  }
  return SESSION_STORE.get(sessionId);
}

export function getVisitorProfile(visitorId) {
  if (VISITOR_STORE.size >= MAX_STORE_ENTRIES) {
    const oldest = VISITOR_STORE.entries().next().value;
    if (oldest) VISITOR_STORE.delete(oldest[0]);
  }
  if (!VISITOR_STORE.has(visitorId)) {
    VISITOR_STORE.set(visitorId, {
      id: visitorId, firstSeen: Date.now(), lastSeen: Date.now(),
      risk: 0, sessionCount: 0, blockedCount: 0, tags: [], identities: {},
    });
  }
  return VISITOR_STORE.get(visitorId);
}

export function recordIdentity(visitorId, attrs) {
  const visitor = getVisitorProfile(visitorId);
  for (const key of Object.keys(attrs)) {
    if (attrs[key] == null) continue;
    if (!visitor.identities[key]) visitor.identities[key] = [];
    if (visitor.identities[key].length >= MAX_IDENTITY_VALUES_PER_KEY) continue;
    if (!visitor.identities[key].includes(attrs[key])) {
      visitor.identities[key].push(attrs[key]);
    }
  }
}

export function searchIdentities(query) {
  if (!query) return [];
  const q = query.toLowerCase();
  const results = [];
  VISITOR_STORE.forEach(function (v) {
    for (const key of Object.keys(v.identities)) {
      for (const val of v.identities[key]) {
        if (String(val).toLowerCase().includes(q)) {
          results.push({ visitorId: v.id, key, value: val, risk: v.risk });
          return;
        }
      }
    }
  });
  return results.slice(0, MAX_IDENTITY_SEARCH_RESULTS);
}

export function cleanupStores() {
  const now = Date.now();
  SESSION_STORE.forEach(function (s, sid) {
    if (now - s.lastActive > STORE_TTL_MS) SESSION_STORE.delete(sid);
  });
  VISITOR_STORE.forEach(function (v, vid) {
    if (now - v.lastSeen > STORE_TTL_MS) VISITOR_STORE.delete(vid);
  });
}

const cleanupTimer = setInterval(cleanupStores, STORE_CLEANUP_INTERVAL_MS);
if (cleanupTimer.unref) cleanupTimer.unref();

export function checkDLP(profile, request, resourcePath, content) {
  if (profile.dataTaint === undefined) profile.dataTaint = DEFAULT_DLP_TAINT;
  if (profile.dataTaintTime === undefined) profile.dataTaintTime = 0;

  if (profile.dataTaintTime > 0 && Date.now() - profile.dataTaintTime > DLP_TAINT_DECAY_MS) {
    profile.dataTaint = 0;
  }

  let dlpLevel = 0;
  if (resourcePath) {
    const dl = classifyPath(resourcePath);
    dlpLevel = DLP_TAINT_RANK[dl] || 0;
  }
  if (content) {
    const cl = scanContent(content);
    const clN = DLP_TAINT_RANK[cl] || 0;
    if (clN > dlpLevel) dlpLevel = clN;
  }
  if (dlpLevel > profile.dataTaint) profile.dataTaint = dlpLevel;
  if (dlpLevel > 0) profile.dataTaintTime = Date.now();

  const isEgress = EGRESS_TOOLS.some(t => request.tool && request.tool.includes(t));
  if (isEgress && profile.dataTaint > 0) {
    const taintLabel = ['', 'P2', 'P1', 'P0'][profile.dataTaint];
    return { blocked: true, reason: 'dlp_egress_' + taintLabel, layer: 'DLP' };
  }
  return { blocked: false };
}
