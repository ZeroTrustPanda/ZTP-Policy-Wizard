/**
 * Audit Logger - Records all API actions and template operations
 * Stores logs on the local filesystem for compliance
 */

const fs = require('fs');
const path = require('path');
const { randomUUID: uuidv4 } = require('crypto'); // built-in (no uuid package)

const { LOG_DIR } = require('./paths');

class AuditLogger {
  constructor() {
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }
    this.sessionId = uuidv4();
    this.entries = [];
    this.listeners = new Set();   // v2.2: live progress subscribers (GET /api/v2/events)
  }

  /** Live progress: fn(event) for every entry from now on. Returns an unsubscribe function. */
  subscribe(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  emit(event) { for (const fn of this.listeners) { try { fn(event); } catch (e) { /* subscriber gone */ } } }

  log(action, details, status = 'success') {
    const entry = {
      id: uuidv4(),
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      action,
      details,
      status
    };
    this.entries.push(entry);
    this._appendToFile(entry);
    if (this.listeners.size) this.emit({ at: entry.timestamp, action, status, ...AuditLogger.brief(action, details) });
    return entry;
  }

  /** The parts of an entry that are safe and useful to show live (never request bodies). */
  static brief(action, d = {}) {
    if (action === 'POLICY_APPLIED') return { category: d.policyType, name: d.ruleName, result: d.action, error: d.result && d.result.error ? String(d.result.error).slice(0, 300) : undefined };
    if (action === 'RATE_LIMIT') return { product: d.product, until: d.until, message: d.message };
    if (action === 'PROGRESS') return { product: d.product, message: d.message };
    if (/_APPLY$/.test(action)) return { category: d.category, name: d.name, result: d.action, error: d.error ? String(d.error).slice(0, 300) : undefined };
    return {};
  }

  logApiCall(method, endpoint, requestBody, responseStatus, responseBody) {
    return this.log('API_CALL', {
      method,
      endpoint,
      requestBody: this._sanitize(requestBody),
      responseStatus,
      responseBody: this._truncate(responseBody)
    }, responseStatus >= 200 && responseStatus < 300 ? 'success' : 'error');
  }

  logTemplateGeneration(templateConfig, templateResult) {
    return this.log('TEMPLATE_GENERATED', {
      tier: templateConfig.tier,
      complianceFramework: templateConfig.complianceFramework,
      prefix: templateConfig.prefix,
      policyCounts: {
        urlFiltering: templateResult.policies.urlFiltering?.length || 0,
        firewallFiltering: templateResult.policies.firewallFiltering?.length || 0,
        sslInspection: templateResult.policies.sslInspection?.length || 0
      }
    });
  }

  logPolicyApply(policyType, ruleName, action, result) {
    return this.log('POLICY_APPLIED', {
      policyType,
      ruleName,
      action,
      result: this._truncate(result)
    }, result.error ? 'error' : 'success');
  }

  logAuthentication(authMode, cloud, success) {
    return this.log('AUTHENTICATION', {
      authMode,
      cloud,
      success
    }, success ? 'success' : 'error');
  }

  logRollback(snapshotId, result) {
    return this.log('ROLLBACK', { snapshotId, result });
  }

  getEntries() {
    return this.entries;
  }

  getSessionId() {
    return this.sessionId;
  }

  exportToCSV() {
    const headers = ['Timestamp', 'Session ID', 'Action', 'Status', 'Details'];
    const rows = this.entries.map(e => [
      e.timestamp,
      e.sessionId,
      e.action,
      e.status,
      JSON.stringify(e.details).replace(/"/g, '""')
    ]);
    return [headers.join(','), ...rows.map(r => r.map(c => `"${c}"`).join(','))].join('\n');
  }

  _sanitize(obj) {
    if (!obj) return obj;
    const sanitized = { ...obj };
    const sensitiveKeys = ['password', 'apiKey', 'clientSecret', 'accessToken', 'sessionCookie'];
    for (const key of sensitiveKeys) {
      if (sanitized[key]) sanitized[key] = '***REDACTED***';
    }
    return sanitized;
  }

  _truncate(obj, maxLen = 500) {
    if (!obj) return obj;
    const str = typeof obj === 'string' ? obj : JSON.stringify(obj);
    return str.length > maxLen ? str.substring(0, maxLen) + '...[truncated]' : obj;
  }

  _appendToFile(entry) {
    const dateStr = new Date().toISOString().split('T')[0];
    const logFile = path.join(LOG_DIR, `ztp-audit-${dateStr}.jsonl`);
    try {
      fs.appendFileSync(logFile, JSON.stringify(entry) + '\n');
    } catch (e) {
      console.error('Failed to write audit log:', e.message);
    }
  }
}

module.exports = { AuditLogger };
