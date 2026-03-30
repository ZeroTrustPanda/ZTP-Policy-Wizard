/**
 * Audit Logger - Records all API actions and template operations
 * Stores logs on the local filesystem for compliance
 */

const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const LOG_DIR = path.join(__dirname, '..', 'logs');

class AuditLogger {
  constructor() {
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }
    this.sessionId = uuidv4();
    this.entries = [];
  }

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
    return entry;
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
