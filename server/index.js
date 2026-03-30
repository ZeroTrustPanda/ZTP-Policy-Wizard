/**
 * ZTP Policy Wizard - Express Server
 * 
 * Serves the web UI and provides REST API endpoints for:
 * - Authentication (OneAPI OAuth2)
 * - Template generation and customization
 * - Dry run / plan / apply / rollback
 * - Audit logging and export
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const { ZIAClient, ZIA_CLOUDS } = require('./zia-client');
const { ZCCClient } = require('./zcc-client');
const { generateFullTemplate, COMPLIANCE_FRAMEWORKS } = require('./templates');
const { generateZCCTemplate } = require('./zcc-templates');
const { AuditLogger } = require('./audit-logger');

const app = express();
const APP_VERSION = '1.5.2';
const PORT = process.env.ZTP_PORT || 3000;
const HOST = process.env.ZTP_HOST || '0.0.0.0';
const SESSION_TTL_MS = 60 * 60 * 1000;   // 1 hour
const MAX_SESSIONS = 50;                  // Max concurrent sessions

// In-memory session store (per-session, never persisted)
const sessions = new Map();

// Session cleanup: remove expired sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      try { session.client.logout(); } catch(e) { /* ignore */ }
      sessions.delete(id);
      cleaned++;
    }
  }
  if (cleaned > 0) console.log(`[SESSION] Cleaned ${cleaned} expired sessions. Active: ${sessions.size}`);
}, 5 * 60 * 1000);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ========================
// Request Logging Middleware
// ========================
// This logs EVERY incoming request to the Node.js console (stdout)
// and to a dedicated HTTP log file in ./logs/
const HTTP_LOG_DIR = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(HTTP_LOG_DIR)) fs.mkdirSync(HTTP_LOG_DIR, { recursive: true });

app.use((req, res, next) => {
  const start = Date.now();
  const timestamp = new Date().toISOString();

  // Log when response finishes
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLine = `[${timestamp}] ${req.method} ${req.originalUrl} → ${res.statusCode} (${duration}ms) from=${req.ip}`;
    
    // Console output (visible in terminal / service logs)
    console.log(logLine);

    // File output
    const dateStr = timestamp.split('T')[0];
    const logFile = path.join(HTTP_LOG_DIR, `ztp-http-${dateStr}.log`);
    try {
      fs.appendFileSync(logFile, logLine + '\n');
    } catch (e) { /* ignore write errors */ }
  });

  next();
});

// JSON parse error handler — catches malformed request bodies
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    console.error(`[JSON_PARSE_ERROR] ${req.method} ${req.originalUrl}: ${err.message}`);
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  next(err);
});

app.use(express.static(path.join(__dirname, '..', 'public')));

// ========================
// Version endpoint (no auth required)
// ========================
app.get('/api/version', (req, res) => {
  res.json({
    version: APP_VERSION,
    name: 'ZTP Policy Wizard',
    build: '2026-03-30',
    activeSessions: sessions.size,
    maxSessions: MAX_SESSIONS,
    sessionTTL: SESSION_TTL_MS / 1000 + 's'
  });
});

// ========================
// Middleware
// ========================

function getSession(req) {
  const sessionId = req.headers['x-session-id'];
  if (!sessionId || !sessions.has(sessionId)) return null;
  return sessions.get(sessionId);
}

function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session || !session.client || !session.client.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated. Please connect to ZIA first.' });
  }
  // Touch session — extend TTL on activity
  session.lastActivity = Date.now();
  req.session = session;
  next();
}

// ========================
// Authentication Routes
// ========================

// Legacy API auth removed in v1.3.0 — OneAPI (OAuth2) is the standard going forward

app.post('/api/auth/oneapi', async (req, res) => {
  try {
    const { clientId, clientSecret, vanityDomain, cloud } = req.body;

    if (!clientId || !clientSecret || !vanityDomain) {
      return res.status(400).json({ error: 'Missing required fields: clientId, clientSecret, vanityDomain' });
    }

    console.log(`[AUTH] OneAPI auth attempt: vanity=${vanityDomain}, cloud=${cloud || 'production'}`);

    const client = new ZIAClient();
    const logger = new AuditLogger();

    const result = await client.authenticateOneAPI({ clientId, clientSecret, vanityDomain, cloud });

    // Create ZCC client sharing the same token — routes through api.zsapi.net/zcc/
    const zccClient = new ZCCClient(client);

    // Enforce max concurrent sessions
    if (sessions.size >= MAX_SESSIONS) {
      // Evict oldest session
      let oldestId = null, oldestTime = Infinity;
      for (const [id, s] of sessions) {
        if (s.createdAt < oldestTime) { oldestTime = s.createdAt; oldestId = id; }
      }
      if (oldestId) {
        try { sessions.get(oldestId).client.logout(); } catch(e) {}
        sessions.delete(oldestId);
        console.log(`[SESSION] Evicted oldest session to make room. Active: ${sessions.size}`);
      }
    }

    const sessionId = uuidv4();
    sessions.set(sessionId, {
      client,
      zccClient,
      logger,
      snapshots: {},
      appliedChanges: [],
      template: null,
      createdAt: Date.now(),
      lastActivity: Date.now()
    });

    logger.logAuthentication('oneapi', cloud || 'production', true);
    console.log(`[AUTH] OneAPI auth SUCCESS: vanity=${vanityDomain}`);

    res.json({
      success: true,
      sessionId,
      expiresIn: result.expiresIn,
      message: 'Successfully authenticated via OneAPI OAuth2'
    });
  } catch (error) {
    console.error(`[AUTH] OneAPI auth FAILED: ${error.message}`);
    if (error.code) console.error(`[AUTH]   Error code: ${error.code}`);
    res.status(401).json({ error: error.message });
  }
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await req.session.client.logout();
    const sessionId = req.headers['x-session-id'];
    sessions.delete(sessionId);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/status', (req, res) => {
  const session = getSession(req);
  if (session && session.client.isAuthenticated()) {
    res.json({
      authenticated: true,
      authMode: session.client.authMode,
      cloud: session.client.cloud
    });
  } else {
    res.json({ authenticated: false });
  }
});

// ========================
// Template Routes
// ========================

app.get('/api/templates/frameworks', (req, res) => {
  res.json(COMPLIANCE_FRAMEWORKS);
});

app.get('/api/templates/clouds', (req, res) => {
  res.json(ZIA_CLOUDS);
});

app.post('/api/templates/generate', (req, res) => {
  try {
    const config = req.body;

    // Validate tier
    if (!['STRICT', 'BALANCED', 'PERMISSIVE', 'ZTH_EBOOK'].includes(config.tier)) {
      return res.status(400).json({ error: 'Invalid tier. Must be STRICT, BALANCED, PERMISSIVE, or ZTH_EBOOK' });
    }

    // Validate framework if provided
    if (config.complianceFramework && !COMPLIANCE_FRAMEWORKS[config.complianceFramework]) {
      return res.status(400).json({ error: `Invalid compliance framework: ${config.complianceFramework}` });
    }

    // Validate prefix
    if (config.prefix && !/^[A-Za-z0-9_-]+$/.test(config.prefix)) {
      return res.status(400).json({ error: 'Prefix must contain only letters, numbers, hyphens, and underscores' });
    }

    const template = generateFullTemplate(config);

    // Store in session if authenticated
    const session = getSession(req);
    if (session) {
      session.template = template;
      session.logger.logTemplateGeneration(config, template);
    }

    res.json(template);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Policy Catalog (no auth required — read-only reference)
// ========================

app.get('/api/catalog', (req, res) => {
  try {
    const tiers = ['STRICT', 'BALANCED', 'PERMISSIVE', 'ZTH_EBOOK'];
    const frameworks = [null, 'HIPAA', 'HITRUST', 'NIST_800_53', 'NIST_800_171', 'PCI', 'CJIS', 'SOX', 'FERPA', 'GDPR'];

    const catalog = {
      generatedAt: new Date().toISOString(),
      version: APP_VERSION,
      tiers: {},
      frameworks: COMPLIANCE_FRAMEWORKS
    };

    for (const tier of tiers) {
      catalog.tiers[tier] = {};
      const fwList = tier === 'ZTH_EBOOK' ? [null, 'HIPAA'] : frameworks;
      for (const fw of fwList) {
        const template = generateFullTemplate({
          tier, complianceFramework: fw, prefix: 'ZTP',
          enableUrlFiltering: true, enableFirewall: true, enableSslInspection: true,
          enableMalwareProtection: true, enableAdvancedSettings: true, enableSandbox: true,
          enableDnsSecurity: true, enableFileTypeControl: true, enableCloudAppControl: true,
          enableDlp: true
        });

        const fwKey = fw || 'NONE';
        const summary = {};
        for (const [policyType, rules] of Object.entries(template.policies)) {
          if (Array.isArray(rules)) {
            summary[policyType] = rules.map(r => ({
              name: r.name,
              action: r.action || r.baRuleAction || r.filteringAction || '—',
              state: r.state || '—',
              description: r.description || '',
              complianceMapping: r.complianceMapping || [],
              // Type-specific fields
              ...(r.urlCategories ? { urlCategories: r.urlCategories } : {}),
              ...(r.protocols ? { protocols: r.protocols } : {}),
              ...(r.severity ? { severity: r.severity } : {}),
              ...(r.dictionaryNames ? { dictionaryNames: r.dictionaryNames } : {}),
              ...(r.preferredEngineNames?.length ? { preferredEngines: r.preferredEngineNames } : {}),
              ...(r.fileTypes ? { fileTypes: r.fileTypes } : {}),
              ...(r.nwApplications ? { nwApplications: r.nwApplications } : {}),
              ...(r.firstTimeOperation ? { firstTimeOperation: r.firstTimeOperation } : {}),
              ...(r.withoutContentInspection ? { withoutContentInspection: true } : {}),
              ...(r.tier ? { tier: r.tier } : {})
            }));
          } else if (rules && typeof rules === 'object') {
            // Settings objects (malware, advanced)
            summary[policyType] = {
              name: rules.name,
              description: rules.description || '',
              settings: rules.settings || {},
              complianceMapping: rules.complianceMapping || []
            };
          }
        }
        catalog.tiers[tier][fwKey] = {
          metadata: template.metadata,
          ruleCounts: Object.fromEntries(
            Object.entries(template.policies).map(([k, v]) => [k, Array.isArray(v) ? v.length : 1])
          ),
          policies: summary,
          checklist: template.implementationChecklist
        };
      }
    }

    res.json(catalog);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Single tier+framework preview (lighter than full catalog)
app.get('/api/catalog/:tier', (req, res) => {
  try {
    const tier = req.params.tier.toUpperCase();
    if (!['STRICT', 'BALANCED', 'PERMISSIVE', 'ZTH_EBOOK'].includes(tier)) {
      return res.status(400).json({ error: 'Invalid tier' });
    }
    const fw = req.query.framework || null;
    if (fw && !COMPLIANCE_FRAMEWORKS[fw]) {
      return res.status(400).json({ error: 'Invalid framework' });
    }

    const template = generateFullTemplate({
      tier, complianceFramework: fw, prefix: 'ZTP',
      enableUrlFiltering: true, enableFirewall: true, enableSslInspection: true,
      enableMalwareProtection: true, enableAdvancedSettings: true, enableSandbox: true,
      enableDnsSecurity: true, enableFileTypeControl: true, enableCloudAppControl: true,
      enableDlp: true
    });

    res.json(template);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Plan / Dry Run Routes
// ========================

app.post('/api/plan/dryrun', requireAuth, async (req, res) => {
  try {
    const { template } = req.body;
    if (!template) {
      return res.status(400).json({ error: 'No template provided' });
    }

    const { client, logger } = req.session;
    const plan = { actions: [], warnings: [], errors: [] };

    // Fetch current state
    let currentUrlRules = [];
    let currentFwRules = [];
    let currentSslRules = [];

    try {
      currentUrlRules = await client.getUrlFilteringRules() || [];
    } catch (e) {
      plan.warnings.push(`Could not fetch current URL filtering rules: ${e.message}`);
    }

    try {
      currentFwRules = await client.getFirewallRules() || [];
    } catch (e) {
      plan.warnings.push(`Could not fetch current firewall rules: ${e.message}`);
    }

    try {
      currentSslRules = await client.getSslInspectionRules() || [];
    } catch (e) {
      plan.warnings.push(`Could not fetch current SSL inspection rules: ${e.message}`);
    }

    // Plan URL Filtering Rules
    if (template.policies?.urlFiltering) {
      for (const rule of template.policies.urlFiltering) {
        const existing = currentUrlRules.find(r => r.name === rule.name);
        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'URL Filtering',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: rule.isRisky || false
        });
      }
    }

    // Plan Firewall Rules
    if (template.policies?.firewallFiltering) {
      for (const rule of template.policies.firewallFiltering) {
        const existing = currentFwRules.find(r => r.name === rule.name);
        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'Firewall',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: rule.isRisky || false
        });
      }
    }

    // Plan SSL Rules
    if (template.policies?.sslInspection) {
      for (const rule of template.policies.sslInspection) {
        const existing = currentSslRules.find(r => r.name === rule.name);
        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'SSL Inspection',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: rule.isRisky || false
        });
      }
    }

    // Malware & Advanced Settings
    if (template.policies?.malwareProtection) {
      plan.actions.push({
        type: 'UPDATE',
        category: 'Malware Protection',
        name: template.policies.malwareProtection.name,
        description: 'Update malware and advanced threat protection settings',
        current: null,
        proposed: { settings: template.policies.malwareProtection.settings },
        complianceMapping: template.policies.malwareProtection.complianceMapping
      });
    }

    if (template.policies?.advancedSettings) {
      plan.actions.push({
        type: 'UPDATE',
        category: 'Advanced Settings',
        name: template.policies.advancedSettings.name,
        description: 'Update advanced cloud configuration settings',
        current: null,
        proposed: { settings: template.policies.advancedSettings.settings },
        complianceMapping: template.policies.advancedSettings.complianceMapping
      });
    }

    // Plan Sandbox Rules
    if (template.policies?.sandbox) {
      let currentSandboxRules = [];
      try { currentSandboxRules = await client.getSandboxRules() || []; } catch(e) { plan.warnings.push(`Could not fetch sandbox rules: ${e.message}`); }
      for (const rule of template.policies.sandbox) {
        const existing = Array.isArray(currentSandboxRules) ? currentSandboxRules.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'Sandbox',
          name: rule.name,
          description: rule.description,
          current: existing ? { baRuleAction: existing.baRuleAction, state: existing.state } : null,
          proposed: { baRuleAction: rule.baRuleAction, state: rule.state, firstTimeOperation: rule.firstTimeOperation },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan DNS Security Rules
    if (template.policies?.dnsSecurity) {
      let currentDnsRules = [];
      try { currentDnsRules = await client.getDnsControlRules() || []; } catch(e) { plan.warnings.push(`Could not fetch DNS rules: ${e.message}`); }
      for (const rule of template.policies.dnsSecurity) {
        const existing = Array.isArray(currentDnsRules) ? currentDnsRules.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'DNS Security',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: { action: rule.action, state: rule.state },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan File Type Control Rules
    if (template.policies?.fileTypeControl) {
      let currentFtcRules = [];
      try { currentFtcRules = await client.getFileTypeRules() || []; } catch(e) { plan.warnings.push(`Could not fetch file type rules: ${e.message}`); }
      for (const rule of template.policies.fileTypeControl) {
        const existing = Array.isArray(currentFtcRules) ? currentFtcRules.find(r => r.name === rule.name) : null;
        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'File Type Control',
          name: rule.name,
          description: rule.description,
          current: existing ? { filteringAction: existing.filteringAction, state: existing.state } : null,
          proposed: { filteringAction: rule.filteringAction, state: rule.state, operation: rule.operation },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan Cloud App Control Rules
    if (template.policies?.cloudAppControl) {
      for (const rule of template.policies.cloudAppControl) {
        plan.actions.push({
          type: 'CREATE',
          category: 'Cloud App Control',
          name: rule.name,
          description: rule.description,
          current: null,
          proposed: { actions: rule.actions, state: rule.state, ruleType: rule.ruleType },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Plan DLP Rules
    if (template.policies?.dlp) {
      let currentDlpRules = [];
      try { currentDlpRules = await client.getWebDlpRules() || []; } catch(e) { plan.warnings.push(`Could not fetch current DLP rules: ${e.message}`); }
      if (!Array.isArray(currentDlpRules)) currentDlpRules = [];

      // Fetch engines and dictionaries to validate availability
      let availableEngines = [];
      let availableDicts = [];
      try {
        availableEngines = await client.getDlpEngines() || [];
        if (!Array.isArray(availableEngines)) availableEngines = [];
      } catch(e) {
        plan.warnings.push(`Could not fetch DLP engines: ${e.message}`);
      }
      try {
        availableDicts = await client.getDlpDictionaries() || [];
        if (!Array.isArray(availableDicts)) availableDicts = [];
      } catch(e) {
        plan.warnings.push(`Could not fetch DLP dictionaries: ${e.message}`);
      }

      for (const rule of template.policies.dlp) {
        const existing = currentDlpRules.find(r => r.name === rule.name);

        // Check engine availability
        let engineMatch = null;
        if (rule.preferredEngineNames && rule.preferredEngineNames.length > 0) {
          for (const eName of rule.preferredEngineNames) {
            engineMatch = availableEngines.find(e => e.name && e.name.toLowerCase() === eName.toLowerCase());
            if (engineMatch) break;
          }
        }

        // Check dictionary availability
        let dictStatus = '';
        if (rule.dictionaryNames && rule.dictionaryNames.length > 0) {
          const foundCount = rule.dictionaryNames.filter(dName =>
            availableDicts.some(d => d.name && d.name.toLowerCase() === dName.toLowerCase())
          ).length;
          dictStatus = `${foundCount}/${rule.dictionaryNames.length} dictionaries available`;
          if (foundCount < rule.dictionaryNames.length) {
            const missing = rule.dictionaryNames.filter(dName =>
              !availableDicts.some(d => d.name && d.name.toLowerCase() === dName.toLowerCase())
            );
            plan.warnings.push(`${rule.name}: Missing dictionaries: ${missing.join(', ')}`);
          }
        }

        const resolution = engineMatch
          ? `Engine: ${engineMatch.name} (ID: ${engineMatch.id})`
          : rule.withoutContentInspection
            ? 'Without content inspection'
            : `Dictionary-based (${dictStatus})`;

        plan.actions.push({
          type: existing ? 'UPDATE' : 'CREATE',
          category: 'Data Loss Prevention',
          name: rule.name,
          description: rule.description,
          current: existing ? { action: existing.action, state: existing.state } : null,
          proposed: {
            action: rule.action,
            state: rule.state,
            severity: rule.severity,
            resolution,
            dictionaries: rule.dictionaryNames || [],
            preferredEngines: rule.preferredEngineNames || []
          },
          complianceMapping: rule.complianceMapping,
          isRisky: false
        });
      }
    }

    // Store snapshot for rollback
    const snapshotId = uuidv4();
    let currentDlpSnapshot = [];
    try { currentDlpSnapshot = await client.getWebDlpRules() || []; } catch(e) { /* ignore */ }
    req.session.snapshots[snapshotId] = {
      urlRules: currentUrlRules,
      fwRules: currentFwRules,
      sslRules: currentSslRules,
      dlpRules: Array.isArray(currentDlpSnapshot) ? currentDlpSnapshot : [],
      timestamp: new Date().toISOString()
    };

    plan.snapshotId = snapshotId;
    plan.summary = {
      totalActions: plan.actions.length,
      creates: plan.actions.filter(a => a.type === 'CREATE').length,
      updates: plan.actions.filter(a => a.type === 'UPDATE').length,
      riskyActions: plan.actions.filter(a => a.isRisky).length,
      categories: [...new Set(plan.actions.map(a => a.category))]
    };

    logger.log('DRY_RUN', plan.summary);

    res.json(plan);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Apply Routes
// ========================

app.post('/api/apply', requireAuth, async (req, res) => {
  try {
    const { template, snapshotId } = req.body;
    if (!template) {
      return res.status(400).json({ error: 'No template provided' });
    }

    const { client, logger } = req.session;
    const results = { applied: [], errors: [], warnings: [] };

    // Apply URL Filtering Rules
    if (template.policies?.urlFiltering) {
      // Track custom category IDs: configuredName -> API-assigned ID
      const customCategoryIds = {};

      // First create custom categories if needed
      for (const rule of template.policies.urlFiltering) {
        if (rule.requiresCustomCategory) {
          try {
            const catResult = await client.createUrlCategory({
              configuredName: rule.customCategoryName,
              superCategory: 'USER_DEFINED',
              urls: ['placeholder.example.com'],
              description: `Custom block category created by ZTP Wizard`
            });
            // The API returns the category with its assigned ID (e.g., "CUSTOM_01")
            if (catResult && catResult.id) {
              customCategoryIds[rule.customCategoryName] = catResult.id;
              console.log(`[APPLY] Custom category created: ${rule.customCategoryName} -> ID: ${catResult.id}`);
            }
            results.applied.push({ type: 'CREATE', category: 'URL Category', name: rule.customCategoryName });
            logger.logPolicyApply('URL Category', rule.customCategoryName, 'CREATE', { success: true, id: catResult?.id });
          } catch (e) {
            if (e.message.includes('DUPLICATE_ITEM') || e.message.includes('already exists') || e.message.includes('already taken')) {
              // Category exists — try to find its ID by fetching custom categories
              results.warnings.push(`Custom category already exists: ${rule.customCategoryName}. Attempting to look up its ID.`);
              try {
                const existingCats = await client.getUrlCategories(true);
                if (Array.isArray(existingCats)) {
                  const match = existingCats.find(c => c.configuredName === rule.customCategoryName);
                  if (match && match.id) {
                    customCategoryIds[rule.customCategoryName] = match.id;
                    console.log(`[APPLY] Found existing custom category: ${rule.customCategoryName} -> ID: ${match.id}`);
                  }
                }
              } catch (lookupErr) {
                results.warnings.push(`Could not look up existing category: ${lookupErr.message}`);
              }
            } else {
              results.errors.push({ category: 'URL Category', name: rule.customCategoryName, error: e.message });
            }
          }
        }
      }

      // Create URL filtering rules — track successful order for next rule
      let urlOrderTracker = 1;
      try {
        const existingUrlRules = await client.getUrlFilteringRules();
        if (Array.isArray(existingUrlRules) && existingUrlRules.length > 0) {
          // Place new rules after existing ones (before the default rule)
          const nonDefaultMaxOrder = Math.max(...existingUrlRules.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          urlOrderTracker = nonDefaultMaxOrder + 1;
        }
      } catch(e) { /* use order 1 */ }

      for (const rule of template.policies.urlFiltering) {
        try {
          // CAUTION action only supports CONNECT/GET/HEAD request methods
          const requestMethods = rule.action === 'CAUTION'
            ? ['CONNECT', 'GET', 'HEAD']
            : ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE',
               'CONNECT', 'OTHER', 'PROPFIND', 'PROPPATCH', 'MOVE', 'MKCOL',
               'LOCK', 'COPY', 'UNLOCK', 'PATCH'];

          // Replace custom category names with their API-assigned IDs
          const urlCategories = rule.urlCategories.map(cat => {
            if (customCategoryIds[cat]) {
              return customCategoryIds[cat];
            }
            return cat;
          });

          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: urlOrderTracker,
            state: rule.state,
            rank: 7,
            action: rule.action,
            urlCategories,
            protocols: ['ANY_RULE'],
            requestMethods,
            blockOverride: false,
            enforceTimeValidity: false
          };

          const result = await client.createUrlFilteringRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'URL Filtering', name: rule.name, id: result?.id });
          logger.logPolicyApply('URL Filtering', rule.name, 'CREATE', { success: true, id: result?.id });
          urlOrderTracker++; // Only increment on success
        } catch (e) {
          results.errors.push({ category: 'URL Filtering', name: rule.name, error: e.message });
          logger.logPolicyApply('URL Filtering', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply Firewall Rules
    if (template.policies?.firewallFiltering) {
      let fwOrderTracker = 5; // Start after predefined rules
      try {
        const existingFwRules = await client.getFirewallRules();
        if (Array.isArray(existingFwRules) && existingFwRules.length > 0) {
          const nonDefaultMaxOrder = Math.max(...existingFwRules.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          fwOrderTracker = nonDefaultMaxOrder + 1;
        }
      } catch(e) { /* use default */ }

      for (const rule of template.policies.firewallFiltering) {
        try {
          const action = rule.action === 'BLOCK_ICMP_UNREACHABLE' ? 'BLOCK_DROP' : rule.action;
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: fwOrderTracker,
            state: rule.state,
            rank: 7,
            action: action,
            enableFullLogging: false
          };

          // Add network application categories (critical — without these, rules match ALL traffic)
          if (rule.nwApplications && rule.nwApplications.length > 0) {
            apiRule.nwApplications = rule.nwApplications;
          }

          // Add destination ports if specified
          if (rule.destPorts) {
            apiRule.destPorts = rule.destPorts;
          }

          // Add protocols if specified (e.g., UDP_RULE for QUIC block)
          if (rule.protocols && rule.protocols.length > 0) {
            apiRule.protocols = rule.protocols;
          }

          // Add destIpCategories if present
          if (rule.destIpCategories && rule.destIpCategories.length > 0) {
            apiRule.destIpCategories = rule.destIpCategories;
          }
          const result = await client.createFirewallRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'Firewall', name: rule.name, id: result?.id });
          logger.logPolicyApply('Firewall', rule.name, 'CREATE', { success: true, id: result?.id });
          fwOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'Firewall', name: rule.name, error: e.message });
          logger.logPolicyApply('Firewall', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply SSL Inspection Rules
    if (template.policies?.sslInspection) {
      for (const rule of template.policies.sslInspection) {
        try {
          // Per Zscaler API docs (automate.zscaler.com):
          // - action is a nested object: { type, decryptSubActions/doNotDecryptSubActions, showEUN, etc }
          // - urlCategories is NOT a string array for SSL — it's an object array
          // - decryptSubActions uses minClientTLSVersion (uppercase TLS), not minClientTlsVersion
          const actionType = (rule.action === 'INSPECT' || rule.action === 'DECRYPT')
            ? 'DECRYPT' : 'DO_NOT_DECRYPT';

          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: rule.order,
            state: rule.state,
            rank: 7,
            roadWarriorForKerberos: false
          };

          if (actionType === 'DO_NOT_DECRYPT') {
            apiRule.action = {
              type: 'DO_NOT_DECRYPT',
              doNotDecryptSubActions: {
                serverCertificates: 'ALLOW',
                bypassOtherPolicies: false,
                ocspCheck: false,
                blockSslTrafficWithNoSniEnabled: false
              },
              showEUN: false,
              showEUNATP: false,
              overrideDefaultCertificate: false
            };
          } else {
            // DECRYPT action — field names must match API doc exactly
            // API doc shows: minClientTLSVersion (not minClientTlsVersion)
            // ZTH Ebook uses TLS 1.2 minimum; standard tiers use TLS 1.0
            const clientTLS = rule.minClientTLS || 'CLIENT_TLS_1_0';
            const serverTLS = rule.minServerTLS || 'SERVER_TLS_1_0';
            apiRule.action = {
              type: 'DECRYPT',
              decryptSubActions: {
                serverCertificates: 'ALLOW',
                ocspCheck: true,
                blockSslTrafficWithNoSniEnabled: true,
                minClientTLSVersion: clientTLS,
                minServerTLSVersion: serverTLS,
                blockUndecrypt: true,
                http2Enabled: false
              },
              showEUN: false,
              showEUNATP: false,
              overrideDefaultCertificate: false
            };
          }

          // urlCategories: use plain string array for specific categories (proven working in v1.0.8/1.0.9)
          // For catch-all (ANY), omit urlCategories entirely (proven working in v1.0.9)
          if (rule.urlCategories && rule.urlCategories.length > 0 &&
              !(rule.urlCategories.length === 1 && rule.urlCategories[0] === 'ANY')) {
            apiRule.urlCategories = rule.urlCategories;
          }
          // When urlCategories is ["ANY"] or empty, we omit it — matches all traffic

          const result = await client.createSslInspectionRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'SSL Inspection', name: rule.name, id: result?.id });
          logger.logPolicyApply('SSL Inspection', rule.name, 'CREATE', { success: true, id: result?.id });
        } catch (e) {
          results.errors.push({ category: 'SSL Inspection', name: rule.name, error: e.message });
          logger.logPolicyApply('SSL Inspection', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply Sandbox Rules
    if (template.policies?.sandbox) {
      let sbOrderTracker = 1;
      try {
        const existingSb = await client.getSandboxRules();
        if (Array.isArray(existingSb) && existingSb.length > 0) {
          const nonDefaultMax = Math.max(...existingSb.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          sbOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      // Look up CBI isolation profile if any rule needs QUARANTINE_ISOLATE
      let cbiProfileId = null;
      const needsCbi = template.policies.sandbox.some(r => r.firstTimeOperation === 'QUARANTINE_ISOLATE');
      if (needsCbi) {
        try {
          // Fetch isolation profiles from the API
          const profiles = await client.apiCall('GET', '/api/v1/browserIsolationProfile');
          if (Array.isArray(profiles)) {
            const defaultProfile = profiles.find(p =>
              p.name === 'Default Isolation Profile' || p.defaultProfile === true
            );
            if (defaultProfile) {
              cbiProfileId = defaultProfile.id;
              console.log(`[APPLY] Found CBI profile: "${defaultProfile.name}" -> ID: ${cbiProfileId}`);
            } else if (profiles.length > 0) {
              // Use first available profile as fallback
              cbiProfileId = profiles[0].id;
              console.log(`[APPLY] Using first CBI profile: "${profiles[0].name}" -> ID: ${cbiProfileId}`);
            }
          }
        } catch(e) {
          results.warnings.push(`Could not fetch CBI profiles: ${e.message}. QUARANTINE_ISOLATE rules will fall back to QUARANTINE.`);
          console.log(`[APPLY] CBI profile lookup failed: ${e.message}`);
        }
      }

      for (const rule of template.policies.sandbox) {
        try {
          let firstTimeOp = rule.firstTimeOperation || 'QUARANTINE';
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: sbOrderTracker,
            state: rule.state,
            rank: 7,
            protocols: rule.protocols || ['ANY_RULE'],
            fileTypes: rule.fileTypes,
            baPolicyCategories: rule.baPolicyCategories || [],
            baRuleAction: rule.baRuleAction || 'BLOCK',
            firstTimeEnable: rule.firstTimeEnable || false,
            mlActionEnabled: rule.mlActionEnabled || false
          };

          // Handle QUARANTINE_ISOLATE — needs cbiProfile
          if (firstTimeOp === 'QUARANTINE_ISOLATE' && cbiProfileId) {
            apiRule.firstTimeOperation = 'QUARANTINE_ISOLATE';
            apiRule.cbiProfileId = cbiProfileId;
          } else if (firstTimeOp === 'QUARANTINE_ISOLATE' && !cbiProfileId) {
            // Fall back to plain QUARANTINE if no CBI profile found
            apiRule.firstTimeOperation = 'QUARANTINE';
            results.warnings.push(`${rule.name}: Fell back to QUARANTINE (no CBI profile available for QUARANTINE_ISOLATE)`);
          } else {
            apiRule.firstTimeOperation = firstTimeOp;
          }

          const result = await client.createSandboxRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'Sandbox', name: rule.name, id: result?.id });
          logger.logPolicyApply('Sandbox', rule.name, 'CREATE', { success: true, id: result?.id });
          sbOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'Sandbox', name: rule.name, error: e.message });
          logger.logPolicyApply('Sandbox', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply DNS Security Rules
    if (template.policies?.dnsSecurity) {
      let dnsOrderTracker = 1;
      try {
        const existingDns = await client.getDnsControlRules();
        if (Array.isArray(existingDns) && existingDns.length > 0) {
          const nonDefaultMax = Math.max(...existingDns.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          dnsOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      for (const rule of template.policies.dnsSecurity) {
        try {
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: dnsOrderTracker,
            state: rule.state,
            rank: rule.rank || 7,
            action: rule.action || 'BLOCK',
            protocols: rule.protocols || ['ANY_RULE']
          };
          if (rule.applications && rule.applications.length > 0) {
            apiRule.applications = rule.applications;
          }
          const result = await client.createDnsControlRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'DNS Security', name: rule.name, id: result?.id });
          logger.logPolicyApply('DNS Security', rule.name, 'CREATE', { success: true, id: result?.id });
          dnsOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'DNS Security', name: rule.name, error: e.message });
          logger.logPolicyApply('DNS Security', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply File Type Control Rules
    if (template.policies?.fileTypeControl) {
      let ftcOrderTracker = 1;
      try {
        const existingFtc = await client.getFileTypeRules();
        if (Array.isArray(existingFtc) && existingFtc.length > 0) {
          const nonDefaultMax = Math.max(...existingFtc.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          ftcOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      for (const rule of template.policies.fileTypeControl) {
        try {
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: ftcOrderTracker,
            state: rule.state,
            rank: 7,
            protocols: rule.protocols || ['ANY_RULE'],
            fileTypes: rule.fileTypes || [],
            filteringAction: rule.filteringAction || 'BLOCK',
            operation: rule.operation || 'UPLOAD_DOWNLOAD'
          };
          if (rule.passwordProtected !== undefined) {
            apiRule.passwordProtected = rule.passwordProtected;
          }
          const result = await client.createFileTypeRule(apiRule);
          results.applied.push({ type: 'CREATE', category: 'File Type Control', name: rule.name, id: result?.id });
          logger.logPolicyApply('File Type Control', rule.name, 'CREATE', { success: true, id: result?.id });
          ftcOrderTracker++;
        } catch (e) {
          results.errors.push({ category: 'File Type Control', name: rule.name, error: e.message });
          logger.logPolicyApply('File Type Control', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply Cloud App Control Rules
    if (template.policies?.cloudAppControl) {
      // Track order per rule type since each CAC category has its own order space
      const cacOrderTrackers = {};

      for (const rule of template.policies.cloudAppControl) {
        try {
          const ruleType = rule.ruleType || rule.type || 'AI_ML';

          // Fetch current max order for this rule type if not yet cached
          if (cacOrderTrackers[ruleType] === undefined) {
            try {
              const existing = await client.getCloudAppControlRules(ruleType);
              if (Array.isArray(existing) && existing.length > 0) {
                const nonDefaultMax = Math.max(...existing.filter(r => !r.predefined).map(r => r.order || 0), 0);
                cacOrderTrackers[ruleType] = nonDefaultMax + 1;
              } else {
                cacOrderTrackers[ruleType] = 1;
              }
            } catch(e) { cacOrderTrackers[ruleType] = 1; }
          }

          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: cacOrderTrackers[ruleType],
            state: rule.state,
            rank: 7,
            type: ruleType,
            actions: rule.actions || []
          };

          const result = await client.createCloudAppControlRule(ruleType, apiRule);
          results.applied.push({ type: 'CREATE', category: 'Cloud App Control', name: rule.name, id: result?.id });
          logger.logPolicyApply('Cloud App Control', rule.name, 'CREATE', { success: true, id: result?.id });
          cacOrderTrackers[ruleType]++;
        } catch (e) {
          results.errors.push({ category: 'Cloud App Control', name: rule.name, error: e.message });
          logger.logPolicyApply('Cloud App Control', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Apply DLP Rules (Web DLP Rules) — Dictionary-first hybrid approach
    if (template.policies?.dlp) {
      const dlpPrefix = template.metadata?.prefix || 'ZTP';

      // Step 1: Fetch engines and dictionaries from tenant
      let dlpEngines = [];
      let dlpDictionaries = [];
      try {
        dlpEngines = await client.getDlpEngines() || [];
        if (!Array.isArray(dlpEngines)) dlpEngines = [];
        console.log(`[APPLY] Found ${dlpEngines.length} DLP engines on tenant:`);
        dlpEngines.forEach(e => console.log(`[APPLY]   Engine ID=${e.id} name="${e.name}"`));
      } catch(e) {
        results.warnings.push(`Could not fetch DLP engines: ${e.message}`);
      }

      try {
        dlpDictionaries = await client.getDlpDictionaries() || [];
        if (!Array.isArray(dlpDictionaries)) dlpDictionaries = [];
        console.log(`[APPLY] Found ${dlpDictionaries.length} DLP dictionaries on tenant`);
        // Log predefined dictionaries to see their actual names
        const predefinedDicts = dlpDictionaries.filter(d => !d.custom);
        const customDicts = dlpDictionaries.filter(d => d.custom);
        console.log(`[APPLY] Predefined: ${predefinedDicts.length}, Custom: ${customDicts.length}`);
        predefinedDicts.forEach(d => console.log(`[APPLY]   PREDEF Dict ID=${d.id} name="${d.name}" nameL10n=${d.nameL10nTag} desc="${(d.description || '').substring(0, 60)}"`));
        customDicts.slice(0, 5).forEach(d => console.log(`[APPLY]   CUSTOM Dict ID=${d.id} name="${d.name}"`));
      } catch(e) {
        results.warnings.push(`Could not fetch DLP dictionaries: ${e.message}`);
      }

      // Step 2: Order tracking
      let dlpOrderTracker = 1;
      try {
        const existingDlp = await client.getWebDlpRules();
        if (Array.isArray(existingDlp) && existingDlp.length > 0) {
          const nonDefaultMax = Math.max(...existingDlp.filter(r => !r.defaultRule).map(r => r.order || 0), 0);
          dlpOrderTracker = nonDefaultMax + 1;
        }
      } catch(e) { /* use 1 */ }

      // Helper: find engine by name (flexible matching)
      function findEngine(name) {
        if (!name || dlpEngines.length === 0) return null;
        let match = dlpEngines.find(e => e.name === name);
        if (match) return match;
        match = dlpEngines.find(e => e.name && e.name.toLowerCase() === name.toLowerCase());
        if (match) return match;
        const words = name.toLowerCase().split(/[\s\-()]+/).filter(w => w.length > 2);
        if (words.length > 0) {
          match = dlpEngines.find(e => e.name && words.every(w => e.name.toLowerCase().includes(w)));
        }
        return match || null;
      }

      // Helper: get the display name from a dictionary object (API may use different fields)
      function getDictName(d) {
        return d.name || d.dictionaryName || d.configuredName || d.displayName || '';
      }

      // Predefined dictionary display-name to internal-name mapping
      // Built from the actual tenant dump — predefined dicts use _LEAKAGE suffix codes
      const DICT_DISPLAY_TO_INTERNAL = {
        'social security numbers (us)': ['SSN'],
        'credit cards': ['CREDIT_CARD'],
        'medical information': ['MEDICAL'],
        'medical document': ['ML_MEDICAL_DOC_LEAKAGE'],
        'diseases information': ['DISEASES_LEAKAGE'],
        'drugs information': ['DRUGS_LEAKAGE'],
        'treatments information': ['TREATMENTS_LEAKAGE'],
        'financial statements': ['FINANCIAL'],
        'names (us)': ['NAME_LEAKAGE'],
        "driver's license (united states)": ['USDL_LEAKAGE', 'EN_USDL_LEAKAGE'],
        'credentials and secrets': ['CRED_LEAKAGE'],
        'source code': ['SOURCE_CODE', 'ML_SOURCE_CODE_DOCUMENT_LEAKAGE'],
        'adult content': ['ADULT_CONTENT'],
        'self-harm & cyberbullying': ['CYBER_BULLY'],
        'tax identification number (us)': ['TIN_LEAKAGE', 'USITIN_LEAKAGE'],
        'individual taxpayer registry id (brazil)': ['CPF_LEAKAGE'],
        'invoice document': ['ML_INVOICE_LEAKAGE'],
        'tax document': ['ML_TAX_LEAKAGE'],
        'corporate finance document': ['ML_CORPORATE_FINANCE_LEAKAGE'],
        'aba bank routing numbers': ['ABA_LEAKAGE'],
        'international bank account number (iban)': ['EUIBAN_LEAKAGE'],
        'legal document': ['ML_LEGAL_LEAKAGE'],
        'court document': ['ML_COURT_LEAKAGE'],
        'immigration document': ['ML_IMMIGRATION_LEAKAGE'],
        'resume document': ['ML_RESUME_LEAKAGE'],
        'insurance document': ['ML_INSURANCE_LEAKAGE'],
        'national identification number (france)': ['INSEE_LEAKAGE'],
        'national identification number (spain)': ['DNI_LEAKAGE'],
        'national identification number (poland)': ['PESEL_LEAKAGE'],
        'passport number (european union)': ['PPEU_LEAKAGE'],
        'citizen service numbers (netherlands)': ['BSN_LEAKAGE'],
        'fiscal code (italy)': ['FISCAL_LEAKAGE'],
        'national insurance number (uk)': ['NINO_LEAKAGE'],
        'national health service number (uk)': ['NHS_LEAKAGE']
      };

      // Helper: find dictionary by display name using exact internal name mapping
      function findDictionary(targetName) {
        if (!targetName || dlpDictionaries.length === 0) return null;
        const target = targetName.toLowerCase().trim();

        // Strategy 1: Exact match on name field
        let match = dlpDictionaries.find(d => getDictName(d).toLowerCase() === target);
        if (match) return match;

        // Strategy 2: Use the display-to-internal mapping (exact match on internal code)
        const internalNames = DICT_DISPLAY_TO_INTERNAL[target];
        if (internalNames) {
          for (const iName of internalNames) {
            match = dlpDictionaries.find(d => getDictName(d) === iName);
            if (match) return match;
          }
        }

        // Strategy 3: Description field contains target (only for predefined dicts)
        // Skip this — it caused too many false matches

        return null;
      }

      // Step 3: Create each DLP rule
      for (const rule of template.policies.dlp) {
        try {
          const isWCI = rule.withoutContentInspection === true;
          let resolvedEngine = null;
          let resolvedDictIds = [];

          if (!isWCI) {
            // Try preferred engines first
            if (rule.preferredEngineNames && rule.preferredEngineNames.length > 0) {
              for (const eName of rule.preferredEngineNames) {
                resolvedEngine = findEngine(eName);
                if (resolvedEngine) {
                  console.log(`[APPLY] "${rule.name}" engine: "${resolvedEngine.name}" (ID: ${resolvedEngine.id})`);
                  break;
                }
              }
            }

            // No engine — resolve dictionaries and create a custom engine from them
            if (!resolvedEngine && rule.dictionaryNames && rule.dictionaryNames.length > 0) {
              const found = [];
              const missing = [];
              for (const dName of rule.dictionaryNames) {
                const dict = findDictionary(dName);
                if (dict) {
                  found.push(dict);
                  resolvedDictIds.push(dict.id);
                  console.log(`[APPLY]   Dict match: "${dName}" -> "${getDictName(dict)}" (ID: ${dict.id})`);
                } else {
                  missing.push(dName);
                  console.log(`[APPLY]   Dict NOT found: "${dName}"`);
                }
              }
              if (missing.length > 0) {
                results.warnings.push(`${rule.name}: Dictionaries not found: ${missing.join(', ')}`);
              }

              // Create a custom DLP engine from resolved dictionaries
              if (found.length > 0) {
                try {
                  const engineName = rule.name.replace(dlpPrefix + '-DLP-', dlpPrefix + '-Engine-');
                  // engineExpression format from API docs:
                  //   Single:  ((D63.S> 1))
                  //   OR:      ((D38.S> 1) OR (D63.S> 1))
                  //   AND:     ((D38.S> 1) AND (D63.S> 1))
                  // Each dictionary ID is wrapped with prefix D and suffix .S
                  let engineExpression;
                  if (found.length === 1) {
                    engineExpression = `((D${found[0].id}.S> 1))`;
                  } else {
                    const parts = found.map(d => `(D${d.id}.S> 1)`).join(' OR ');
                    engineExpression = `(${parts})`;
                  }

                  const customEngine = {
                    name: engineName,
                    description: `Auto-created by ZTP Wizard. Dictionaries: ${found.map(d => getDictName(d)).join(', ')}`,
                    customDlpEngine: true,
                    engineExpression: engineExpression
                  };

                  console.log(`[APPLY] Creating custom engine "${engineName}" engineExpression: ${engineExpression}`);
                  const result = await client.createCustomDlpEngine(customEngine);
                  if (result && result.id) {
                    resolvedEngine = result;
                    console.log(`[APPLY] Created custom DLP engine: "${engineName}" (ID: ${result.id})`);
                    results.applied.push({ type: 'CREATE', category: 'DLP Engine', name: engineName, id: result.id });
                  }
                } catch (engineErr) {
                  console.log(`[APPLY] Custom engine creation failed: ${engineErr.message}`);
                  // Fall through — will try without engine below
                }
              }

              if (resolvedDictIds.length === 0 && !resolvedEngine) {
                results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: `No engines or dictionaries found. Needed: ${rule.dictionaryNames.join(', ')}` });
                continue;
              }
            }

            // If we have dictionaries but still no engine, try withoutContentInspection as last resort
            if (!resolvedEngine && resolvedDictIds.length > 0) {
              console.log(`[APPLY] "${rule.name}" — has ${resolvedDictIds.length} dictionaries but no engine. Will attempt rule creation with engine fallbacks.`);
            }

            if (!resolvedEngine && resolvedDictIds.length === 0) {
              results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: 'No engine or dictionaries resolved' });
              continue;
            }
          }

          // --- Build API payload ---
          const apiRule = {
            name: rule.name,
            description: rule.description || '',
            order: dlpOrderTracker,
            state: 'ENABLED',
            rank: 7,
            protocols: ['ANY_RULE'],
            action: 'ALLOW',
            severity: rule.severity || 'RULE_SEVERITY_MEDIUM'
          };

          // Text-based file type categories — avoid OCR-heavy image types
          const TEXT_FILE_TYPES = [
            'FTCATEGORY_MS_WORD', 'FTCATEGORY_MS_EXCEL', 'FTCATEGORY_MS_POWERPOINT',
            'FTCATEGORY_MS_RTF', 'FTCATEGORY_PDF_DOCUMENT', 'FTCATEGORY_TEXT',
            'FTCATEGORY_CSV', 'FTCATEGORY_HTML'
          ];

          if (isWCI || (!resolvedEngine)) {
            // Without content inspection — fallback when no engine created
            apiRule.withoutContentInspection = true;
            // WCI rules REQUIRE fileTypes — use text-based categories
            apiRule.fileTypes = TEXT_FILE_TYPES;
            if (!isWCI && !resolvedEngine) {
              results.warnings.push(`${rule.name}: No DLP engine matched. Created as without-content-inspection rule. For full scanning, create a custom DLP engine from: ${(rule.dictionaryNames || []).join(', ')}`);
            }
          } else if (resolvedEngine) {
            apiRule.dlpEngines = [{ id: resolvedEngine.id }];
          }

          // Attempt 1: Without incident receiver (it causes 400 on this tenant)
          let created = false;
          try {
            const result = await client.createWebDlpRule(apiRule);
            results.applied.push({ type: 'CREATE', category: 'Data Loss Prevention', name: rule.name, id: result?.id });
            logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { success: true, id: result?.id });
            dlpOrderTracker++;
            created = true;
          } catch (e1) {
            console.log(`[APPLY] DLP attempt 1 failed "${rule.name}": ${e1.message}`);
            // Attempt 2: Add zscalerIncidentReceiver (works on some tenants)
            try {
              apiRule.zscalerIncidentReceiver = true;
              const result = await client.createWebDlpRule(apiRule);
              results.applied.push({ type: 'CREATE', category: 'Data Loss Prevention', name: rule.name, id: result?.id });
              logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { success: true, id: result?.id, fallback: 'with-receiver' });
              dlpOrderTracker++;
              created = true;
            } catch (e2) {
              console.log(`[APPLY] DLP attempt 2 failed "${rule.name}": ${e2.message}`);
              // Attempt 3: Bare minimum with text fileTypes for WCI
              try {
                const bareRule = {
                  name: rule.name,
                  order: dlpOrderTracker,
                  rank: 7,
                  state: 'ENABLED',
                  action: 'ALLOW',
                  protocols: ['ANY_RULE']
                };
                if (resolvedEngine) {
                  bareRule.dlpEngines = [{ id: resolvedEngine.id }];
                } else {
                  bareRule.withoutContentInspection = true;
                  bareRule.fileTypes = TEXT_FILE_TYPES;
                }
                const result = await client.createWebDlpRule(bareRule);
                results.applied.push({ type: 'CREATE', category: 'Data Loss Prevention', name: rule.name, id: result?.id });
                results.warnings.push(`${rule.name}: Created with bare minimum fields`);
                logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { success: true, id: result?.id, fallback: 'bare' });
                dlpOrderTracker++;
                created = true;
              } catch (e3) {
                const dictInfo = rule.dictionaryNames ? ` Dictionaries: ${rule.dictionaryNames.join(', ')}` : '';
                results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: `All attempts failed. ${e3.message}.${dictInfo} Use /api/diag/dlp to inspect tenant.` });
                logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { error: e3.message });
              }
            }
          }
        } catch (e) {
          results.errors.push({ category: 'Data Loss Prevention', name: rule.name, error: e.message });
          logger.logPolicyApply('Data Loss Prevention', rule.name, 'CREATE', { error: e.message });
        }
      }
    }

    // Activate changes
    try {
      await client.activateChanges();
      results.activated = true;
      logger.log('ACTIVATION', { success: true });
    } catch (e) {
      results.activated = false;
      results.errors.push({ category: 'Activation', error: e.message });
      logger.log('ACTIVATION', { success: false, error: e.message }, 'error');
    }

    results.summary = {
      applied: results.applied.length,
      errors: results.errors.length,
      activated: results.activated,
      snapshotId
    };

    req.session.appliedChanges.push({
      timestamp: new Date().toISOString(),
      template: template.metadata,
      results
    });

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Rollback Routes
// ========================

app.post('/api/rollback', requireAuth, async (req, res) => {
  try {
    const { snapshotId } = req.body;
    const session = req.session;
    const snapshot = session.snapshots[snapshotId];

    if (!snapshot) {
      return res.status(404).json({ error: 'Snapshot not found. Rollback not available.' });
    }

    // Best-effort rollback: we note this is limited since we only create, not delete
    const results = {
      message: 'Rollback is best-effort. Created rules must be manually removed from ZIA admin portal. Snapshot state has been recorded for reference.',
      snapshotTimestamp: snapshot.timestamp,
      originalState: {
        urlRulesCount: snapshot.urlRules.length,
        fwRulesCount: snapshot.fwRules.length,
        sslRulesCount: snapshot.sslRules.length,
        dlpRulesCount: (snapshot.dlpRules || []).length
      }
    };

    session.logger.logRollback(snapshotId, results);

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Current State Routes
// ========================

// Diagnostic route — fetches a sample of current rules to show API schema
app.get('/api/diag/schema', requireAuth, async (req, res) => {
  try {
    const { client } = req.session;
    const diag = {};
    
    try {
      const urlRules = await client.getUrlFilteringRules();
      diag.urlFilteringRules = {
        count: Array.isArray(urlRules) ? urlRules.length : 'unknown',
        sample: Array.isArray(urlRules) && urlRules[0] ? urlRules[0] : urlRules
      };
    } catch (e) { diag.urlFilteringRules = { error: e.message }; }
    
    try {
      const fwRules = await client.getFirewallRules();
      diag.firewallRules = {
        count: Array.isArray(fwRules) ? fwRules.length : 'unknown',
        sample: Array.isArray(fwRules) && fwRules[0] ? fwRules[0] : fwRules
      };
    } catch (e) { diag.firewallRules = { error: e.message }; }
    
    try {
      const sslRules = await client.getSslInspectionRules();
      diag.sslInspectionRules = {
        count: Array.isArray(sslRules) ? sslRules.length : 'unknown',
        sample: Array.isArray(sslRules) && sslRules[0] ? sslRules[0] : sslRules,
        // Show ALL SSL rules so we can see DECRYPT rule format
        allRules: Array.isArray(sslRules) ? sslRules.map(r => ({
          id: r.id, name: r.name, order: r.order,
          action: r.action,
          urlCategories: r.urlCategories,
          platforms: r.platforms,
          predefined: r.predefined, defaultRule: r.defaultRule
        })) : []
      };
    } catch (e) { diag.sslInspectionRules = { error: e.message }; }

    try {
      const cats = await client.getUrlCategories();
      diag.urlCategories = {
        count: Array.isArray(cats) ? cats.length : 'unknown',
        names: Array.isArray(cats) ? cats.map(c => c.id || c.configuredName || c.name) : 'unknown'
      };
    } catch (e) { diag.urlCategories = { error: e.message }; }

    res.json(diag);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/url-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getUrlFilteringRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/firewall-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getFirewallRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/ssl-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getSslInspectionRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/url-categories', requireAuth, async (req, res) => {
  try {
    const cats = await req.session.client.getUrlCategories(req.query.customOnly === 'true');
    res.json(cats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/activation', requireAuth, async (req, res) => {
  try {
    const status = await req.session.client.getActivationStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- New v1.2.0 State Routes ---

app.get('/api/state/sandbox-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getSandboxRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dns-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getDnsControlRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/file-type-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getFileTypeRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/cloud-app-rules/:ruleType', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getCloudAppControlRules(req.params.ruleType);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- v1.5.0 DLP State Routes ---

app.get('/api/state/dlp-rules', requireAuth, async (req, res) => {
  try {
    const rules = await req.session.client.getWebDlpRules();
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dlp-engines', requireAuth, async (req, res) => {
  try {
    const engines = await req.session.client.getDlpEngines();
    res.json(engines);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dlp-dictionaries', requireAuth, async (req, res) => {
  try {
    const dicts = await req.session.client.getDlpDictionaries();
    res.json(dicts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/state/dlp-notification-templates', requireAuth, async (req, res) => {
  try {
    const templates = await req.session.client.getDlpNotificationTemplates();
    res.json(templates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DLP diagnostic — full dump of engines, dictionaries, existing rules, notification templates
app.get('/api/diag/dlp', requireAuth, async (req, res) => {
  try {
    const { client } = req.session;
    const diag = {};

    try {
      const engines = await client.getDlpEngines();
      diag.engines = {
        count: Array.isArray(engines) ? engines.length : 'unknown',
        list: Array.isArray(engines) ? engines.map(e => ({ id: e.id, name: e.name, predefinedEngineName: e.predefinedEngineName, customDlpEngine: e.customDlpEngine })) : engines
      };
    } catch (e) { diag.engines = { error: e.message }; }

    try {
      const dicts = await client.getDlpDictionaries();
      diag.dictionaries = {
        count: Array.isArray(dicts) ? dicts.length : 'unknown',
        list: Array.isArray(dicts) ? dicts.map(d => ({ id: d.id, name: d.name, predefinedDlpDictionary: d.predefinedDlpDictionary, custom: d.custom })) : dicts
      };
    } catch (e) { diag.dictionaries = { error: e.message }; }

    try {
      const rules = await client.getWebDlpRules();
      diag.existingRules = {
        count: Array.isArray(rules) ? rules.length : 'unknown',
        list: Array.isArray(rules) ? rules.map(r => ({ id: r.id, name: r.name, order: r.order, action: r.action, state: r.state, dlpEngines: r.dlpEngines })) : rules
      };
    } catch (e) { diag.existingRules = { error: e.message }; }

    try {
      const notif = await client.getDlpNotificationTemplates();
      diag.notificationTemplates = {
        count: Array.isArray(notif) ? notif.length : 'unknown',
        list: Array.isArray(notif) ? notif : notif
      };
    } catch (e) { diag.notificationTemplates = { error: e.message }; }

    try {
      const receivers = await client.getDlpIncidentReceiverServers();
      diag.incidentReceivers = {
        count: Array.isArray(receivers) ? receivers.length : 'unknown',
        list: Array.isArray(receivers) ? receivers : receivers
      };
    } catch (e) { diag.incidentReceivers = { error: e.message }; }

    res.json(diag);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Bulk Delete Routes (v1.2.0)
// ========================

app.post('/api/bulk-delete', requireAuth, async (req, res) => {
  try {
    const { rules } = req.body;
    // rules: array of { category, id, name, ruleType? }
    // category: 'url-filtering' | 'firewall' | 'ssl' | 'sandbox' | 'dns' | 'file-type' | 'cloud-app'
    if (!rules || !Array.isArray(rules) || rules.length === 0) {
      return res.status(400).json({ error: 'No rules specified for deletion. Provide an array of { category, id, name }.' });
    }

    const { client, logger } = req.session;
    const results = { deleted: [], errors: [], skipped: [] };

    for (const rule of rules) {
      if (!rule.id || !rule.category) {
        results.skipped.push({ name: rule.name, reason: 'Missing id or category' });
        continue;
      }

      // Skip default/predefined rules
      if (rule.defaultRule || rule.predefined) {
        results.skipped.push({ name: rule.name, id: rule.id, reason: 'Cannot delete predefined/default rules' });
        continue;
      }

      try {
        switch (rule.category) {
          case 'url-filtering':
            await client.deleteUrlFilteringRule(rule.id);
            break;
          case 'firewall':
            await client.deleteFirewallRule(rule.id);
            break;
          case 'ssl':
            await client.deleteSslInspectionRule(rule.id);
            break;
          case 'sandbox':
            await client.deleteSandboxRule(rule.id);
            break;
          case 'dns':
            await client.deleteDnsControlRule(rule.id);
            break;
          case 'file-type':
            await client.deleteFileTypeRule(rule.id);
            break;
          case 'cloud-app':
            await client.deleteCloudAppControlRule(rule.ruleType || 'AI_ML', rule.id);
            break;
          case 'dlp':
            await client.deleteWebDlpRule(rule.id);
            break;
          case 'dlp-engine':
            await client.deleteCustomDlpEngine(rule.id);
            break;
          case 'dlp-dictionary':
            // Only custom dictionaries can be deleted
            await client.apiCall('DELETE', `/api/v1/dlpDictionaries/${rule.id}`);
            break;
          default:
            results.skipped.push({ name: rule.name, id: rule.id, reason: `Unknown category: ${rule.category}` });
            continue;
        }
        results.deleted.push({ category: rule.category, name: rule.name, id: rule.id });
        logger.log('BULK_DELETE', { category: rule.category, name: rule.name, id: rule.id });
      } catch (e) {
        results.errors.push({ category: rule.category, name: rule.name, id: rule.id, error: e.message });
      }
    }

    // Activate after bulk delete
    try {
      await client.activateChanges();
      results.activated = true;
    } catch (e) {
      results.activated = false;
      results.errors.push({ category: 'Activation', error: e.message });
    }

    results.summary = {
      deleted: results.deleted.length,
      errors: results.errors.length,
      skipped: results.skipped.length,
      activated: results.activated
    };

    logger.log('BULK_DELETE_COMPLETE', results.summary);

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Convenience: List all rules across all categories for bulk delete UI
app.get('/api/state/all-rules', requireAuth, async (req, res) => {
  try {
    const { client } = req.session;
    const allRules = {};
    const prefix = req.query.prefix || ''; // Empty = return all rules

    const fetchCategory = async (name, fn) => {
      try {
        const data = await fn();
        let rules = Array.isArray(data) ? data : [];
        // If prefix filter specified, case-insensitive match
        if (prefix) {
          const lowerPrefix = prefix.toLowerCase();
          rules = rules.filter(r => r.name && r.name.toLowerCase().startsWith(lowerPrefix));
        }
        return rules.map(r => {
          // Normalize action to a string — SSL rules return action as an object { type: 'DECRYPT', ... }
          let action = r.action || r.baRuleAction || r.filteringAction || '';
          if (typeof action === 'object' && action !== null) {
            action = action.type || JSON.stringify(action);
          }
          return {
            id: r.id, name: r.name || '(unnamed)', order: r.order,
            state: r.state, action: String(action),
            defaultRule: r.defaultRule || r.predefined || false
          };
        });
      } catch (e) {
        console.error(`[ALL-RULES] Failed to fetch ${name}: ${e.message}`);
        return [];
      }
    };

    allRules.urlFiltering = await fetchCategory('url', () => client.getUrlFilteringRules());
    allRules.firewall = await fetchCategory('fw', () => client.getFirewallRules());
    allRules.ssl = await fetchCategory('ssl', () => client.getSslInspectionRules());
    allRules.sandbox = await fetchCategory('sandbox', () => client.getSandboxRules());
    allRules.dns = await fetchCategory('dns', () => client.getDnsControlRules());
    allRules.fileType = await fetchCategory('ftc', () => client.getFileTypeRules());
    allRules.dlp = await fetchCategory('dlp', () => client.getWebDlpRules());

    // DLP Engines (custom only — predefined engines can't be deleted)
    try {
      const engines = await client.getDlpEngines();
      const engineList = Array.isArray(engines) ? engines : [];
      allRules.dlpEngines = engineList
        .filter(e => e.customDlpEngine === true)
        .filter(e => !prefix || (e.name && e.name.toLowerCase().startsWith(prefix.toLowerCase())))
        .map(e => ({
          id: e.id, name: e.name || '(unnamed)', order: 0,
          state: 'ENABLED', action: e.engineExpression ? 'CUSTOM' : 'PREDEFINED',
          defaultRule: false
        }));
    } catch (e) {
      console.error(`[ALL-RULES] Failed to fetch DLP engines: ${e.message}`);
      allRules.dlpEngines = [];
    }

    // DLP Dictionaries (custom only)
    try {
      const dicts = await client.getDlpDictionaries();
      const dictList = Array.isArray(dicts) ? dicts : [];
      allRules.dlpDictionaries = dictList
        .filter(d => d.custom === true)
        .filter(d => !prefix || (d.name && d.name.toLowerCase().startsWith(prefix.toLowerCase())))
        .map(d => ({
          id: d.id, name: d.name || '(unnamed)', order: 0,
          state: 'ENABLED', action: 'CUSTOM',
          defaultRule: false
        }));
    } catch (e) {
      console.error(`[ALL-RULES] Failed to fetch DLP dictionaries: ${e.message}`);
      allRules.dlpDictionaries = [];
    }

    // Cloud app rules removed from bulk fetch — each type requires a separate API call
    // with rate limiting, adding ~10s to the total. Cloud app rules can be managed
    // individually via the ZIA admin portal.

    res.json(allRules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================
// Audit Log Routes
// ========================

app.get('/api/audit/logs', requireAuth, (req, res) => {
  res.json(req.session.logger.getEntries());
});

app.get('/api/audit/export/csv', requireAuth, (req, res) => {
  const csv = req.session.logger.exportToCSV();
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="ztp-audit-${new Date().toISOString().split('T')[0]}.csv"`);
  res.send(csv);
});

app.get('/api/audit/export/json', requireAuth, (req, res) => {
  const data = JSON.stringify(req.session.logger.getEntries(), null, 2);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="ztp-audit-${new Date().toISOString().split('T')[0]}.json"`);
  res.send(data);
});

// ========================
// ZCC Routes (v1.3.0 — Mobile Admin Portal)
// ========================

// Generate ZCC template
// ========================
// ZCC Routes (v1.5.1 — GET then PATCH/POST edit workflow)
// ========================

app.post('/api/zcc/templates/generate', requireAuth, (req, res) => {
  try {
    const config = req.body;
    const template = generateZCCTemplate(config);
    res.json(template);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Fetch all profiles for the selection UI
app.get('/api/zcc/profiles', requireAuth, async (req, res) => {
  try {
    const { zccClient } = req.session;
    if (!zccClient) return res.status(400).json({ error: 'ZCC client not initialized' });

    const result = { forwardingProfiles: [], appProfiles: [], errors: [] };

    // Forwarding profiles
    try {
      const fpResp = await zccClient.getForwardingProfiles();
      const fps = Array.isArray(fpResp) ? fpResp : (fpResp?.list || fpResp?.content || []);
      result.forwardingProfiles = fps.map(fp => ({
        id: fp.id, name: fp.name, active: fp.active,
        conditionType: fp.conditionType,
        hasActions: !!(fp.forwardingProfileActions && fp.forwardingProfileActions.length > 0),
        actionCount: fp.forwardingProfileActions?.length || 0,
        _raw: fp
      }));
      console.log(`[ZCC] Found ${result.forwardingProfiles.length} forwarding profiles`);
    } catch (e) {
      result.errors.push(`Forwarding profiles: ${e.message}`);
      console.log(`[ZCC] Forwarding profile fetch failed: ${e.message}`);
    }

    // App profiles (Windows = deviceType 3)
    try {
      const apResp = await zccClient.getWindowsAppProfiles();
      const aps = Array.isArray(apResp) ? apResp : (apResp?.list || apResp?.content || []);
      result.appProfiles = aps.map(ap => ({
        id: ap.id, name: ap.name, active: ap.active,
        deviceType: ap.deviceType || ap.device_type || 'unknown',
        hasForwardingProfile: !!(ap.onNetPolicy || ap.forwardingProfileId),
        forwardingProfileName: ap.onNetPolicy?.name || '',
        _raw: ap
      }));
      console.log(`[ZCC] Found ${result.appProfiles.length} app profiles`);
    } catch (e) {
      result.errors.push(`App profiles: ${e.message}`);
      console.log(`[ZCC] App profile fetch failed: ${e.message}`);
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Apply best practices to selected profiles
// Expects: { forwardingProfileId, appProfileId, settings: { fwd: {...}, app: {...} } }
app.post('/api/zcc/apply', requireAuth, async (req, res) => {
  try {
    const { forwardingProfileId, appProfileId, settings } = req.body;
    const { zccClient, logger } = req.session;
    if (!zccClient) return res.status(400).json({ error: 'ZCC client not initialized' });

    const results = { applied: [], errors: [], warnings: [] };

    // 1. Apply forwarding profile changes via POST edit
    if (forwardingProfileId && settings?.fwd) {
      try {
        // GET by ID endpoint returns 404, so fetch the list and find by ID
        console.log(`[ZCC] Fetching forwarding profiles to find ID: ${forwardingProfileId}`);
        const allProfiles = await zccClient.getForwardingProfiles();
        const profileList = Array.isArray(allProfiles) ? allProfiles : (allProfiles?.list || allProfiles?.content || []);
        const current = profileList.find(p => String(p.id) === String(forwardingProfileId));

        if (!current) {
          throw new Error(`Forwarding profile ID ${forwardingProfileId} not found in list of ${profileList.length} profiles`);
        }

        console.log(`[ZCC] Found forwarding profile: "${current.name}" (ID: ${current.id})`);
        console.log(`[ZCC] Merging best practices into forwarding profile`);

        // Deep clone the existing profile and merge our settings
        const merged = JSON.parse(JSON.stringify(current));

        if (settings.fwd.forwardingProfileActions) {
          merged.forwardingProfileActions = settings.fwd.forwardingProfileActions;
        }
        if (settings.fwd.forwardingProfileZpaActions) {
          merged.forwardingProfileZpaActions = settings.fwd.forwardingProfileZpaActions;
        }
        // Apply individual field overrides (skip action arrays already handled)
        for (const [key, val] of Object.entries(settings.fwd)) {
          if (key !== 'forwardingProfileActions' && key !== 'forwardingProfileZpaActions') {
            merged[key] = val;
          }
        }

        console.log(`[ZCC] POST edit forwarding profile: "${merged.name}"`);
        const fpResult = await zccClient.editForwardingProfile(merged);
        results.applied.push({ type: 'EDIT', category: 'Forwarding Profile', name: current.name, id: forwardingProfileId });
        logger.log('ZCC_APPLY', { category: 'Forwarding Profile', name: current.name, action: 'POST_EDIT', id: forwardingProfileId });
      } catch (e) {
        results.errors.push({ category: 'Forwarding Profile', name: `ID: ${forwardingProfileId}`, error: e.message });
        console.log(`[ZCC] Forwarding profile edit failed: ${e.message}`);
      }
    }

    // 2. Apply app profile changes via PATCH (only allowlisted fields)
    if (appProfileId && settings?.app) {
      try {
        // Build clean PATCH payload with only non-empty allowlisted fields
        const patchData = {};

        // Always include deviceType — likely required for PATCH
        patchData.deviceType = 3; // 3 = Windows

        // Integer/boolean toggle fields — send as integers (0/1)
        const intFields = ['disableParallelIpv4AndIPv6', 'useDefaultAdapterForDNS', 'updateDnsSearchOrder',
          'disableDNSRouteExclusion', 'enforceSplitDNS', 'bypassDNSTrafficUsingUDPProxy',
          'truncateLargeUDPDNSResponse', 'prioritizeDnsExclusions', 'groupAll'];
        for (const f of intFields) {
          if (settings.app[f] !== undefined && settings.app[f] !== '') {
            patchData[f] = settings.app[f] === true || settings.app[f] === '1' ? 1 : 0;
          }
        }

        // String fields — send if non-empty
        const strFields = ['packetTunnelExcludeList', 'packetTunnelExcludeListForIPv6',
          'packetTunnelIncludeList', 'packetTunnelIncludeListForIPv6',
          'vpnGateways', 'sourcePortBasedBypasses',
          'packetTunnelDnsExcludeList', 'packetTunnelDnsIncludeList',
          'dnsPriorityOrdering', 'dnsPriorityOrderingForTrustedDnsCriteria', 'customDNS',
          'appServiceIds', 'bypassAppIds', 'bypassCustomAppIds',
          'logoutpassword', 'uninstallpassword', 'disablepassword', 'exitPassword',
          'zdxDisablePassword', 'zdDisablePassword', 'zpaDisablePassword',
          'zdpDisablePassword', 'zccRevertPassword', 'zccFailCloseSettingsExitUninstallPassword'];
        for (const f of strFields) {
          if (settings.app[f] && settings.app[f] !== '') {
            patchData[f] = settings.app[f];
          }
        }

        // Only deviceType means no actual changes
        if (Object.keys(patchData).length <= 1) {
          results.warnings.push('App profile: No fields to patch (all values were empty)');
        } else {
          console.log(`[ZCC] PATCHing app profile ID: ${appProfileId}`);
          console.log(`[ZCC] PATCH payload: ${JSON.stringify(patchData)}`);

          try {
            const apResult = await zccClient.patchAppProfile(appProfileId, patchData);
            results.applied.push({ type: 'PATCH', category: 'App Profile', name: `ID: ${appProfileId}`, id: appProfileId });
            logger.log('ZCC_APPLY', { category: 'App Profile', action: 'PATCH', id: appProfileId, fields: Object.keys(patchData) });
          } catch (e1) {
            console.log(`[ZCC] PATCH attempt 1 failed: ${e1.message}`);
            // Attempt 2: Try without deviceType
            try {
              delete patchData.deviceType;
              console.log(`[ZCC] PATCH attempt 2 without deviceType`);
              const apResult = await zccClient.patchAppProfile(appProfileId, patchData);
              results.applied.push({ type: 'PATCH', category: 'App Profile', name: `ID: ${appProfileId}`, id: appProfileId });
              logger.log('ZCC_APPLY', { category: 'App Profile', action: 'PATCH', id: appProfileId, fallback: 'no-deviceType' });
            } catch (e2) {
              console.log(`[ZCC] PATCH attempt 2 failed: ${e2.message}`);
              results.errors.push({ category: 'App Profile', name: `ID: ${appProfileId}`, error: `PATCH failed: ${e2.message}` });
            }
          }
        }
      } catch (e) {
        results.errors.push({ category: 'App Profile', name: `ID: ${appProfileId}`, error: e.message });
        console.log(`[ZCC] App profile PATCH failed: ${e.message}`);
      }
    }

    results.summary = {
      applied: results.applied.length,
      errors: results.errors.length,
      warnings: results.warnings.length
    };

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Direct forwarding profile fetch
app.get('/api/zcc/forwarding-profiles', requireAuth, async (req, res) => {
  try {
    const { zccClient } = req.session;
    if (!zccClient) return res.status(400).json({ error: 'ZCC client not initialized' });
    const profiles = await zccClient.getForwardingProfiles();
    res.json(profiles);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Direct app profiles fetch
app.get('/api/zcc/policies', requireAuth, async (req, res) => {
  try {
    const { zccClient } = req.session;
    if (!zccClient) return res.status(400).json({ error: 'ZCC client not initialized' });
    const policies = await zccClient.getWindowsAppProfiles();
    res.json(policies);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ZCC API diagnostic
app.get('/api/zcc/diag', requireAuth, async (req, res) => {
  try {
    const { zccClient } = req.session;
    if (!zccClient) return res.status(400).json({ error: 'ZCC client not initialized' });

    const diag = { results: {} };
    try {
      const fps = await zccClient.getForwardingProfiles();
      const count = Array.isArray(fps) ? fps.length : (fps?.list?.length || 0);
      diag.results.forwardingProfiles = { status: 'OK', count };
    } catch (e) { diag.results.forwardingProfiles = { status: 'ERROR', error: e.message }; }

    try {
      const aps = await zccClient.getWindowsAppProfiles();
      const count = Array.isArray(aps) ? aps.length : (aps?.list?.length || 0);
      diag.results.appProfiles = { status: 'OK', count };
    } catch (e) { diag.results.appProfiles = { status: 'ERROR', error: e.message }; }

    res.json(diag);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ========================
// Global Error Handler
// ========================
// Catches any unhandled errors in route handlers
app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  const errMsg = `[${timestamp}] UNHANDLED ERROR: ${req.method} ${req.originalUrl} — ${err.stack || err.message}`;
  console.error(errMsg);

  // Also write to error log file
  const dateStr = timestamp.split('T')[0];
  const logFile = path.join(__dirname, '..', 'logs', `ztp-errors-${dateStr}.log`);
  try {
    fs.appendFileSync(logFile, errMsg + '\n');
  } catch (e) { /* ignore */ }

  res.status(500).json({ error: 'Internal server error. Check server logs for details.' });
});

// ========================
// SPA Fallback
// ========================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ========================
// Start Server
// ========================

const server = app.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║       ZTP Policy Wizard v${APP_VERSION} - Zscaler Template       ║
║                  Policy Configuration                   ║
╠══════════════════════════════════════════════════════════╣
║  Server running at: http://${HOST}:${PORT}                  ║
║  Auth modes: OneAPI (OAuth2) Only                       ║
║  Modules: URL | FW | SSL | Sandbox | DNS | FTC | CAC   ║
║  NEW: Mobile Admin Portal (ZCC) | OneAPI Only           ║
║  Logs: ./logs/                                          ║
║                                                          ║
║  Log files:                                              ║
║    HTTP requests: ./logs/ztp-http-YYYY-MM-DD.log         ║
║    Audit events:  ./logs/ztp-audit-YYYY-MM-DD.jsonl      ║
║    Errors:        ./logs/ztp-errors-YYYY-MM-DD.log       ║
╚══════════════════════════════════════════════════════════╝
  `);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n[FATAL] Port ${PORT} is already in use. Another process is listening on it.`);
    console.error(`  Fix: Change ZTP_PORT or stop the other process.\n`);
  } else if (err.code === 'EACCES') {
    console.error(`\n[FATAL] Permission denied binding to ${HOST}:${PORT}.`);
    console.error(`  Fix: Use a port > 1024 or run as administrator.\n`);
  } else {
    console.error(`\n[FATAL] Server failed to start:`, err.message, '\n');
  }
  process.exit(1);
});

// Log uncaught exceptions so the process doesn't die silently
process.on('uncaughtException', (err) => {
  console.error(`[UNCAUGHT EXCEPTION] ${err.stack || err.message}`);
  const logFile = path.join(__dirname, '..', 'logs', `ztp-errors-${new Date().toISOString().split('T')[0]}.log`);
  try { fs.appendFileSync(logFile, `[UNCAUGHT] ${err.stack || err.message}\n`); } catch(e) {}
});

process.on('unhandledRejection', (reason) => {
  console.error(`[UNHANDLED REJECTION] ${reason}`);
  const logFile = path.join(__dirname, '..', 'logs', `ztp-errors-${new Date().toISOString().split('T')[0]}.log`);
  try { fs.appendFileSync(logFile, `[UNHANDLED_REJECTION] ${reason}\n`); } catch(e) {}
});

module.exports = app;
