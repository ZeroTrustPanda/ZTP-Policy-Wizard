/**
 * ZIA API Client - Supports both Legacy API and OneAPI (OAuth2) authentication
 * 
 * Legacy: Uses username/password/apiKey with obfuscation
 * OneAPI: Uses OAuth2 client_credentials flow via ZIdentity
 */

const https = require('https');
const http = require('http');

// ZIA Cloud base URLs
const ZIA_CLOUDS = {
  'zscaler':      'zsapi.zscaler.net',
  'zscalerone':   'zsapi.zscalerone.net',
  'zscalertwo':   'zsapi.zscalertwo.net',
  'zscalerthree': 'zsapi.zscalerthree.net',
  'zscloud':      'zsapi.zscloud.net',
  'zscalerbeta':  'zsapi.zscalerbeta.net',
  'zscalergov':   'zsapi.zscalergov.net',
  'zscalerten':   'zsapi.zscalerten.net'
};

// ZIA Admin portal URLs (for legacy auth)
const ZIA_ADMIN_URLS = {
  'zscaler':      'admin.zscaler.net',
  'zscalerone':   'admin.zscalerone.net',
  'zscalertwo':   'admin.zscalertwo.net',
  'zscalerthree': 'admin.zscalerthree.net',
  'zscloud':      'admin.zscloud.net',
  'zscalerbeta':  'admin.zscalerbeta.net',
  'zscalergov':   'admin.zscalergov.net',
  'zscalerten':   'admin.zscalerten.net'
};

// OneAPI endpoint
const ONEAPI_BASE = 'api.zsapi.net';
const ZIDENTITY_TOKEN_PATH = '/oauth2/v1/token';

class ZIAClient {
  constructor() {
    this.authMode = null; // 'legacy' or 'oneapi'
    this.sessionCookie = null;
    this.accessToken = null;
    this.tokenExpiry = null;
    this.cloud = null;
    this.baseUrl = null;
    this.adminUrl = null;
    this.vanityDomain = null;
    this.credentials = null;
  }

  /**
   * Obfuscate API key for legacy authentication
   */
  static obfuscateApiKey(apiKey) {
    const now = Date.now();
    const n = String(now).slice(-6);
    const r = String(parseInt(n) >> 1).padStart(6, '0');
    let key = '';
    for (let i = 0; i < n.length; i++) {
      key += apiKey[parseInt(n[i])];
    }
    for (let j = 0; j < r.length; j++) {
      key += apiKey[parseInt(r[j]) + 2];
    }
    return { timestamp: now, key };
  }

  /**
   * Initialize with Legacy API credentials
   */
  async authenticateLegacy({ username, password, apiKey, cloud }) {
    this.authMode = 'legacy';
    this.cloud = cloud;
    this.baseUrl = ZIA_ADMIN_URLS[cloud] || cloud;
    this.adminUrl = this.baseUrl;
    this.credentials = { username, password, apiKey, cloud };

    const { timestamp, key } = ZIAClient.obfuscateApiKey(apiKey);

    const payload = JSON.stringify({
      apiKey: key,
      username,
      password,
      timestamp
    });

    const response = await this._request('POST', '/api/v1/authenticatedSession', payload, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache'
    }, true);

    if (response.statusCode === 200) {
      // Extract JSESSIONID from Set-Cookie header
      const cookies = response.headers['set-cookie'];
      if (cookies) {
        for (const cookie of cookies) {
          const match = cookie.match(/JSESSIONID=([^;]+)/);
          if (match) {
            this.sessionCookie = match[1];
            break;
          }
        }
      }
      if (!this.sessionCookie) {
        throw new Error('Authentication succeeded but no session cookie received');
      }
      return { success: true, authType: response.body.authType };
    } else {
      throw new Error(`Legacy authentication failed: ${response.statusCode} - ${JSON.stringify(response.body)}`);
    }
  }

  /**
   * Initialize with OneAPI OAuth2 credentials
   * 
   * Token endpoint format:
   *   Production: https://{vanityDomain}.zslogin.net/oauth2/v1/token
   *   Non-prod:   https://{vanityDomain}.{cloud}.zslogin.net/oauth2/v1/token
   */
  async authenticateOneAPI({ clientId, clientSecret, vanityDomain, cloud }) {
    this.authMode = 'oneapi';
    this.cloud = cloud || 'production';
    this.vanityDomain = vanityDomain;
    this.credentials = { clientId, clientSecret, vanityDomain, cloud };

    // Build the token hostname
    // Production:  {vanity}.zslogin.net
    // Beta/Alpha:  {vanity}.{cloud}.zslogin.net
    let tokenHost;
    if (!cloud || cloud === 'production' || cloud === '') {
      tokenHost = `${vanityDomain}.zslogin.net`;
    } else {
      tokenHost = `${vanityDomain}.${cloud}.zslogin.net`;
    }

    // Build the API base URL
    // Production:  api.zsapi.net
    // Non-prod:    api.{cloud}.zsapi.net
    if (!cloud || cloud === 'production' || cloud === '') {
      this.baseUrl = ONEAPI_BASE;  // api.zsapi.net
    } else {
      this.baseUrl = `api.${cloud}.zsapi.net`;
    }

    console.log(`[ONEAPI] Token endpoint: https://${tokenHost}${ZIDENTITY_TOKEN_PATH}`);
    console.log(`[ONEAPI] API base URL:   https://${this.baseUrl}`);
    console.log(`[ONEAPI] Client ID:      ${clientId.substring(0, 8)}...`);

    const payload = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret
    }).toString();

    const response = await this._rawRequest('POST', tokenHost, ZIDENTITY_TOKEN_PATH, payload, {
      'Content-Type': 'application/x-www-form-urlencoded'
    });

    console.log(`[ONEAPI] Token response: ${response.statusCode}`);

    if (response.statusCode === 200) {
      const tokenData = response.body;
      this.accessToken = tokenData.access_token;
      this.tokenExpiry = Date.now() + (tokenData.expires_in * 1000);
      return { success: true, tokenType: tokenData.token_type, expiresIn: tokenData.expires_in };
    } else {
      console.error(`[ONEAPI] Token error body: ${JSON.stringify(response.body)}`);
      
      // Provide actionable error messages
      let hint = '';
      const errBody = response.body;
      if (typeof errBody === 'object' && errBody.error === 'invalid_client') {
        hint = '\n  Possible causes:'
          + '\n  1. Client ID or Client Secret is incorrect (re-copy from ZIdentity)'
          + '\n  2. Vanity domain is wrong (check your ZIdentity portal URL)'
          + '\n  3. API client is disabled or expired in ZIdentity → Integration → API Clients'
          + '\n  4. API client has no ZIA scopes assigned (ZIdentity → API Resources → Zscaler APIs → ZIA)'
          + `\n  5. Wrong cloud — currently targeting: ${tokenHost}`;
      }
      
      throw new Error(`OneAPI authentication failed: ${response.statusCode} - ${JSON.stringify(response.body)}${hint}`);
    }
  }

  /**
   * Check if session/token is still valid
   */
  isAuthenticated() {
    if (this.authMode === 'legacy') {
      return !!this.sessionCookie;
    } else if (this.authMode === 'oneapi') {
      return !!this.accessToken && Date.now() < this.tokenExpiry;
    }
    return false;
  }

  /**
   * Logout / end session
   */
  async logout() {
    if (this.authMode === 'legacy' && this.sessionCookie) {
      try {
        await this.apiCall('DELETE', '/api/v1/authenticatedSession');
      } catch (e) {
        // Ignore logout errors
      }
      this.sessionCookie = null;
    }
    this.accessToken = null;
    this.tokenExpiry = null;
  }

  /**
   * Activate changes (required after making configuration changes)
   */
  async activateChanges() {
    return this.apiCall('POST', '/api/v1/status/activate');
  }

  /**
   * Get activation status
   */
  async getActivationStatus() {
    return this.apiCall('GET', '/api/v1/status');
  }

  // ========================
  // ZIA API Endpoints
  // Paths use /api/v1/ — the apiCall method prepends /zia for OneAPI
  // Correct paths based on Zscaler SDK and Terraform provider source
  // ========================

  // --- URL Filtering Rules ---
  async getUrlFilteringRules() {
    return this.apiCall('GET', '/api/v1/urlFilteringRules');
  }

  async createUrlFilteringRule(rule) {
    return this.apiCall('POST', '/api/v1/urlFilteringRules', rule);
  }

  async updateUrlFilteringRule(ruleId, rule) {
    return this.apiCall('PUT', `/api/v1/urlFilteringRules/${ruleId}`, rule);
  }

  // --- URL Categories ---
  async getUrlCategories(customOnly = false) {
    const path = customOnly ? '/api/v1/urlCategories?customOnly=true' : '/api/v1/urlCategories';
    return this.apiCall('GET', path);
  }

  async createUrlCategory(category) {
    return this.apiCall('POST', '/api/v1/urlCategories', category);
  }

  async updateUrlCategory(categoryId, category) {
    return this.apiCall('PUT', `/api/v1/urlCategories/${categoryId}`, category);
  }

  // --- Security Policy ---
  async getSecurityBlacklist() {
    return this.apiCall('GET', '/api/v1/security/advanced');
  }

  async updateSecurityBlacklist(urls) {
    return this.apiCall('PUT', '/api/v1/security/advanced', urls);
  }

  async getSecurityWhitelist() {
    return this.apiCall('GET', '/api/v1/security');
  }

  async updateSecurityWhitelist(urls) {
    return this.apiCall('PUT', '/api/v1/security', urls);
  }

  // --- Firewall Filtering Rules ---
  // Note: Endpoint is /firewallFilteringRules (not /firewallRules)
  async getFirewallRules() {
    return this.apiCall('GET', '/api/v1/firewallFilteringRules');
  }

  async createFirewallRule(rule) {
    return this.apiCall('POST', '/api/v1/firewallFilteringRules', rule);
  }

  async updateFirewallRule(ruleId, rule) {
    return this.apiCall('PUT', `/api/v1/firewallFilteringRules/${ruleId}`, rule);
  }

  // --- Network Services ---
  async getNetworkServices() {
    return this.apiCall('GET', '/api/v1/networkServices');
  }

  // --- Network Application Groups ---
  async getNetworkApplicationGroups() {
    return this.apiCall('GET', '/api/v1/networkApplicationGroups');
  }

  // --- SSL Inspection Rules ---
  async getSslInspectionRules() {
    return this.apiCall('GET', '/api/v1/sslInspectionRules');
  }

  async createSslInspectionRule(rule) {
    return this.apiCall('POST', '/api/v1/sslInspectionRules', rule);
  }

  async updateSslInspectionRule(ruleId, rule) {
    return this.apiCall('PUT', `/api/v1/sslInspectionRules/${ruleId}`, rule);
  }

  // --- Web DLP Rules (webDlpRules) ---
  async getWebDlpRules() {
    return this.apiCall('GET', '/api/v1/webDlpRules');
  }

  async createWebDlpRule(rule) {
    return this.apiCall('POST', '/api/v1/webDlpRules', rule);
  }

  async deleteWebDlpRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/webDlpRules/${ruleId}`);
  }

  // --- DLP Engines (predefined + custom) ---
  async getDlpEngines() {
    return this.apiCall('GET', '/api/v1/dlpEngines');
  }

  async getDlpEngineLite() {
    return this.apiCall('GET', '/api/v1/dlpEngines/lite');
  }

  async createCustomDlpEngine(engine) {
    return this.apiCall('POST', '/api/v1/dlpEngines', engine);
  }

  async deleteCustomDlpEngine(engineId) {
    return this.apiCall('DELETE', `/api/v1/dlpEngines/${engineId}`);
  }

  // --- DLP Dictionaries ---
  async getDlpDictionaries() {
    return this.apiCall('GET', '/api/v1/dlpDictionaries');
  }

  // --- DLP Notification Templates ---
  async getDlpNotificationTemplates() {
    return this.apiCall('GET', '/api/v1/dlpNotificationTemplates');
  }

  // --- DLP Incident Receiver ---
  async getDlpIncidentReceiverServers() {
    return this.apiCall('GET', '/api/v1/incidentReceiverServers');
  }

  // --- Sandbox (BA) Rules ---
  async getSandboxRules() {
    return this.apiCall('GET', '/api/v1/sandboxRules');
  }

  async createSandboxRule(rule) {
    return this.apiCall('POST', '/api/v1/sandboxRules', rule);
  }

  async deleteSandboxRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/sandboxRules/${ruleId}`);
  }

  // --- Cloud App Control (Web Application Rules) ---
  // The rule_type path parameter selects the category
  async getCloudAppControlRules(ruleType = 'AI_ML') {
    return this.apiCall('GET', `/api/v1/webApplicationRules/${ruleType}`);
  }

  async createCloudAppControlRule(ruleType, rule) {
    return this.apiCall('POST', `/api/v1/webApplicationRules/${ruleType}`, rule);
  }

  async deleteCloudAppControlRule(ruleType, ruleId) {
    return this.apiCall('DELETE', `/api/v1/webApplicationRules/${ruleType}/${ruleId}`);
  }

  // --- DNS Control (Firewall DNS) Rules ---
  async getDnsControlRules() {
    return this.apiCall('GET', '/api/v1/firewallDnsRules');
  }

  async createDnsControlRule(rule) {
    return this.apiCall('POST', '/api/v1/firewallDnsRules', rule);
  }

  async deleteDnsControlRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/firewallDnsRules/${ruleId}`);
  }

  // --- File Type Control Rules ---
  async getFileTypeRules() {
    return this.apiCall('GET', '/api/v1/fileTypeRules');
  }

  async createFileTypeRule(rule) {
    return this.apiCall('POST', '/api/v1/fileTypeRules', rule);
  }

  async deleteFileTypeRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/fileTypeRules/${ruleId}`);
  }

  // --- Delete methods for existing rule types ---
  async deleteUrlFilteringRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/urlFilteringRules/${ruleId}`);
  }

  async deleteFirewallRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/firewallFilteringRules/${ruleId}`);
  }

  async deleteSslInspectionRule(ruleId) {
    return this.apiCall('DELETE', `/api/v1/sslInspectionRules/${ruleId}`);
  }

  // --- Locations ---
  async getLocations() {
    return this.apiCall('GET', '/api/v1/locations');
  }

  // --- Admin Audit Logs ---
  async getAuditLogs(startTime, endTime) {
    return this.apiCall('GET', `/api/v1/auditlogEntryReport?startTime=${startTime}&endTime=${endTime}`);
  }

  // ========================
  // HTTP Transport with Rate Limiting + Retry
  // ========================

  /**
   * Sleep helper for rate limiting
   */
  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async apiCall(method, path, body = null, retryCount = 0) {
    // Rate limiting: enforce minimum 1.1 seconds between requests
    const now = Date.now();
    if (this._lastRequestTime && (now - this._lastRequestTime) < 1100) {
      const waitMs = 1100 - (now - this._lastRequestTime);
      await this._sleep(waitMs);
    }
    this._lastRequestTime = Date.now();

    const headers = {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-cache'
    };

    if (this.authMode === 'legacy') {
      headers['Cookie'] = `JSESSIONID=${this.sessionCookie}`;
    } else if (this.authMode === 'oneapi') {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    const payload = body ? JSON.stringify(body) : null;
    
    let fullPath;
    let host;
    if (this.authMode === 'oneapi') {
      fullPath = `/zia${path}`;
      host = this.baseUrl;
    } else {
      fullPath = path;
      host = this.baseUrl;
    }

    console.log(`[API] ${method} https://${host}${fullPath}`);
    if (payload && method !== 'GET') {
      // Log truncated request body for debugging
      const bodyPreview = payload.length > 2000 ? payload.substring(0, 2000) + '...' : payload;
      console.log(`[API] Request body: ${bodyPreview}`);
    }

    const response = await this._rawRequest(method, host, fullPath, payload, headers);

    console.log(`[API] Response: ${response.statusCode}`);
    if (response.statusCode >= 400) {
      const respPreview = typeof response.body === 'string' 
        ? response.body.substring(0, 300) 
        : JSON.stringify(response.body).substring(0, 300);
      console.error(`[API] Error body: ${respPreview}`);
    }

    // Handle rate limiting with retry
    if (response.statusCode === 429 && retryCount < 5) {
      let retryAfter = 2; // default 2 seconds
      if (response.headers && response.headers['retry-after']) {
        retryAfter = parseInt(response.headers['retry-after']) || 2;
      } else if (response.headers && response.headers['x-ratelimit-reset']) {
        retryAfter = parseInt(response.headers['x-ratelimit-reset']) || 2;
      }
      console.log(`[API] Rate limited (429). Retrying in ${retryAfter}s (attempt ${retryCount + 1}/5)`);
      await this._sleep(retryAfter * 1000);
      return this.apiCall(method, path, body, retryCount + 1);
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      return response.body;
    }
    throw new Error(`API Error ${response.statusCode}: ${JSON.stringify(response.body)}`);
  }

  _request(method, path, payload, headers, parseJson = true) {
    return this._rawRequest(method, this.baseUrl, path, payload, headers, parseJson);
  }

  _rawRequest(method, host, path, payload, headers, parseJson = true) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: host,
        port: 443,
        path,
        method,
        headers: { ...headers },
        rejectUnauthorized: true
      };

      if (payload) {
        options.headers['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          let body = data;
          if (parseJson && data) {
            try { body = JSON.parse(data); } catch (e) { /* keep as string */ }
          }
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body
          });
        });
      });

      req.on('error', reject);
      req.setTimeout(30000, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      if (payload) {
        req.write(payload);
      }
      req.end();
    });
  }
}

module.exports = { ZIAClient, ZIA_CLOUDS, ZIA_ADMIN_URLS };
