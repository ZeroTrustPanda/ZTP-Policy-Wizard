/**
 * ZDX API Client - Zscaler Digital Experience configuration API (v1.8.0)
 *
 * Routes through the OneAPI gateway (api.zsapi.net/zdx/v1/config/...) with the same
 * Bearer token as ZIA / ZCC. Verified against a live tenant 2026-10-12:
 *
 *   Apps        GET  /config/applications                      configured apps (custom, network, predefined)
 *               GET  /config/applications/supported?type=PREDEFINED   predefined catalog (id -1 = not set up yet)
 *               POST /config/applications                      create; needs collection {id, name};
 *                                                              custom apps must be created inactive;
 *                                                              predefined apps need `prefix` and get
 *                                                              Zscaler's own Web + CloudPath probes (inactive)
 *               PUT  /config/applications/{key}/activate|deactivate
 *               DELETE /config/applications/{id}               custom/network only (predefined -> 403)
 *   Monitors    GET  /config/applications/{key}/monitors
 *               POST /config/applications/{key}/monitors       WEB (url) / TRACERT (host, followWebMonitor {id})
 *               PUT  /config/applications/{key}/monitors/{mid}/activate|deactivate
 *               DELETE /config/applications/{key}/monitors/{mid}
 *               GET  /config/monitors                          every monitor in the tenant
 *   Collections GET  /config/collections
 *               POST /config/collections                       {name, type END_USER, active, description}
 *                                                              (new ZDX tenants have no "Custom Apps Collection"
 *                                                              until the first custom app is added)
 *               DELETE /config/collections/{id}
 *
 * {key} is the numeric app id for custom/network apps and the provider name
 * (e.g. MICROSOFT_LOGIN) for predefined apps.
 */

class ZDXClient {
  constructor(ziaClient) {
    this.ziaClient = ziaClient;
  }

  async apiCall(method, path, body = null) {
    if (!this.ziaClient || !this.ziaClient.isAuthenticated()) {
      throw new Error('Not authenticated. The ZDX API requires OneAPI authentication.');
    }
    if (this.ziaClient.authMode !== 'oneapi') {
      throw new Error('The ZDX API requires OneAPI (OAuth2) authentication.');
    }
    const host = this.ziaClient.baseUrl;

    const now = Date.now();
    if (this.ziaClient._lastRequestTime && (now - this.ziaClient._lastRequestTime) < 1100) {
      await this.ziaClient._sleep(1100 - (now - this.ziaClient._lastRequestTime));
    }
    this.ziaClient._lastRequestTime = Date.now();

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Cache-Control': 'no-cache',
      'Authorization': `Bearer ${this.ziaClient.accessToken}`
    };
    const payload = body ? JSON.stringify(body) : null;
    const fullPath = `/zdx/v1${path}`;
    console.log(`[ZDX-API] ${method} https://${host}${fullPath}`);
    if (payload && method !== 'GET') console.log(`[ZDX-API] Request body: ${payload.length > 1500 ? payload.substring(0, 1500) + '...' : payload}`);

    const response = await this.ziaClient._rawRequest(method, host, fullPath, payload, headers);
    console.log(`[ZDX-API] Response: ${response.statusCode}`);

    if (response.statusCode === 429) {
      let retryAfter = 2;
      if (response.headers?.['retry-after']) retryAfter = parseInt(response.headers['retry-after']) || 2;
      await this.ziaClient._sleep(retryAfter * 1000);
      return this.apiCall(method, path, body);
    }
    if (response.statusCode >= 200 && response.statusCode < 300) return response.body;

    // ZDX answers errors as {"code": "...", "message": "..."}; surface them readably
    let b = response.body;
    if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { /* keep text */ } }
    const msg = b && typeof b === 'object' ? [b.code, b.message].filter(Boolean).join(': ') : String(b || '').substring(0, 300);
    console.error(`[ZDX-API] Error: ${msg}`);
    const err = new Error(`ZDX ${response.statusCode}${msg ? ` — ${msg}` : ''}`);
    err.status = response.statusCode;
    err.zdxCode = b && b.code;
    err.zdxMessage = b && b.message;
    throw err;
  }

  static list(resp) {
    return Array.isArray(resp) ? resp : (resp?.items || resp?.list || resp?.content || []);
  }

  // Applications
  listApps() { return this.apiCall('GET', '/config/applications').then(ZDXClient.list); }
  listSupported(type = 'PREDEFINED') { return this.apiCall('GET', `/config/applications/supported?type=${encodeURIComponent(type)}`).then(ZDXClient.list); }
  getApp(key) { return this.apiCall('GET', `/config/applications/${encodeURIComponent(key)}`); }
  createApp(body) { return this.apiCall('POST', '/config/applications', body); }
  activateApp(key) { return this.apiCall('PUT', `/config/applications/${encodeURIComponent(key)}/activate`); }
  deactivateApp(key) { return this.apiCall('PUT', `/config/applications/${encodeURIComponent(key)}/deactivate`); }
  deleteApp(id) { return this.apiCall('DELETE', `/config/applications/${encodeURIComponent(id)}`); }

  // Monitors (probes)
  listAllMonitors() { return this.apiCall('GET', '/config/monitors').then(ZDXClient.list); }
  listAppMonitors(key) { return this.apiCall('GET', `/config/applications/${encodeURIComponent(key)}/monitors`).then(ZDXClient.list); }
  createMonitor(key, body) { return this.apiCall('POST', `/config/applications/${encodeURIComponent(key)}/monitors`, body); }
  activateMonitor(key, mid) { return this.apiCall('PUT', `/config/applications/${encodeURIComponent(key)}/monitors/${encodeURIComponent(mid)}/activate`); }
  deactivateMonitor(key, mid) { return this.apiCall('PUT', `/config/applications/${encodeURIComponent(key)}/monitors/${encodeURIComponent(mid)}/deactivate`); }
  deleteMonitor(key, mid) { return this.apiCall('DELETE', `/config/applications/${encodeURIComponent(key)}/monitors/${encodeURIComponent(mid)}`); }

  // Collections
  listCollections() { return this.apiCall('GET', '/config/collections').then(ZDXClient.list); }
  createCollection(body) { return this.apiCall('POST', '/config/collections', body); }
  deleteCollection(id) { return this.apiCall('DELETE', `/config/collections/${encodeURIComponent(id)}`); }
}

module.exports = { ZDXClient };
