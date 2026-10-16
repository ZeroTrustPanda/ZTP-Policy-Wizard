/**
 * ZCC API Client - Zscaler Client Connector API
 * 
 * Routes through OneAPI gateway: api.zsapi.net/zcc/papi/public/v1/...
 * Uses the same Bearer token as ZIA.
 * 
 * v1.6.0: create / full update / delete of Windows app profiles verified against a live tenant.
 *
 * v1.5.1 Workflow:
 *   1. GET existing profiles (user creates dummy profiles manually first)
 *   2. Show checkboxes for which settings to apply
 *   3. PATCH app profiles (only allowlisted fields)
 *   4. POST forwarding profile edit (full profile from GET merged with changes)
 */

class ZCCClient {
  constructor(ziaClient) {
    this.ziaClient = ziaClient;
  }

  async apiCall(method, path, body = null, attempt = 0) {
    // v2.0: the ZCC API allows about 100 calls per hour, so identical reads within 2 minutes are served from
    // memory (per session). Any write clears the cache so a read after a write is always fresh.
    this._cache = this._cache || new Map();
    if (method === 'GET' && !attempt) {
      const hit = this._cache.get(path);
      if (hit && Date.now() - hit.at < 120000) return JSON.parse(JSON.stringify(hit.body));
    } else if (method !== 'GET') this._cache.clear();
    const result = await this._apiCall(method, path, body, attempt);
    if (method === 'GET') this._cache.set(path, { at: Date.now(), body: JSON.parse(JSON.stringify(result === undefined ? null : result)) });
    return result;
  }

  async _apiCall(method, path, body = null, attempt = 0) {
    if (!this.ziaClient || !this.ziaClient.isAuthenticated()) {
      throw new Error('Not authenticated. ZCC API requires OneAPI authentication.');
    }
    if (this.ziaClient.authMode !== 'oneapi') {
      throw new Error('ZCC API requires OneAPI (OAuth2) authentication.');
    }

    const host = this.ziaClient.baseUrl;

    // Rate limiting
    const now = Date.now();
    if (this.ziaClient._lastRequestTime && (now - this.ziaClient._lastRequestTime) < 1100) {
      const waitMs = 1100 - (now - this.ziaClient._lastRequestTime);
      await this.ziaClient._sleep(waitMs);
    }
    this.ziaClient._lastRequestTime = Date.now();

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Cache-Control': 'no-cache',
      'Authorization': `Bearer ${this.ziaClient.accessToken}`
    };

    const payload = body ? JSON.stringify(body) : null;

    console.log(`[ZCC-API] ${method} https://${host}${path}`);
    if (payload && method !== 'GET') {
      const bodyPreview = payload.length > 2000 ? payload.substring(0, 2000) + '...' : payload;
      console.log(`[ZCC-API] Request body: ${bodyPreview}`);
    }

    const response = await this.ziaClient._rawRequest(method, host, path, payload, headers);

    console.log(`[ZCC-API] Response: ${response.statusCode}`);
    if (response.statusCode >= 400) {
      const respPreview = typeof response.body === 'string'
        ? response.body.substring(0, 500)
        : JSON.stringify(response.body).substring(0, 500);
      console.error(`[ZCC-API] Error body: ${respPreview}`);
    }

    if (response.statusCode === 429) {
      let retryAfter = 2;
      if (response.headers?.['retry-after']) retryAfter = parseInt(response.headers['retry-after']) || 2;
      // v2.0: never sleep for minutes inside a request. Short waits are retried (3 times); long ones are reported.
      const next = attempt + 1;
      if (retryAfter > 30 || next > 3) {
        const mins = Math.max(1, Math.ceil(retryAfter / 60));
        throw new Error(`ZCC API rate limit reached (HTTP 429). The Client Connector API allows about 100 calls per hour; Zscaler asks to wait about ${mins} minute${mins === 1 ? '' : 's'}. Nothing else was changed; run the dry run again later.`);
      }
      console.log(`[ZCC-API] Rate limited. Retrying in ${retryAfter}s (attempt ${next})`);
      await this.ziaClient._sleep(retryAfter * 1000);
      return this._apiCall(method, path, body, next);
    }

    if (response.statusCode >= 200 && response.statusCode < 300) {
      return response.body;
    }
    throw new Error(`ZCC API Error ${response.statusCode}: ${JSON.stringify(response.body)}`);
  }

  // ========================
  // Forwarding Profiles
  // ========================

  async getForwardingProfiles() {
    return this.apiCall('GET', '/zcc/papi/public/v1/webForwardingProfile/listByCompany');
  }

  async getForwardingProfile(id) {
    return this.apiCall('GET', `/zcc/papi/public/v1/webForwardingProfile/${id}`);
  }

  // POST edit — updates a forwarding profile (full object from GET merged with changes)
  async editForwardingProfile(profile) {
    const resp = await this.apiCall('POST', '/zcc/papi/public/v1/webForwardingProfile/edit', profile);
    return ZCCClient.assertSuccess(resp, `Edit forwarding profile "${profile.name}"`);
  }

  // CREATE a forwarding profile (v1.7.0). Verified on ZTH 2026-10-11: the same POST /edit
  // endpoint creates when the body carries id "-1" (what the portal sends); without it ZCC
  // answers HTTP 400 with an empty body. Returns {success:"true", id}.
  async createForwardingProfile(body) {
    const resp = await this.apiCall('POST', '/zcc/papi/public/v1/webForwardingProfile/edit', { ...body, id: '-1' });
    return ZCCClient.assertSuccess(resp, `Create forwarding profile "${body.name}"`);
  }

  // DELETE a forwarding profile (verified 2026-10-11)
  async deleteForwardingProfile(id) {
    const resp = await this.apiCall('DELETE', `/zcc/papi/public/v1/webForwardingProfile/${id}/delete`);
    return ZCCClient.assertSuccess(resp, `Delete forwarding profile ${id}`);
  }

  // ========================
  // App Profiles (Application Profiles)
  // ========================

  async getAppProfiles(deviceType) {
    let path = '/zcc/papi/public/v1/web/policy/listByCompany';
    if (deviceType) path += `?deviceType=${deviceType}`;
    return this.apiCall('GET', path);
  }

  async getWindowsAppProfiles() {
    return this.getAppProfiles(3); // 3 = Windows
  }

  // ZCC write endpoints answer HTTP 200 with {"success":"false"} when they reject a body.
  // Treat that as an error so callers never report a silent failure as success.
  static assertSuccess(resp, what) {
    if (resp && typeof resp === 'object' && (resp.success === 'false' || resp.success === false)) {
      const err = new Error(`${what} was rejected by ZCC (HTTP 200, success:false). The payload shape is not accepted.`);
      err.zccResponse = resp;
      throw err;
    }
    return resp;
  }

  // IP-based app bypass definitions (Teams, Zoom, M365, ...)
  async getWebAppServices() {
    return this.apiCall('GET', '/zcc/papi/public/v1/webAppService/listByCompany');
  }

  // GET a single app profile (newer API, richest shape)
  async getApplicationProfile(profileId) {
    return this.apiCall('GET', `/zcc/papi/public/v1/application-profiles/${profileId}`);
  }

  // PATCH — update allowlisted fields on an app profile by ID.
  // Verified on ZTH 2026-10-09: body MUST include policyId + deviceType, and settings must be
  // nested where they live (e.g. { policyExtension: { sourcePortBasedBypasses: '...' } }).
  async patchAppProfile(profileId, patchData) {
    const body = { ...patchData, policyId: Number(profileId), deviceType: patchData.deviceType || 3 };
    const resp = await this.apiCall('PATCH', `/zcc/papi/public/v1/application-profiles/${profileId}`, body);
    return ZCCClient.assertSuccess(resp, `PATCH app profile ${profileId}`);
  }

  // CREATE or full UPDATE (when body.id is set) via PUT /web/policy/edit.
  // Verified on ZTH 2026-10-09: only the full portal-shaped body is accepted
  // (see zcc-windows-profile-template.json). Minimal / SDK-shaped bodies return success:false.
  async saveAppProfile(fullBody) {
    const resp = await this.apiCall('PUT', '/zcc/papi/public/v1/web/policy/edit', fullBody);
    return ZCCClient.assertSuccess(resp, fullBody.id ? `Update app profile ${fullBody.id}` : `Create app profile "${fullBody.name}"`);
  }

  // DELETE an app profile. Verified on ZTH 2026-10-09.
  async deleteAppProfile(profileId) {
    const resp = await this.apiCall('DELETE', `/zcc/papi/public/v1/web/policy/${profileId}/delete`);
    return ZCCClient.assertSuccess(resp, `Delete app profile ${profileId}`);
  }

  // Enable / disable an app profile
  async activateAppProfile(profileId, active, deviceType = 3) {
    const resp = await this.apiCall('PUT', '/zcc/papi/public/v1/web/policy/activate', { policyId: Number(profileId), deviceType, active: active ? 1 : 0 });
    return ZCCClient.assertSuccess(resp, `Activate app profile ${profileId}`);
  }

  // Legacy PUT edit (kept for fallback)
  async editPolicy(policy) {
    return this.apiCall('PUT', '/zcc/papi/public/v1/web/policy/edit', policy);
  }
}

module.exports = { ZCCClient };
