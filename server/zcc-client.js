/**
 * ZCC API Client - Zscaler Client Connector API
 * 
 * Routes through OneAPI gateway: api.zsapi.net/zcc/papi/public/v1/...
 * Uses the same Bearer token as ZIA.
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

  async apiCall(method, path, body = null) {
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
      console.log(`[ZCC-API] Rate limited. Retrying in ${retryAfter}s`);
      await this.ziaClient._sleep(retryAfter * 1000);
      return this.apiCall(method, path, body);
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
    return this.apiCall('POST', '/zcc/papi/public/v1/webForwardingProfile/edit', profile);
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

  // PATCH — update only allowlisted fields on an app profile by ID
  async patchAppProfile(profileId, patchData) {
    return this.apiCall('PATCH', `/zcc/papi/public/v1/application-profiles/${profileId}`, patchData);
  }

  // Legacy PUT edit (kept for fallback)
  async editPolicy(policy) {
    return this.apiCall('PUT', '/zcc/papi/public/v1/web/policy/edit', policy);
  }
}

module.exports = { ZCCClient };
