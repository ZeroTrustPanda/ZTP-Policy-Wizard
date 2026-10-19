/**
 * v2.2: rate-limit bookkeeping for the Client Connector and ZDX APIs (about 100 calls per hour per API client).
 * Calls are counted in a rolling hour. When Zscaler answers 429 with a long Retry-After, the product is marked
 * blocked until then: further calls fail fast with err.rateLimitedUntil (the browser shows a countdown and retries
 * the step on its own when the time is up) instead of hammering the API.
 */
'use strict';
const HOUR = 3600e3;

class RateGate {
  constructor(product, budget = 100) { this.product = product; this.budget = budget; this.calls = []; this.blockedUntil = 0; }
  _trim() { const cut = Date.now() - HOUR; while (this.calls.length && this.calls[0] < cut) this.calls.shift(); }
  error(until) {
    const secs = Math.max(1, Math.ceil((until - Date.now()) / 1000));
    const mins = Math.ceil(secs / 60);
    const e = new Error(`${this.product} API rate limit reached. The ${this.product} API allows about ${this.budget} calls per hour; the wizard waits about ${mins} minute${mins === 1 ? '' : 's'} and then carries on. Nothing else was changed.`);
    e.rateLimitedUntil = new Date(until).toISOString(); e.product = this.product; e.status = 429;
    return e;
  }
  /** Before each request: fail fast while blocked; count the call. */
  before() {
    if (this.blockedUntil > Date.now()) throw this.error(this.blockedUntil);
    this._trim(); this.calls.push(Date.now());
  }
  /** After a 429 with a long wait. */
  limited(retryAfterSeconds) { this.blockedUntil = Date.now() + Math.max(1, retryAfterSeconds) * 1000; return this.error(this.blockedUntil); }
  status() {
    this._trim();
    const blocked = this.blockedUntil > Date.now();
    return { product: this.product, usedLastHour: this.calls.length, budget: this.budget, remaining: Math.max(0, this.budget - this.calls.length),
      blockedUntil: blocked ? new Date(this.blockedUntil).toISOString() : null,
      // when the oldest counted call drops out of the window
      nextFreeAt: this.calls.length >= this.budget ? new Date(this.calls[0] + HOUR).toISOString() : null };
  }
}

/** One gate per product per signed-in client (the limit is per API client). */
function gate(ziaClient, product) {
  ziaClient._rateGates = ziaClient._rateGates || {};
  if (!ziaClient._rateGates[product]) ziaClient._rateGates[product] = new RateGate(product);
  return ziaClient._rateGates[product];
}

module.exports = { RateGate, gate };
