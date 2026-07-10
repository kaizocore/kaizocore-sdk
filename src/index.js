/**
 * KaizoCore SDK — client-side loader (npm / bundler usage)
 *
 * For most sites, the plain script tag is all you need:
 *   <script src="https://cdn.kaizocore.com/l.js?k=pk_live_xxx" defer></script>
 *
 * Use this module when you need programmatic control from a bundler:
 *   import { KaizoCore } from '@kaizocore/sdk'
 *   const kz = new KaizoCore({ apiKey: 'pk_live_xxx' })
 *   await kz.settle()
 */

const CDN_URL = 'https://cdn.kaizocore.com';

export class KaizoCore {
  constructor({ apiKey, cdnUrl = CDN_URL } = {}) {
    if (!apiKey || !apiKey.startsWith('pk_live_')) {
      throw new Error('KaizoCore: apiKey must start with pk_live_');
    }
    this._key = apiKey;
    this._cdn = cdnUrl;
    this._scriptLoading = null;
  }

  /**
   * _loadScript() — injects l.js into the page if it hasn't been loaded yet.
   * Idempotent: calling it multiple times returns the same Promise.
   */
  _loadScript() {
    if (this._scriptLoading) return this._scriptLoading;

    this._scriptLoading = new Promise((resolve, reject) => {
      // Don't inject twice if the tag is already in the DOM
      const existing = document.querySelector(
        `script[src*="${this._cdn}/l.js"]`
      );
      if (existing && window.__kz) {
        resolve();
        return;
      }

      const script = document.createElement('script');
      script.src = `${this._cdn}/l.js?k=${encodeURIComponent(this._key)}`;
      script.async = true;
      script.onload = () => resolve();
      script.onerror = () => {
        this._scriptLoading = null; // allow retry
        reject(new Error('KaizoCore: failed to load SDK script from CDN'));
      };
      document.head.appendChild(script);
    });

    return this._scriptLoading;
  }

  /**
   * settle(options) — waits for the session to reach a verified state.
   *
   * ALWAYS await this before a protected action (login, checkout, payment, OTP).
   * The underlying challenge takes ~600ms for FORGE mode. Skipping settle() is
   * the #1 integration mistake — the kz_st cookie will not be set yet.
   *
   * @param {Object}  [options]
   * @param {number}  [options.minHeartbeats=1] - min PULSE heartbeats required (PULSE mode only)
   * @param {number}  [options.timeoutMs=8000]  - max wait in milliseconds
   * @returns {Promise<void>}
   */
  async settle({ minHeartbeats = 1, timeoutMs = 8000 } = {}) {
    if (!window.__kz) await this._loadScript();
    return window.__kz.settle({ minHeartbeats, timeoutMs });
  }

  /**
   * getState() — returns the current SDK state from the underlying c.js runner.
   *
   * Possible values: 'IDLE' | 'LOADING' | 'SOLVING' | 'READY' | 'ERROR'
   *
   * @returns {string}
   */
  getState() {
    return window.__kz ? window.__kz.getState() : 'IDLE';
  }

  /**
   * getDeviceId() — returns the stable device ID assigned to this browser.
   * Persisted in localStorage across sessions.
   *
   * @returns {string|null}
   */
  getDeviceId() {
    return window.__kz ? window.__kz.getDeviceId() : null;
  }
}

// Auto-init if data-key attribute is present on the script tag itself
// e.g. <script src="..." data-key="pk_live_xxx">
if (typeof document !== 'undefined') {
  const me = document.currentScript;
  if (me && me.dataset.key) {
    const kz = new KaizoCore({ apiKey: me.dataset.key });
    kz._loadScript().catch(() => {});
    window.__kaizocore = kz;
  }
}
