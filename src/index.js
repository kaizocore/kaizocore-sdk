/**
 * KaizoCore SDK — client-side loader
 *
 * Usage (HTML):
 *   <script src="https://cdn.kaizocore.com/l.js?k=pk_live_YOUR_KEY" defer></script>
 *
 * Usage (npm / bundler):
 *   import { KaizoCore } from '@kaizocore/sdk'
 *   const kz = new KaizoCore({ apiKey: 'pk_live_YOUR_KEY' })
 *   await kz.boot()
 *   const token = kz.getToken()
 */

const CDN_URL = 'https://cdn.kaizocore.com';

export class KaizoCore {
  constructor({ apiKey, cdnUrl = CDN_URL } = {}) {
    if (!apiKey || !apiKey.startsWith('pk_live_')) {
      throw new Error('KaizoCore: apiKey must start with pk_live_');
    }
    this._key = apiKey;
    this._cdn = cdnUrl;
    this._token = null;
    this._state = 'IDLE';
  }

  /**
   * boot() — loads the obfuscated collector script and runs the full FORGE flow.
   * Returns a Promise that resolves once the session token is ready.
   */
  async boot() {
    if (this._state !== 'IDLE') return;
    this._state = 'LOADING';

    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = `${this._cdn}/l.js?k=${encodeURIComponent(this._key)}`;
      script.async = true;
      script.onload = () => {
        // l.js bootstraps window.__kz — wait for it to settle
        const poll = setInterval(() => {
          if (window.__kz && window.__kz.getToken()) {
            clearInterval(poll);
            this._token = window.__kz.getToken();
            this._state = 'READY';
            resolve(this._token);
          }
        }, 100);
        // Timeout after 10s
        setTimeout(() => {
          clearInterval(poll);
          if (this._state !== 'READY') {
            this._state = 'ERROR';
            reject(new Error('KaizoCore: boot timed out'));
          }
        }, 10000);
      };
      script.onerror = () => {
        this._state = 'ERROR';
        reject(new Error('KaizoCore: failed to load SDK script'));
      };
      document.head.appendChild(script);
    });
  }

  /**
   * settle(options) — waits for the session to reach a verified state.
   * Call this before a protected action (login, checkout, payment).
   *
   * @param {Object} options
   * @param {number} [options.minHeartbeats=1] - minimum PULSE heartbeats required
   * @param {number} [options.timeoutMs=8000]  - max wait in ms
   */
  async settle({ minHeartbeats = 1, timeoutMs = 8000 } = {}) {
    if (window.__kz) {
      return window.__kz.settle({ minHeartbeats, timeoutMs });
    }
    // If SDK not yet loaded, boot first
    await this.boot();
    return this.settle({ minHeartbeats, timeoutMs });
  }

  /** Returns the current session token, or null if not yet collected. */
  getToken() {
    return this._token || (window.__kz ? window.__kz.getToken() : null);
  }

  /** Returns the current SDK state string. */
  getState() {
    return window.__kz ? window.__kz.getState() : this._state;
  }

  /** Returns the device ID assigned to this browser. */
  getDeviceId() {
    return window.__kz ? window.__kz.getDeviceId() : null;
  }
}

// Auto-init if data-key attribute present on the script tag
if (typeof document !== 'undefined') {
  const me = document.currentScript;
  if (me && me.dataset.key) {
    const kz = new KaizoCore({ apiKey: me.dataset.key });
    kz.boot().catch(() => {});
    window.__kaizocore = kz;
  }
}
