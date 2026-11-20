// ============================================================================
//  SiudiBridge — Node side of the SIUDI/Sunlite bridge.
//
//  Owns the lifecycle of the 32-bit SiudiSidecar.exe (which loads the Nicolaudie
//  LsHardDevKit.dll that a 64-bit Electron process cannot) and turns its
//  line-delimited stdin/stdout protocol into promises + events.
//
//  Design:
//    • ONE persistent sidecar per app (single DHDK_init for its whole lifetime —
//      safer for the SDK than re-init on every 3s supervisor scan). Respawned if
//      it dies; spawn attempts are throttled when the DLL is missing (fatal).
//    • scan() is NON-blocking: if the sidecar is not ready yet it kicks off the
//      spawn and returns [] immediately, so DmxManager.scan() never stalls on
//      process start. The next scan (≈3s later) returns the real device list.
//    • open()/close() await the sidecar (user actions — a short wait is fine).
//    • send() is fire-and-forget (no per-frame round trip); the sidecar surfaces
//      a physical unplug once as an 'lost' event after N failed sends.
//
//  Availability is fail-open: no exe or no DLL -> scan() returns [] and nothing
//  else in the app is affected.
// ============================================================================
const { spawn } = require('child_process');
const readline = require('readline');
const path = require('path');
const fs = require('fs');

const START_TIMEOUT_MS = 6000;   // wait for {"event":"ready"} / "fatal"
const REQUEST_TIMEOUT_MS = 4000; // wait for a control-command reply
const SPAWN_THROTTLE_MS = 5000;  // min gap between spawn attempts after a failure

class SiudiBridge {
  constructor(opts = {}) {
    this.exePath = opts.exePath || SiudiBridge.defaultExePath();
    this.dllDir = opts.dllDir || null;   // optional explicit LsHardDevKit.dll dir
    // Injection point for tests (dmx/ lives outside the Vitest module graph, so
    // vi.mock('child_process') does not reach this file). Production passes
    // nothing and gets the real spawn.
    this.spawnProcess = opts.spawn || spawn;

    this.proc = null;
    this.rl = null;
    this.ready = false;
    this._fatal = null;                  // last fatal error (DLL missing / init)
    this._starting = null;               // Promise while a spawn is in flight
    this._startResolve = null;
    this._startTimer = null;
    this._lastSpawnMs = 0;

    this._nextId = 1;
    this._pending = new Map();           // id -> { resolve, timer }

    // Listeners wired by the transport (SunliteTransport / DmxManager).
    this.onLost = null;                  // () => void   — device unplugged mid-send
    this.onFatal = null;                 // (msg) => void — DLL missing / init failed
    this.onExit = null;                  // (code) => void — sidecar process died
  }

  // packaged: resources/siudi/SiudiSidecar.exe ; dev: build/siudi/SiudiSidecar.exe
  static defaultExePath() {
    try {
      if (process.resourcesPath) {
        const p = path.join(process.resourcesPath, 'siudi', 'SiudiSidecar.exe');
        if (fs.existsSync(p)) return p;
      }
    } catch (e) { /* not electron */ }
    // __dirname = <repo>/dmx/siudi → build output is at <repo>/build/siudi.
    return path.join(__dirname, '..', '..', 'build', 'siudi', 'SiudiSidecar.exe');
  }

  isAvailable() {
    try { return fs.existsSync(this.exePath); } catch (e) { return false; }
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  // Non-blocking: kick the spawn and return [] until the sidecar is ready.
  async scan() {
    if (!this.isAvailable()) return [];
    if (!this.ready) { this._ensureStarted(); return []; }
    const r = await this._request('SCAN');
    return (r && r.ok && Array.isArray(r.devices)) ? r.devices : [];
  }

  // Await the sidecar; returns { ok, universes } or { ok:false, error }.
  async open(deviceIndex) {
    const ok = await this._ensureStarted();
    if (!ok) return { ok: false, error: this._fatal || 'sidecar unavailable' };
    return this._request('OPEN ' + deviceIndex);
  }

  // Fire-and-forget hot path. Buffer is the DMX data for one universe (≤512).
  // Returns whether the line REACHED the sidecar's stdin — not whether the box lit
  // up (the SDK acknowledges no single frame). That distinction is what the report
  // calls the `sidecar` confirmation level; without a return value the transport
  // could not tell a live stream from a dead pipe at all (2026-09-11).
  send(universeIndex, buffer) {
    if (!this.ready || !this.proc || !this.proc.stdin || !this.proc.stdin.writable) return false;
    const b64 = Buffer.from(buffer).toString('base64');
    const id = this._nextId++;
    // stdin.write() returns false on BACKPRESSURE — the line is queued, not lost, so
    // that is still a delivered frame. Only a throw means it went nowhere.
    try { this.proc.stdin.write(id + ' SEND ' + universeIndex + ' ' + b64 + '\n'); }
    catch (e) { /* pipe closed — exit handler will surface it */ return false; }
    return true;
  }

  async close() {
    if (!this.ready) return { ok: true };
    return this._request('CLOSE');
  }

  // Ask the sidecar to exit; kill as a fallback. Called on app shutdown.
  dispose() {
    this.ready = false;
    const p = this.proc;
    if (p) {
      try { p.stdin.write((this._nextId++) + ' EXIT\n'); } catch (e) { /* already gone */ }
      setTimeout(() => { try { p.kill(); } catch (e) {} }, 500);
    }
  }

  // ─── Internals ──────────────────────────────────────────────────────────────

  async _ensureStarted() {
    if (this.ready && this.proc) return true;
    if (this._starting) return this._starting;
    // Throttle respawns after a failure (esp. missing-DLL fatal fast loop).
    if (this._fatal && (Date.now() - this._lastSpawnMs) < SPAWN_THROTTLE_MS) return false;
    this._starting = this._spawn();
    const ok = await this._starting;
    this._starting = null;
    return ok;
  }

  _spawn() {
    return new Promise((resolve) => {
      this._lastSpawnMs = Date.now();
      let proc;
      const args = this.dllDir ? [this.dllDir] : [];
      try {
        proc = this.spawnProcess(this.exePath, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      } catch (e) {
        this._fatal = 'spawn failed: ' + e.message;
        resolve(false);
        return;
      }
      this.proc = proc;
      this._startResolve = resolve;

      this.rl = readline.createInterface({ input: proc.stdout });
      this.rl.on('line', (line) => this._onLine(line));
      if (proc.stderr) proc.stderr.on('data', () => { /* drain diagnostics */ });

      proc.on('error', (e) => {
        this._fatal = 'proc error: ' + e.message;
        this._settleStart(false);
      });
      proc.on('exit', (code) => this._onExit(code));

      this._startTimer = setTimeout(() => {
        this._fatal = 'sidecar start timeout';
        try { proc.kill(); } catch (e) {}
        this._settleStart(false);
      }, START_TIMEOUT_MS);
    });
  }

  _settleStart(ok) {
    if (this._startTimer) { clearTimeout(this._startTimer); this._startTimer = null; }
    if (this._startResolve) { const r = this._startResolve; this._startResolve = null; r(ok); }
  }

  _onLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch (e) { return; } // ignore non-JSON noise
    if (msg.event) {
      if (msg.event === 'ready') {
        this.ready = true; this._fatal = null; this._settleStart(true);
      } else if (msg.event === 'fatal') {
        this._fatal = msg.error || 'fatal'; this.ready = false; this._settleStart(false);
        if (this.onFatal) { try { this.onFatal(this._fatal); } catch (e) {} }
      } else if (msg.event === 'lost') {
        if (this.onLost) { try { this.onLost(); } catch (e) {} }
      }
      return;
    }
    if (msg.id != null) {
      const p = this._pending.get(msg.id);
      if (p) { this._pending.delete(msg.id); clearTimeout(p.timer); p.resolve(msg); }
    }
  }

  _request(cmd) {
    return new Promise((resolve) => {
      if (!this.proc || !this.proc.stdin || !this.proc.stdin.writable) {
        resolve({ ok: false, error: 'sidecar not running' });
        return;
      }
      const id = this._nextId++;
      const timer = setTimeout(() => {
        this._pending.delete(id);
        resolve({ ok: false, error: 'timeout' });
      }, REQUEST_TIMEOUT_MS);
      this._pending.set(id, { resolve, timer });
      try {
        this.proc.stdin.write(id + ' ' + cmd + '\n');
      } catch (e) {
        clearTimeout(timer); this._pending.delete(id);
        resolve({ ok: false, error: 'write failed: ' + e.message });
      }
    });
  }

  _onExit(code) {
    this.ready = false;
    this.proc = null;
    if (this.rl) { try { this.rl.close(); } catch (e) {} this.rl = null; }
    // Fail any in-flight control requests so callers don't hang.
    for (const [, p] of this._pending) { clearTimeout(p.timer); p.resolve({ ok: false, error: 'sidecar exited' }); }
    this._pending.clear();
    this._settleStart(false);
    if (this.onExit) { try { this.onExit(code); } catch (e) {} }
  }
}

// Single shared bridge: the static SunliteTransport.scan() and a connected
// transport instance all talk to the SAME sidecar process.
let _shared = null;
function getSharedBridge(opts) {
  if (!_shared) _shared = new SiudiBridge(opts);
  return _shared;
}

module.exports = { SiudiBridge, getSharedBridge };
