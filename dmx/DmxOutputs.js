// DmxOutputs.js
//
// MULTI-OUTPUT (2026-09-13). Until now the app had exactly ONE live DMX
// interface: DmxManager kept a single `activeTransport`, and connecting to a
// second device tore the first one down. Universes above 1 only ever reached the
// wire when that single transport carried them itself (Art-Net / sACN / SIUDI).
//
// This registry keeps SEVERAL interfaces open at once and routes each project
// universe to the line the user chose — including mixed rigs (a USB dongle for
// universe 1, an Art-Net node for universes 2-4).
//
// Why one DmxManager PER OUTPUT instead of a list of transports inside one
// manager: everything that keeps a connection alive is per-connection state —
// the reconnect supervisor, the outage journal, the USB-attach shortcut, the
// blackout-edge throttle, the licence gates on the frame path. Reusing the whole
// manager per output keeps that machinery untouched and, most importantly, makes
// every output travel the SAME guarded send path: a new output cannot become a
// route that bypasses a barrier, because there is no new send path at all.
//
// Vocabulary:
//   output   — one live interface (id = the scan's device id, stable per device).
//   slot     — 1-based DMX line WITHIN an output. USB dongle: 1. SIUDI7B: 1..3.
//              Network: as many as the node addresses (base + slot − 1).
//   universe — the project's logical universe (Fixture.universe, 1..64).
// An assignment is the triple {universe → device, slot}: it names the DEVICE, not
// the output's running number, because a freed number is reused and a stale entry
// would then come alive for a different dongle. Several assignments may target the
// same universe (one universe mirrored onto two interfaces) and the same device
// (different universes on different lines of one node).

const DmxManager = require('./DmxManager');
const banGate = require('../main/license/banGate');
const hiddenCodes = require('../main/license/hiddenCodes');

// Network transports stamp the universe into every packet, so one socket serves
// many lines. A USB dongle drives ONE physical DMX line — Nicolaudie/SIUDI is the
// exception (its SDK exposes several lines through one box, `universeCount`).
const NETWORK_TYPES = new Set(['artnet', 'sacn']);

// The patch UI caps a fixture at universe 64, so a network output never needs
// more slots than that.
const MAX_UNIVERSE = 64;

// Id of the first output. It reuses the process-wide manager that main.js
// already created (and armed with the licence gate), so a single-interface rig
// behaves EXACTLY as before this file existed.
const PRIMARY_OUTPUT = 'output-1';

/** How many DMX lines this interface can carry (see «slot» above). */
function slotsFor(deviceInfo) {
  if (!deviceInfo) return 1;
  if (NETWORK_TYPES.has(deviceInfo.type)) return MAX_UNIVERSE;
  const declared = Number(deviceInfo.universeCount);
  if (Number.isFinite(declared) && declared >= 1) return Math.min(MAX_UNIVERSE, Math.floor(declared));
  return 1;
}

function normalizeUniverse(value) {
  const n = Math.floor(Number(value));
  return Number.isFinite(n) && n >= 1 ? Math.min(MAX_UNIVERSE, n) : 1;
}

class DmxOutputs {
  /**
   * @param {object} options
   * @param {DmxManager} [options.primary]      manager for the first output
   * @param {() => DmxManager} [options.createManager] factory for the others —
   *        MUST arm the same licence gate as the primary (main.js passes the very
   *        function that built the primary, so the barrier cannot be forgotten).
   */
  constructor(options = {}) {
    this._createManager = typeof options.createManager === 'function'
      ? options.createManager
      : () => new DmxManager();

    // Set by main.js — the renderer-facing sinks. Events carry `outputId` so the
    // UI can tell which interface dropped or recovered.
    this.onConnectionEvent = null;
    this.onDiagnosticEvent = null;

    this._windowActive = true;
    /** @type {Map<string, object>} outputId → entry */
    this.outputs = new Map();
    /** Managers not currently bound to an output, primary first. */
    this._idle = [];
    /** @type {Array<{universe:number, deviceId:string, slot:number}>} */
    this._assignments = [];
    /** universe → [{ entry, slot }] — derived from _assignments on every change. */
    this._routes = new Map();

    const primary = options.primary || this._createManager();
    this._primary = primary;
    this._bindManager(primary, PRIMARY_OUTPUT);
    // The first output exists from the start (bound to the primary manager) so
    // auto-connect, the supervisor and the legacy IPC path all have a home.
    this.outputs.set(PRIMARY_OUTPUT, {
      id: PRIMARY_OUTPUT,
      manager: primary,
      deviceId: null,
      deviceInfo: null,
      options: null,
      slots: 1,
    });
  }

  // ─── wiring ───────────────────────────────────────────────────────────────

  /** The manager that also owns cold-start auto-connect and the scan inventory. */
  primary() { return this._primary; }

  /** @returns {DmxManager|null} */
  managerFor(outputId) {
    const entry = this.outputs.get(outputId);
    return entry ? entry.manager : null;
  }

  _bindManager(manager, outputId) {
    if (typeof manager.setOutputId === 'function') manager.setOutputId(outputId);
    manager.onConnectionEvent = (event) => {
      // A manager reconnects, recovers and (on the primary) cold-start connects on
      // its own, without anyone calling connect() here. Re-read what it actually
      // drives on every such event — ONE place keeps the registry honest instead
      // of three call sites remembering to do it.
      this._syncEntry(this.outputs.get(outputId));
      if (typeof this.onConnectionEvent !== 'function') return;
      try { this.onConnectionEvent({ ...event, outputId }); } catch (e) { /* listener errors never touch DMX */ }
    };
    manager.onDiagnosticEvent = (event) => {
      if (typeof this.onDiagnosticEvent !== 'function') return;
      try { this.onDiagnosticEvent({ ...event, outputId }); } catch (e) { /* ditto */ }
    };
  }

  // ─── lifecycle ────────────────────────────────────────────────────────────

  setWindowActive(active) {
    this._windowActive = !!active;
    for (const entry of this.outputs.values()) entry.manager.setWindowActive(this._windowActive);
  }

  /** Start the cold-start supervisor. Only the primary hunts for a device on its
   *  own; a secondary output reconnects to ITS device after a drop (its manager
   *  remembers lastConnect) but never goes looking for an unclaimed one. */
  kickSupervisor() {
    try { if (!banGate.mayAttemptConnection()) return; } catch (_) { return; }
    this._primary.kickSupervisor();
  }

  // ─── inventory ────────────────────────────────────────────────────────────

  /**
   * One scan for the whole app: the bus is scanned once and the result handed to
   * every manager, so a second output can open a device by id without starting a
   * competing scan of the same USB bus.
   */
  // Called by the renderer's «Поиск»: the source label is for diagnostics only.
  async scan() {
    try {
      if (!banGate.mayAttemptConnection()) {
        try { this._primary.noteBlockedBeaconScan({ beaconSource: 1 }); } catch (_) {}
        return [];
      }
    } catch (_) { return []; }
    const results = await this._primary.scan({ beaconSource: 1 });
    for (const entry of this.outputs.values()) {
      if (entry.manager !== this._primary) entry.manager.setScanResults(results);
    }
    for (const manager of this._idle) {
      if (manager !== this._primary) manager.setScanResults(results);
    }
    return results;
  }

  get lastScanResults() { return this._primary.lastScanResults; }

  // ─── outputs ──────────────────────────────────────────────────────────────

  /** Public view of every output, for the renderer and the support report. */
  list() {
    const items = [];
    for (const entry of this.outputs.values()) {
      this._syncEntry(entry);
      const status = entry.manager.getStatus();
      items.push({
        id: entry.id,
        deviceId: entry.deviceId,
        deviceType: status.deviceType || (entry.deviceInfo && entry.deviceInfo.type) || null,
        deviceName: status.deviceName || (entry.deviceInfo && entry.deviceInfo.name) || null,
        connected: status.connected,
        error: status.error,
        slots: entry.slots,
        primary: entry.id === PRIMARY_OUTPUT,
      });
    }
    return items;
  }

  /**
   * Re-read what an output actually drives right now (its manager is the source
   * of truth — it also connects on its own via the supervisor). Returns true when
   * something changed, so routes are rebuilt only when they really moved.
   */
  _syncEntry(entry) {
    if (!entry) return false;
    const transport = entry.manager.activeTransport;
    const info = transport ? transport.deviceInfo : null;
    const deviceId = info && info.id ? info.id : (transport ? entry.deviceId : null);
    const slots = info ? slotsFor(info) : 1;
    const changed = entry.deviceId !== deviceId || entry.slots !== slots;
    entry.deviceId = deviceId;
    entry.deviceInfo = info || (transport ? entry.deviceInfo : null);
    entry.slots = slots;
    if (changed) this._rebuildRoutes();
    return changed;
  }

  /** An output already driving this device, if any. */
  _findByDevice(deviceId) {
    for (const entry of this.outputs.values()) {
      if (entry.deviceId && entry.deviceId === deviceId) return entry;
    }
    return null;
  }

  /**
   * Which output should carry this connection:
   *   • the one already bound to this device (reconnect / settings change), else
   *   • an output that holds no device yet (the primary is first in line), else
   *   • a brand new output with its own manager.
   */
  _entryFor(deviceId, outputId) {
    if (outputId) {
      const explicit = this.outputs.get(outputId);
      if (explicit) return explicit;
    }
    const byDevice = this._findByDevice(deviceId);
    if (byDevice) return byDevice;
    for (const entry of this.outputs.values()) {
      if (!entry.deviceId && !entry.manager.activeTransport) return entry;
    }
    return this._createOutput();
  }

  _createOutput() {
    let manager = this._idle.find(m => !m.activeTransport && m !== this._primary) || null;
    if (manager) this._idle = this._idle.filter(m => m !== manager);
    else manager = this._createManager();
    const id = this._nextOutputId();
    this._bindManager(manager, id);
    // A secondary output has no remembered device yet. Do not let restoring its
    // window start a cold hunt for the primary's USB box before manual connect.
    manager.userDisconnected = true;
    manager.setScanResults(this._primary.lastScanResults);
    manager.setWindowActive(this._windowActive);
    const entry = { id, manager, deviceId: null, deviceInfo: null, options: null, slots: 1 };
    this.outputs.set(id, entry);
    return entry;
  }

  _nextOutputId() {
    for (let n = 1; n <= 64; n++) {
      const id = `output-${n}`;
      if (!this.outputs.has(id)) return id;
    }
    return `output-${Date.now()}`;
  }

  /**
   * Open `deviceId` as an output. Unlike the old single-transport connect, an
   * interface that is already live is NOT torn down — unless the same output is
   * being pointed at a different device.
   */
  async connect(deviceId, options = {}, opts = {}) {
    try {
      if (!banGate.mayAttemptConnection()) {
        const banned = banGate.getState() === banGate.STATE.BANNED;
        try { this._primary.noteBlockedBeaconAttempt(deviceId, options, opts); } catch (_) {}
        return {
          success: false,
          ...(banned ? { noticeCode: hiddenCodes.CODE.r_manual } : { error: 'Не удалось подключиться к DMX-интерфейсу.' }),
          outputId: typeof opts.outputId === 'string' ? opts.outputId : PRIMARY_OUTPUT,
        };
      }
    } catch (_) {
      return {
        success: false,
        error: 'Не удалось подключиться к DMX-интерфейсу.',
        outputId: typeof opts.outputId === 'string' ? opts.outputId : PRIMARY_OUTPUT,
      };
    }
    const entry = this._entryFor(deviceId, opts.outputId);
    let result;
    try {
      result = await entry.manager.connect(deviceId, options, opts);
    } finally {
      if (entry.id !== PRIMARY_OUTPUT && !entry.manager.activeTransport && !entry.manager.lastConnect) {
        entry.manager.userDisconnected = true;
      }
    }
    if (result && result.success) entry.options = options || {};
    this._syncEntry(entry);
    return { ...result, outputId: entry.id };
  }

  /**
   * Cold-start auto-connect stays the primary's job: it is the search for an
   * unclaimed single device, and two outputs hunting at once would race for the
   * same dongle.
   */
  async autoConnect(opts = {}) {
    try {
      if (!banGate.mayAttemptConnection()) {
        try { this._primary.noteBlockedBeaconAttempt(null, {}, { ...opts, beaconSource: 2 }); } catch (_) {}
        return { autoConnected: false, reason: 'unavailable', devices: [] };
      }
    } catch (_) {
      return { autoConnected: false, reason: 'unavailable', devices: [] };
    }
    const result = await this._primary.autoConnect(opts);
    this._syncEntry(this.outputs.get(PRIMARY_OUTPUT));
    return result;
  }

  /** Disconnect one output (default: the primary — the legacy «Отключить»). */
  async disconnect(outputId = PRIMARY_OUTPUT) {
    const entry = this.outputs.get(outputId);
    if (!entry) return { success: false, error: 'Выход не найден' };
    await entry.manager.disconnect();
    entry.deviceId = null;
    entry.deviceInfo = null;
    entry.options = null;
    entry.slots = 1;
    // A secondary output disappears with its device; the primary always stays so
    // the next plain connect/auto-connect has a home.
    if (entry.id !== PRIMARY_OUTPUT) {
      this.outputs.delete(entry.id);
      entry.manager.onConnectionEvent = null;
      entry.manager.onDiagnosticEvent = null;
      this._idle.push(entry.manager);
    }
    this._rebuildRoutes();
    return { success: true };
  }

  async disconnectAll() {
    const ids = Array.from(this.outputs.keys());
    for (const id of ids) {
      try { await this.disconnect(id); } catch (e) { /* a dead device must not block shutdown */ }
    }
  }

  // ─── routing ──────────────────────────────────────────────────────────────

  /**
   * Replace the universe map. An assignment names the DEVICE (`deviceId` from the
   * scan), not the output's running number: a number is reused when an output is
   * freed, and a stale entry would then come alive for a DIFFERENT dongle — the
   * one failure this feature must never have («the light went to the wrong rig»).
   * A device id is stable (uDMX: its USB location, serial port: its path), so the
   * map survives a restart and simply stays dormant while that interface is absent.
   *
   * Entries for a device nothing is connected to, or for a line the interface does
   * not have, are dropped when routes are built — a dormant map never guesses.
   */
  setAssignments(list) {
    const next = [];
    if (Array.isArray(list)) {
      for (const item of list) {
        if (!item || !item.deviceId) continue;
        const universe = normalizeUniverse(item.universe);
        const slot = Math.max(1, Math.floor(Number(item.slot)) || 1);
        const deviceId = String(item.deviceId);
        if (next.some(a => a.universe === universe && a.deviceId === deviceId && a.slot === slot)) continue;
        next.push({ universe, deviceId, slot });
      }
    }
    this._assignments = next;
    this._rebuildRoutes();
    return this.getAssignments();
  }

  getAssignments() {
    return this._assignments.map(a => ({ ...a }));
  }

  _rebuildRoutes() {
    const routes = new Map();
    for (const assignment of this._assignments) {
      const entry = this._findByDevice(assignment.deviceId);
      if (!entry) continue;                        // that interface is not connected
      if (assignment.slot > entry.slots) continue; // interface has no such line
      const list = routes.get(assignment.universe) || [];
      list.push({ entry, slot: assignment.slot });
      routes.set(assignment.universe, list);
    }
    this._routes = routes;
  }

  /** True while no usable assignment exists — then the legacy path runs. */
  _routesEmpty() { return this._routes.size === 0; }

  /**
   * The frame path. `universe` is the project's logical universe; what reaches a
   * transport is the SLOT on its own output (a network transport turns that into
   * base + slot − 1 exactly as it did for logical universes before).
   *
   * With no assignments configured this behaves like the old single-output app:
   * every universe goes to the primary output under its own number, so an
   * existing rig keeps working without touching any setting.
   */
  route(universe, dmxData) {
    if (this._routesEmpty()) {
      const session = this._primary.getManualBanSession && this._primary.getManualBanSession();
      try {
        if (!banGate.maySendFrame(PRIMARY_OUTPUT, session && session.sessionId)) return;
      } catch (_) { return; }
      this._primary.sendThrottled(universe, dmxData);
      return;
    }
    const targets = this._routes.get(normalizeUniverse(universe));
    if (!targets) return; // universe not patched to any output — nothing to send
    for (const target of targets) {
      const session = target.entry.manager.getManualBanSession
        ? target.entry.manager.getManualBanSession() : null;
      try {
        if (!banGate.maySendFrame(target.entry.id, session && session.sessionId)) continue;
      } catch (_) { continue; }
      target.entry.manager.sendThrottled(target.slot, dmxData);
    }
  }

  // ─── aggregate views ──────────────────────────────────────────────────────

  /**
   * Back-compatible status: the top-level fields describe the primary output (the
   * only one a single-interface rig has), `outputs` describes every one of them.
   */
  getStatus() {
    const base = this._primary.getStatus();
    return { ...base, outputs: this.list() };
  }

  /** Support report: the primary's full black box plus a summary of the rest. */
  getDiagnostics() {
    const diagnostics = this._primary.getDiagnostics();
    const extras = [];
    for (const entry of this.outputs.values()) {
      if (entry.manager === this._primary) continue;
      extras.push({
        outputId: entry.id,
        deviceId: entry.deviceId,
        slots: entry.slots,
        status: entry.manager.getStatus(),
        diagnostics: entry.manager.getDiagnostics(),
      });
    }
    return { ...diagnostics, outputs: this.list(), assignments: this.getAssignments(), extraOutputs: extras };
  }

  getActiveDeviceInfo() { return this._primary.getActiveDeviceInfo(); }

  // ─── licence-driven suspension ────────────────────────────────────────────
  // Signing out / clearing the licence must silence EVERY interface, not just the
  // one the app happens to call primary — a second output that kept clocking the
  // wire would be a hole in exactly the barrier these calls exist for. Idle
  // managers (freed by a disconnect, reused later) are included so a released
  // manager can never come back carrying a stale «allowed» state.
  _allManagers() {
    const seen = new Set();
    const managers = [];
    for (const entry of this.outputs.values()) {
      if (seen.has(entry.manager)) continue;
      seen.add(entry.manager);
      managers.push(entry.manager);
    }
    for (const manager of this._idle) {
      if (seen.has(manager)) continue;
      seen.add(manager);
      managers.push(manager);
    }
    return managers;
  }

  /** Exact pairs open at the R transition; banGate freezes this snapshot. */
  activeManualBanSessions() {
    const sessions = [];
    for (const entry of this.outputs.values()) {
      try {
        const session = entry.manager.getManualBanSession && entry.manager.getManualBanSession();
        if (session) sessions.push(session);
      } catch (_) {}
    }
    return sessions;
  }

  /** Stop all idle/open attempts without closing sessions already on the wire. */
  applyManualBanBoundary() {
    for (const manager of this._allManagers()) {
      try { manager.applyManualBanBoundary(); } catch (_) {}
    }
  }

  async suspendForLicenseClear() {
    for (const manager of this._allManagers()) {
      try { await manager.suspendForLicenseClear(); } catch (e) { /* a dead device must not block the barrier */ }
    }
  }

  resumeAfterVerifiedToken() {
    // An idle manager was released by a manual disconnect (userDisconnected), so
    // resuming it cannot start a second hunt for an unclaimed device — the
    // supervisor refuses to run for it.
    for (const manager of this._allManagers()) {
      try { manager.resumeAfterVerifiedToken(); } catch (e) { /* never break the licence path */ }
    }
  }

  getForeignSources() {
    const seen = [];
    for (const entry of this.outputs.values()) {
      try {
        for (const source of entry.manager.getForeignSources()) seen.push({ ...source, outputId: entry.id });
      } catch (e) { /* observation must never affect output */ }
    }
    return seen;
  }
}

module.exports = { DmxOutputs, PRIMARY_OUTPUT, slotsFor, MAX_UNIVERSE };
