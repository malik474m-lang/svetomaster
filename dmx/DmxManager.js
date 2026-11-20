const UdmxTransport = require('./UdmxTransport');
const EnttecProTransport = require('./EnttecProTransport');
const FtdiOpenDmxTransport = require('./FtdiOpenDmxTransport');
const ArtNetTransport = require('./ArtNetTransport');
const SunliteTransport = require('./SunliteTransport');
const MartinTransport = require('./MartinTransport');
const SacnTransport = require('./SacnTransport');
const { isBlackoutFrame } = require('./frameUtils');
const { findReconnectTarget, closeWithTimeout, compareDevicesStable } = require('./reconnectUtils');
const { DmxDiagnostics, cleanDeviceInfo, shouldPersistEvent } = require('./DmxDiagnostics');
const connGate = require('../main/license/connGate'); // WAVE-6 / Рубеж A — отдельный барьер подключения
const frameGate = require('../main/license/frameGate'); // WAVE-6 / Рубеж B — отдельный барьер кадров
const banGate = require('../main/license/banGate'); // R2 — independent manual installation/build boundary

// Both helpers fail open on an unexpected module/runtime error. In packaged builds the gates
// self-arm inside their integrity-covered modules; DmxManager is itself integrity-covered, so
// removing these calls changes the digest. Keeping A here (not only in root main.js IPC) covers
// manual connect, auto-connect, cold-start supervisor and reconnect with one last-mile check.
function isDeferredConnectionBlocked() {
  try { return connGate.isConnBlocked(); } catch (_) { return false; }
}

function isManualConnectionBlocked() {
  try { return !banGate.mayAttemptConnection(); } catch (_) { return true; }
}

function isManualBanActive() {
  try { return banGate.getState() === banGate.STATE.BANNED; } catch (_) { return false; }
}

const DEFERRED_CONNECT_ERROR = 'Не удалось подключиться к DMX-интерфейсу.';

// N1 (резервный звонарь A): как долго кэшировать сырой снимок пропуска для точки наблюдения,
// чтобы не расшифровывать secure-store на каждом ~40 Гц кадре (secureStore.get = чтение файла +
// DPAPI). Снимок принудительно обновляется при открытии подключения и не чаще этого окна на
// горячем пути. Это только СБОР ФАКТА — проверка пропуска и классификация живут в обфусцированном
// main/license/edgeAssetA, не здесь.
const EDGE_PASS_SNAPSHOT_TTL_MS = 2000;

// N1a lifecycle identifiers must be unique across every DmxManager in this
// process. A per-manager diagnostic sequence used to collide as soon as a
// second physical output opened its first transport. Keep this namespace local
// to the process; the notifier binds it to its own process nonce before any
// durable decision is made.
const EDGE_PROCESS_NAMESPACE = `${process.pid}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 10)}`;
let edgeTransportSequence = 0;
let edgeReconnectAttemptSequence = 0;

function nextEdgeTransportId() {
  edgeTransportSequence += 1;
  return `dmx:${EDGE_PROCESS_NAMESPACE}:t:${edgeTransportSequence.toString(36)}`;
}

function nextEdgeReconnectAttemptId() {
  edgeReconnectAttemptSequence += 1;
  return `dmx:${EDGE_PROCESS_NAMESPACE}:r:${edgeReconnectAttemptSequence.toString(36)}`;
}

function edgeMonotonicNowMs() {
  try { return Number(process.hrtime.bigint()) / 1e6; } catch (_) { return Date.now(); }
}

function normalizeEdgeString(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase();
  return normalized || null;
}

function normalizeEdgePath(value) {
  const normalized = normalizeEdgeString(value);
  return normalized ? normalized.replace(/\\/g, '/').replace(/\/{2,}/g, '/') : null;
}

function normalizeEdgeHex(value) {
  if (value == null || value === '') return null;
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.trunc(value)).toString(16).padStart(4, '0');
  }
  const text = String(value).trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(text)) return null;
  return parseInt(text, 16).toString(16).padStart(4, '0');
}

function normalizeEdgeInteger(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

// Only stable raw hardware/network facts cross the observation boundary.
// UI labels, scan aliases, indexes and native handles are deliberately absent.
// edgeAssetA applies the identity tiers (serial -> path -> network) itself.
function normalizeEdgeAdapter(deviceInfo) {
  const info = deviceInfo && typeof deviceInfo === 'object' ? deviceInfo : {};
  const adapter = {};
  const type = normalizeEdgeString(info.type);
  const serialNumber = normalizeEdgeString(info.serialNumber != null ? info.serialNumber : info.serial);
  const path = normalizeEdgePath(info.path);
  const vendorId = normalizeEdgeHex(info.vendorId != null ? info.vendorId : info.vid);
  const productId = normalizeEdgeHex(info.productId != null ? info.productId : info.pid);
  let address = normalizeEdgeString(info.address != null ? info.address : info.ip);
  let port = normalizeEdgeInteger(info.port);
  let universe = normalizeEdgeInteger(info.universe);
  const subnet = normalizeEdgeInteger(info.subnet);
  // sACN's scan row omits destination/port because they are protocol-derived,
  // while the live transport always sends to this exact multicast endpoint.
  // Include those effective transport facts so two configured network outputs
  // are never linked merely by the broad `sacn` type.
  if (type === 'sacn') {
    if (!universe) universe = 1;
    if (!address && universe > 0 && universe <= 0xffff) {
      address = `239.255.${(universe >> 8) & 0xff}.${universe & 0xff}`;
    }
    if (port == null) port = 5568;
  }
  if (type) adapter.type = type;
  if (serialNumber) adapter.serialNumber = serialNumber;
  if (path) adapter.path = path;
  if (vendorId) adapter.vendorId = vendorId;
  if (productId) adapter.productId = productId;
  if (address) adapter.address = address;
  if (port != null) adapter.port = port;
  if (universe != null) adapter.universe = universe;
  if (subnet != null) adapter.subnet = subnet;
  return Object.freeze(adapter);
}

function normalizeEdgePassRead(value, failed = false) {
  if (failed) return { status: 'unknown', value: null };
  if (value && typeof value === 'object') {
    if (value.status === 'present') return { status: 'present', value: value.value };
    if (value.status === 'absent') return { status: 'absent', value: null };
    if (value.status === 'unknown') return { status: 'unknown', value: null };
  }
  // Backward compatibility for embedders/tests that still inject the old raw
  // provider. Production main.js always supplies secureStore.getWithStatus().
  if (value == null) return { status: 'absent', value: null };
  return { status: 'present', value };
}

function rawPassFromStatus(passRead) {
  return passRead && passRead.status === 'present' ? passRead.value : null;
}

const EDGE_CLOSE_CAUSES = new Set([
  'manual_disconnect',
  'device_change',
  'ordinary_teardown',
  'license_clear',
  'shutdown',
]);

// §7.10 — support code of the quiet layer that refused the connection. Only a NUMBER leaves
// this file: the wording lives in the interface dictionary, and no layer name reaches the
// user, app.log or the wire. 0 = Rubezh A is not the reason (then the plain wording stands).
const hiddenCodes = require('../main/license/hiddenCodes');
function deferredConnectionCode() {
  try {
    const verdict = connGate.getVerdict();
    return verdict && verdict.verdict === 'BLOCK' ? hiddenCodes.forConnGate(verdict.reason) : 0;
  } catch (_) {
    return 0;
  }
}

// One shape for both reasons a connection can be refused before it starts. A suspended
// session (signed out / licence cleared) keeps its plain wording — an honest state of an
// honest person. Rubezh A returns a number instead, which the renderer turns into the single
// sentence every quiet layer shows.
function deferredConnectResult(suspended) {
  if (isManualBanActive()) return { noticeCode: hiddenCodes.CODE.r_manual };
  if (suspended) return { error: DEFERRED_CONNECT_ERROR };
  const code = deferredConnectionCode();
  return code ? { noticeCode: code } : { error: DEFERRED_CONNECT_ERROR };
}

// Single retry cadence for the connection supervisor (DMX-004): both the cold-start
// auto-connect and the after-drop reconnect retry on this interval.
const SUPERVISOR_INTERVAL_MS = 3000;

// UDMX-006: how long a freshly attached USB device is given to finish binding to
// its driver before the supervisor tries to open it. Windows announces the
// arrival earlier than libusbK is ready to hand out a working handle.
const ATTACH_SETTLE_MS = 400;

// Hard cap on how long teardown waits for an old transport's close() (DMXMGR-003).
// A hung device (Enttec Pro/Open DMX holding the port, uDMX not releasing) can
// leave a callback-based close() pending forever; without this, connect() to a
// new device — which tears down the old one first — would block indefinitely and
// the «Подключить» button would hang. After the timeout we orphan the old
// transport and proceed (see closeWithTimeout in reconnectUtils).
const TEARDOWN_TIMEOUT_MS = 2000;

// Default wire clock (~40 FPS, close to the 44 FPS DMX standard). A transport
// whose physical frame time is longer overrides it via minFrameIntervalMs
// (UDMX-002: uDMX needs ~35 ms per full frame on low-speed USB).
const DEFAULT_FRAME_INTERVAL_MS = 25;

// A driver/runtime error can include arbitrary native detail. Keep enough for
// support while preserving the report's bounded-size invariant.
const SERIAL_SCAN_ERROR_MAX_CHARS = 1000;

class DmxManager {
  constructor() {
    this.activeTransport = null;
    this.lastScanResults = [];
    // Last COM/USB-serial inventory for the support report. Unlike
    // lastScanResults, this also preserves an empty/failed scan as evidence.
    this._lastSerialScan = null;
    // Последний снимок чужих Art-Net источников. Живёт дольше подключения: отчёт
    // поддержки собирают уже после отключения (аудит 2026-09-05, см. getForeignSources).
    this._lastForeignSources = null;
    // MULTI-UNIVERSE: throttle state is per-universe (each universe = its own ~40 Hz
    // frame clock + blackout edge). Keyed by universe → { lastData, lastWasBlackout,
    // sendTimeout }. Single-universe (legacy) just uses key 1, identical behaviour.
    this.throttle = new Map();
    // Connection supervisor (DMX-004) — keeps a connection alive: cold-start
    // auto-connect AND after-drop reconnect are one mechanism.
    this.lastConnect = null;       // { deviceInfo, options } of the last live connection
    this.userDisconnected = false; // true after a manual disconnect() — suppresses all auto-connect
    this.windowActive = true;      // false while the window is minimized — pause scanning/reconnect
    this.supervising = false;      // a supervisor retry loop is currently scheduled
    this.supervisorTimer = null;
    this._lostActive = false;      // an active device was lost (drop) — emit 'reconnected' on success
    this._lastAutoResultSig = null; // dedup of cold-start autoconnect-result emits
    this.onConnectionEvent = null; // (event) => void — set by main.js to notify renderer
    this.onDiagnosticEvent = null; // persisted critical event sink — set by main.js
    this._connectLock = Promise.resolve(); // serializes connect() calls (BUG-005)
    this._licenseGate = null; // WAVE-2: injected () => boolean; false → кадр на железо не идёт
    this._licenseSuspended = false; // true between main-side license-clear and a verified login
    this._diagnostics = new DmxDiagnostics();
    this._diagnosticSessionSeq = 0;
    this._activeDiagnosticSession = null;
    this._outputId = null; // assigned by DmxOutputs; forms the R admission pair with sessionId
    this._lostAtMs = null;
    this._lastUdmxPresenceSignature = null;
    this._degradedActive = false; // UDMX-004: transport is healing an outage (not a drop)
    // A reopened uDMX handle is only provisional until its first successful USB
    // DMX transfer. The session id prevents a late callback from an old transport
    // from falsely confirming the new connection.
    this._reconnectVerificationSessionId = null;
    // Repeats the proof frame while the session stays provisional. The renderer's
    // own output gate is shut during an outage, so the manager is the ONLY source
    // of frames that can either confirm the link or let the transport's recovery
    // ladder run to its verdict.
    this._reconnectProbeTimer = null;
    // Last frame that passed the manager's license/output gates. Kept across a
    // transport teardown so a reopened uDMX session can prove a real transfer
    // even while the renderer truthfully keeps its normal output gate closed.
    this._lastPermittedDmxFrames = new Map();
    // UDMX-006: hotplug shortcut for the reconnect wait (see _watchUsbAttach).
    this._usbAttachUnsubscribe = null;
    this._attachKickTimer = null;
    // N1 — резервный звонарь A: точка наблюдения «реальная работа» строго ПОСЛЕ всех гейтов
    // (ТЗ звонарей §12, ТЗ паспортов §9-бис.3 п.1). DmxManager только СООБЩАЕТ ФАКТЫ (id сессии
    // транспорта, сырой снимок пропуска, момент допуска) обфусцированному main/license/edgeAssetA;
    // свой счётчик, своё состояние и журнал допусков — там, вердикты гейтов звонарь не читает.
    // Инъекция (как _licenseGate): без наблюдателя (dev/тесты) путь полностью бездействует.
    this._dmxObserver = null;
    this._edgeTransportId = null;   // process-global id текущей сессии транспорта
    this._edgeAdapter = null;       // стабильные raw hardware facts текущей сессии
    this._edgeReconnectPreviousTransportId = null; // unexpected-loss lease candidate
    this._edgeReconnectAdapter = null;
    this._edgePass = { status: 'unknown', value: null }; // tri-state cache for the hot path
    this._edgePassAtMonoMs = null;  // monotonic cache timestamp (wall-clock changes cannot pin it)
    // N1-B keeps a separate observer and pass cache. The two callbacks are intentionally not
    // composed: deleting or throwing in one path cannot suppress the other notifier.
    this._dmxObserverB = null;
    this._edgePassB = { status: 'unknown', value: null };
    this._edgePassBAtMonoMs = null;
    this._beaconDiagnostics = null; // optional bounded observations; never an admission predicate
  }

  // WAVE-2 primary licence predicate stays injected from main. Deferred A/B are deliberately
  // direct independent requires above: DmxManager is integrity-covered, so root-main patching
  // cannot remove their last-mile calls without touching another protected file.
  setLicenseGate(fn) { this._licenseGate = typeof fn === 'function' ? fn : null; }

  setOutputId(outputId) { this._outputId = typeof outputId === 'string' ? outputId : null; }

  getManualBanSession() {
    if (!this._outputId || !this.activeTransport || !this.activeTransport.isConnected()
        || !this._activeDiagnosticSession) return null;
    return { outputId: this._outputId, sessionId: this._activeDiagnosticSession.sessionId };
  }

  // A transition to R does not close a live transport: its exact session pair was
  // snapshotted and may finish the show. It only stops idle discovery/reconnect work.
  applyManualBanBoundary() {
    this._stopSupervisor();
    this.cancelArtNetDiscovery();
  }

  // N1: наблюдатель резервного звонаря A. Инъектируется из main.js только в packaged.
  // Все lifecycle/frame вызовы наблюдателя — fail-open и
  // НИКОГДА не влияют на вывод DMX (см. connect()/sendThrottled).
  setDmxObserver(obs) { this._dmxObserver = (obs && typeof obs === 'object') ? obs : null; }

  // N1-B: independent observer injection. Every call site has its own fail-open boundary.
  setDmxObserverB(obs) { this._dmxObserverB = (obs && typeof obs === 'object') ? obs : null; }

  setBeaconDiagnostics(observer) {
    this._beaconDiagnostics = observer && typeof observer === 'object' ? observer : null;
  }

  // Retain only the observer and its local number. No device identity/options cross
  // this boundary; a failed observer must leave every connection result unchanged.
  _beginBeaconAttempt(deviceId, options, opts) {
    try {
      const observer = this._beaconDiagnostics;
      if (!observer || typeof observer.beginAttempt !== 'function') return null;
      const device = this.lastScanResults.find(item => item.id === deviceId);
      const type = options.type === undefined ? device && device.type : options.type;
      const kind = type === 'artnet' ? 3 : type === 'sacn' ? 4
        : type === 'enttec-pro' || type === 'open-dmx' ? 2
          : type === 'udmx' || type === 'sunlite' || type === 'martin' ? 1 : 0;
      const manual = opts.manual === undefined ? true : !!opts.manual;
      const source = opts.beaconSource === 2 || opts.beaconSource === 3
        ? opts.beaconSource : manual ? 1 : 0;
      const id = observer.beginAttempt({ source, manual, kind });
      // No terminal outcome until a branch names one. A return path that forgets to
      // note its result then stays «outcome unknown» instead of being reported as an
      // exception; a rejected connect passes 5 explicitly.
      return Number.isSafeInteger(id) && id > 0 ? { observer, id, outcome: 0 } : null;
    } catch (_) { return null; }
  }

  _noteBeaconAttempt(attempt, fields, outcome) {
    try {
      if (!attempt) return;
      if (outcome !== undefined) attempt.outcome = outcome;
      attempt.observer.noteAttempt(attempt.id, fields);
    } catch (_) { /* observation must never affect DMX */ }
  }

  _finishBeaconAttempt(attempt, outcome) {
    try {
      const final = outcome === undefined ? (attempt && attempt.outcome) : outcome;
      // 0 = no branch named a result: leave the record pending (shown as unknown).
      if (attempt && final) attempt.observer.finishAttempt(attempt.id, final);
    } catch (_) { /* observation must never affect DMX */ }
  }

  _noteBeaconSelection(source, result) {
    try {
      if (this._beaconDiagnostics) this._beaconDiagnostics.noteSelection({ source, result });
    } catch (_) { /* observation must never affect DMX */ }
  }

  // Search refused by a barrier (5: Rubezh A, 6: R). A selection result, not an
  // attempt: repeated searches add to its counter instead of evicting attempts.
  _noteBlockedBeaconScan(opts, result) {
    try {
      const source = opts && (opts.beaconSource === 1 || opts.beaconSource === 2 || opts.beaconSource === 3)
        ? opts.beaconSource : 0;
      this._noteBeaconSelection(source, result);
    } catch (_) { /* observation must never affect DMX */ }
  }

  // The registry refuses a search under R before reaching any manager.
  noteBlockedBeaconScan(opts) {
    this._noteBlockedBeaconScan(opts, 6);
  }

  // The registry can reject before selecting a manager. Count exactly that
  // rejected request here; successful registry paths are counted by connect().
  noteBlockedBeaconAttempt(deviceId, options = {}, opts = {}) {
    try {
      const attempt = this._beginBeaconAttempt(deviceId, options, opts);
      this._noteBeaconAttempt(attempt, { phase: 0, admission: 2, deny: 1 }, 1);
      this._finishBeaconAttempt(attempt);
    } catch (_) { /* observation must never affect the registry barrier */ }
  }

  // Сырой снимок пропуска для точки наблюдения. Расшифровка secure-store дорога, поэтому на
  // горячем пути читаем не чаще EDGE_PASS_SNAPSHOT_TTL_MS; force=true — обновить сейчас (открытие
  // подключения — холодная точка). Ошибка чтения сохраняется как unknown, а не как
  // честное отсутствие пропуска (fail-open: наблюдение не трогает вывод).
  _edgePassSnapshot(force) {
    const obs = this._dmxObserver;
    if (!obs || typeof obs.readPass !== 'function') return { status: 'unknown', value: null };
    const nowMonoMs = edgeMonotonicNowMs();
    if (force || this._edgePassAtMonoMs == null
        || (nowMonoMs - this._edgePassAtMonoMs) > EDGE_PASS_SNAPSHOT_TTL_MS) {
      try { this._edgePass = normalizeEdgePassRead(obs.readPass()); }
      catch (_) { this._edgePass = normalizeEdgePassRead(null, true); }
      this._edgePassAtMonoMs = nowMonoMs;
    }
    return this._edgePass;
  }

  _edgePassSnapshotB(force) {
    const obs = this._dmxObserverB;
    if (!obs || typeof obs.readPass !== 'function') return { status: 'unknown', value: null };
    const nowMonoMs = edgeMonotonicNowMs();
    if (force || this._edgePassBAtMonoMs == null
        || (nowMonoMs - this._edgePassBAtMonoMs) > EDGE_PASS_SNAPSHOT_TTL_MS) {
      try { this._edgePassB = normalizeEdgePassRead(obs.readPass()); }
      catch (_) { this._edgePassB = normalizeEdgePassRead(null, true); }
      this._edgePassBAtMonoMs = nowMonoMs;
    }
    return this._edgePassB;
  }

  // Факты допуска для точки наблюдения. Момент допуска = сейчас: звонарь классифицирует кадр по
  // МОМЕНТУ ДОПУСКА, а не по времени физической отправки (§9-бис.3 п.2), поэтому для отложенного
  // throttle эти факты сохраняются вместе с кадром и уходят в колбэке без переоценки.
  _edgeFacts(force) {
    const admitAtSec = Math.floor(Date.now() / 1000);
    const admitMonoMs = edgeMonotonicNowMs();
    const passRead = this._edgePassSnapshot(force);
    return {
      transportId: this._edgeTransportId,
      adapter: this._edgeAdapter,
      passRead,
      // Compatibility evidence for the original N1 tests/callers. It is raw
      // input only; no ALLOW/proof verdict is produced here.
      rawPass: rawPassFromStatus(passRead),
      admitAtSec,
      admitMonoMs,
    };
  }

  _edgeFactsB(force) {
    const admitAtSec = Math.floor(Date.now() / 1000);
    const admitMonoMs = edgeMonotonicNowMs();
    const passRead = this._edgePassSnapshotB(force);
    return {
      transportId: this._edgeTransportId,
      adapter: this._edgeAdapter,
      passRead,
      rawPass: rawPassFromStatus(passRead),
      admitAtSec,
      admitMonoMs,
    };
  }

  _edgeConnectionFacts(force, reconnectAttemptId, previousTransportId) {
    const openedAtSec = Math.floor(Date.now() / 1000);
    const openedMonoMs = edgeMonotonicNowMs();
    const passRead = this._edgePassSnapshot(force);
    const facts = {
      transportId: this._edgeTransportId,
      adapter: this._edgeAdapter,
      passRead,
      rawPass: rawPassFromStatus(passRead),
      openedAtSec,
      openedMonoMs,
    };
    if (reconnectAttemptId) facts.reconnectAttemptId = reconnectAttemptId;
    if (previousTransportId) facts.previousTransportId = previousTransportId;
    return facts;
  }

  _edgeConnectionFactsB(force, reconnectAttemptId, previousTransportId) {
    const openedAtSec = Math.floor(Date.now() / 1000);
    const openedMonoMs = edgeMonotonicNowMs();
    const passRead = this._edgePassSnapshotB(force);
    const facts = {
      transportId: this._edgeTransportId,
      adapter: this._edgeAdapter,
      passRead,
      rawPass: rawPassFromStatus(passRead),
      openedAtSec,
      openedMonoMs,
    };
    if (reconnectAttemptId) facts.reconnectAttemptId = reconnectAttemptId;
    if (previousTransportId) facts.previousTransportId = previousTransportId;
    return facts;
  }

  _emit(event) {
    if (typeof this.onConnectionEvent === 'function') {
      try { this.onConnectionEvent(event); } catch (e) { /* ignore listener errors */ }
    }
  }

  /**
   * Транспорт увидел чужие ArtDmx в НАШЕМ юниверсе. Событие идёт наверх один раз на
   * источник (троттлинг — в наблюдателе транспорта), потому что кадры приходят 40 раз
   * в секунду. Свет не трогаем: решение, кого выключать, за человеком.
   */
  _onForeignSource(info) {
    const ip = info && info.ip ? String(info.ip) : '';
    const portAddress = info && Number.isFinite(Number(info.portAddress)) ? Number(info.portAddress) : null;
    const sources = (info && Array.isArray(info.sources)) ? info.sources : this.getForeignSources();
    this._rememberForeignSources(sources);
    this._emit({ type: 'foreign-source', ip, portAddress, sources });
  }

  /** Кто ещё вещает в наши юниверсы прямо сейчас. Пустой список — транспорт не сетевой. */
  getForeignSources() {
    const t = this.activeTransport;
    if (t && typeof t.foreignSources === 'function') {
      try {
        const live = t.foreignSources();
        if (Array.isArray(live) && live.length) {
          this._rememberForeignSources(live);
          return live;
        }
      } catch (e) { /* наблюдение не имеет права мешать выводу света */ }
    }
    // Отчёт поддержки собирают ПОСЛЕ того, как человек отключился или переподключился, —
    // а `close()` обнуляет наблюдателя. Без сохранённого снимка главная улика чужого
    // HTP-источника исчезала вместе с подключением, и жалоба «прибор живёт своей жизнью»
    // снова оказывалась недоказуемой (аудит 2026-09-05). Возраст помечаем явно, чтобы
    // старый снимок не читался как «прямо сейчас».
    const last = this._lastForeignSources;
    if (!last) return [];
    return last.sources.map((s) => ({ ...s, stale: true, capturedAt: last.capturedAt }));
  }

  /** Запомнить снимок чужих источников: он должен пережить закрытие транспорта. */
  _rememberForeignSources(sources) {
    if (!Array.isArray(sources) || !sources.length) return;
    this._lastForeignSources = { capturedAt: Date.now(), sources };
  }

  _persistDiagnostic(event) {
    // UDMX-006: shouldPersistEvent (not a bare level check) — a throttled
    // duplicate of a storm error keeps its WARN level for the in-memory ring but
    // must not reach app.log, or 25 lines/s bury every other module's logging.
    if (!shouldPersistEvent(event) || typeof this.onDiagnosticEvent !== 'function') return;
    try { this.onDiagnosticEvent(event); } catch { /* diagnostics must never affect DMX */ }
  }

  _recordDiagnostic(type, data = {}, options = {}) {
    const event = this._diagnostics.recordEvent(type, data, options);
    this._persistDiagnostic(event);
    return event;
  }

  _handleTransportDiagnostic(event, context) {
    if (!event || typeof event.type !== 'string') return;
    if (event.usbPresence && event.usbPresence.ok) {
      const signature = event.usbPresence.signature;
      if (signature !== this._lastUdmxPresenceSignature) {
        const previousSignature = this._lastUdmxPresenceSignature;
        this._lastUdmxPresenceSignature = signature;
        const devices = event.usbPresence.devices || [];
        this._recordDiagnostic('usb-presence-change', {
          source: event.type,
          previousSignature,
          signature,
          devices,
        }, { level: previousSignature == null ? null : 'WARN' });
        // UDMX-006: the single most valuable fact about an outage — did the stick
        // merely stall, or did it actually leave the bus (and for how long)?
        if (previousSignature != null) {
          // UDMX-010: "is OUR stick still there", not "is any uDMX still there".
          // The presence snapshot lists every uDMX-class device on the bus, so
          // with a second stick plugged in the answer stayed `true` while the
          // active one was gone — and «уходил ли прибор с шины» is the single
          // most valuable line of an outage record. The reconnect itself was
          // never affected (it matches by path), only the verdict was. Falls
          // back to the old any-device answer when the session has no USB path.
          const wantPath = context && context.device && context.device.path
            ? String(context.device.path).replace(/^usb:/, '')
            : null;
          const anyPresent = devices.length > 0;
          // Matching by location only works while the location is stable. Two
          // cases where it is not, and where answering "gone" forever would be a
          // worse lie than the old any-device answer: a location derived from the
          // volatile USB address (`1-a5`, used when portNumbers is unavailable —
          // see usbLocationOf) does not survive a re-enumeration, and a snapshot
          // taken without a bus number carries no path at all.
          const matchable = !!wantPath
            && !/-a\d+$/.test(wantPath)
            && devices.some(d => d.path != null);
          const present = matchable ? devices.some(d => d.path === wantPath) : anyPresent;
          this._diagnostics.noteDevicePresence(present);
          this._diagnostics.noteOutageStage(
            present ? 'device-back' : 'device-gone',
            // Both facts, so a report never has to guess which question was
            // answered: ours specifically, or "some uDMX is still there".
            { signature: signature || null, path: wantPath, matchedByPath: matchable, anyPresent },
          );
        }
      }
    }
    // UDMX-006: ladder milestones land in the outage record, so one line of the
    // journal tells the whole story instead of ten scattered events.
    if (event.type === 'udmx-recovery-step') {
      this._diagnostics.noteOutageStage(event.step || 'step', {
        ok: !!event.ok,
        outageMs: event.outageMs == null ? null : event.outageMs,
      }, { sessionId: context.sessionId });
    } else if (event.type === 'udmx-storm-backoff') {
      this._diagnostics.noteOutageStage('storm-backoff', {
        retryIntervalMs: event.retryIntervalMs || null,
      }, { sessionId: context.sessionId });
    } else if (event.type === 'udmx-recovery-failed') {
      this._diagnostics.noteOutageStage('give-up', {
        reason: event.reason || null,
        outageMs: event.outageMs == null ? null : event.outageMs,
      }, { sessionId: context.sessionId });
    }
    if (event.type === 'frame-coalesced') {
      this._diagnostics.recordCoalesced();
      return;
    }
    // UDMX-004: the link is misbehaving but the device is still ours — surface it
    // as «восстановление связи», NOT as a disconnect. A hard drop (transport-lost)
    // is still reported the old way; this only covers outages we are healing.
    if (event.type === 'recovery-state') {
      const degraded = event.state === 'degraded';
      this._recordDiagnostic('transport-recovery-state', {
        sessionId: context.sessionId,
        device: context.device,
        state: event.state || null,
        reason: event.reason || null,
        outageMs: event.outageMs == null ? null : event.outageMs,
      }, { level: degraded ? 'WARN' : 'INFO' });
      this._degradedActive = degraded;
      this._emit({
        type: degraded ? 'degraded' : 'recovered',
        deviceName: this._activeName(),
        reason: event.reason || null,
        outageMs: event.outageMs == null ? null : event.outageMs,
      });
      return;
    }
    if (event.type === 'transfer-result') {
      const stored = this._diagnostics.recordTransfer({
        ...event,
        sessionId: context.sessionId,
        device: context.device,
        // 2026-09-11: уровень подтверждения — свойство ТРАНСПОРТА, а не кадра, поэтому
        // спрашивается один раз при подключении и штампуется здесь. Горячий путь
        // отправки (40 кадров в секунду у каждого транспорта) о нём ничего не знает.
        confirmation: event.confirmation || context.confirmation || null,
      });
      stored.forEach(item => this._persistDiagnostic(item));
      // UDMX-006: an outage lasts from the first failed frame until one really
      // gets through — across give-ups, reconnects and re-enumerations, because
      // that is the single hole the user saw on stage.
      if (event.success) {
        this._diagnostics.endOutage('recovered');
        this._confirmReconnectAfterTransfer(context, event);
      } else {
        this._diagnostics.noteOutageError({
          kind: (event.error && event.error.kind) || 'OTHER',
          sessionId: context.sessionId,
        });
      }
      return;
    }

    const levelByType = {
      'transport-open-failed': 'WARN',
      'usb-attach': 'INFO',
      'usb-detach': 'WARN',
      // WHICH backend opened a Nicolaudie box (DHDK; the DasHard2006 fallback was
      // removed 2026-09-30) and under what full name — the first line of any case
      // about that hardware.
      // Without a level the event lived only in the report ring, and app.log (which
      // clients send more often than the report) never carried it at all, even
      // though both the code comment and ДОК/DMX_CONTROLLER_TROUBLESHOOTING promised it.
      'sunlite-open': 'INFO',
      'martin-open': 'INFO',
    };
    const details = { ...event };
    delete details.type;
    this._recordDiagnostic(event.type, {
      sessionId: context.sessionId,
      device: context.device,
      ...details,
    }, { level: levelByType[event.type] || null });
  }

  _bindTransportDiagnostics(transport, deviceInfo) {
    const context = {
      sessionId: ++this._diagnosticSessionSeq,
      device: cleanDeviceInfo(deviceInfo),
      // Чем этот транспорт подтверждает переданный кадр (см. CONFIRMATION_MEANING).
      // Берётся у уже созданного транспорта до open(): свойство объявляется в
      // конструкторе и за время подключения не меняется.
      confirmation: transport && transport.transferConfirmation ? transport.transferConfirmation : null,
    };
    transport.onDiagnostic = event => this._handleTransportDiagnostic(event, context);
    return context;
  }

  // `opts.beaconSource` only labels the optional observation of a blocked search.
  async scan(opts) {
    const scanStartedAtMs = Date.now();
    let deferredBlocked = false;
    let manualBlocked = false;
    if (this._licenseSuspended || (deferredBlocked = isDeferredConnectionBlocked())
        || (manualBlocked = isManualConnectionBlocked())) {
      this.lastScanResults = [];
      this._lastSerialScan = {
        startedAt: new Date(scanStartedAtMs).toISOString(),
        completedAt: new Date().toISOString(),
        blocked: true,
        physicalPortCount: 0,
        entryCount: 0,
        devices: [],
        errors: [],
      };
      // A blocked search returns an empty list, so the UI never gets a device to
      // connect: without this record "0 attempts" would look like nobody tried.
      if (deferredBlocked || manualBlocked) this._noteBlockedBeaconScan(opts, deferredBlocked ? 5 : 6);
      return [];
    }
    const results = [];
    const serialResults = [];
    const serialErrors = [];

    // 1. uDMX (synchronous)
    try {
      const udmxResults = UdmxTransport.scan();
      // DMXMGR-002: usb.getDeviceList() order is not guaranteed stable — sort by
      // the stable USB-location path so two identical uDMX sticks keep a fixed
      // order in the UI list (and the reconnect fallback is deterministic).
      udmxResults.sort(compareDevicesStable);
      results.push(...udmxResults);
    } catch (e) {
      console.log('⚠️ uDMX scan failed:', e.message);
    }

    // 2. Serial: Open DMX (async) — FTDI и CH340.
    //    На один порт мы возвращаем ДВА варианта (Open DMX + Enttec Pro), чтобы пользователь
    //    мог явно выбрать протокол. Свистки на одном и том же чипе бывают двух типов:
    //      • bare USB-serial → говорит на Open DMX (250 kbaud + ручной break/MAB)
    //      • с прошивкой Enttec → говорит на Enttec Pro (57600 baud, пакеты 0x7E/0xE7)
    //    autoConnect выбирает default по vendorId (см. ниже).
    try {
      const openDmxResults = await FtdiOpenDmxTransport.scan();
      // DMXMGR-002: SerialPort.list() order is OS-dependent and unstable between
      // scans — sort to a deterministic order so two identical FTDI sticks never
      // swap places in the UI list or the reconnect fallback.
      openDmxResults.sort(compareDevicesStable);
      results.push(...openDmxResults);
      serialResults.push(...openDmxResults);
    } catch (e) {
      console.log('⚠️ Open DMX scan failed:', e.message);
      serialErrors.push({
        transport: 'open-dmx',
        message: String(e && e.message ? e.message : e).slice(0, SERIAL_SCAN_ERROR_MAX_CHARS),
      });
    }

    // 3. Serial: Enttec Pro (async) — FTDI и CH340, БЕЗ дедупликации с Open DMX.
    try {
      const enttecResults = await EnttecProTransport.scan();
      enttecResults.sort(compareDevicesStable); // DMXMGR-002: deterministic order (see above)
      results.push(...enttecResults);
      serialResults.push(...enttecResults);
    } catch (e) {
      console.log('⚠️ Enttec Pro scan failed:', e.message);
      serialErrors.push({
        transport: 'enttec-pro',
        message: String(e && e.message ? e.message : e).slice(0, SERIAL_SCAN_ERROR_MAX_CHARS),
      });
    }

    // 4. Sunlite / Nicolaudie (async — enumerated via the 32-bit SDK sidecar).
    //    Returns [] instantly when no Nicolaudie USB device is present.
    try {
      const sunliteResults = await SunliteTransport.scan();
      sunliteResults.sort(compareDevicesStable); // DMXMGR-002: deterministic order
      results.push(...sunliteResults);
    } catch (e) {
      console.log('⚠️ Sunlite scan failed:', e.message);
    }

    // Martin/Jungo has no COM port. PnP-only scan must not touch an active SDK session.
    try {
      const martinResults = await MartinTransport.scan();
      martinResults.sort(compareDevicesStable);
      results.push(...martinResults);
    } catch (e) {
      console.log('⚠️ Martin scan failed:', e.message);
      this._recordDiagnostic('martin-scan-failed', {
        error: { kind: 'MARTIN_SCAN_FAILED', message: String(e.message || e).slice(0, SERIAL_SCAN_ERROR_MAX_CHARS), code: e.code || null },
      }, { level: 'WARN' });
    }

    // 5. Art-Net (always available)
    results.push(...ArtNetTransport.scan());

    // 6. sACN / E1.31 (always available)
    results.push(...SacnTransport.scan());

    this.lastScanResults = results;
    this._lastSerialScan = {
      startedAt: new Date(scanStartedAtMs).toISOString(),
      completedAt: new Date().toISOString(),
      blocked: false,
      physicalPortCount: new Set(serialResults.map(device => device.path).filter(Boolean)).size,
      entryCount: serialResults.length,
      devices: serialResults.map(cleanDeviceInfo),
      errors: serialErrors,
    };
    console.log(`🔍 Найдено интерфейсов: ${results.length}`);
    return results;
  }

  // MULTI-OUTPUT (2026-09-13): with several interfaces open at once the bus is
  // scanned ONCE (by the registry, see dmx/DmxOutputs.js) and the inventory is
  // handed to every output's manager, so a second output can open a device by id
  // without starting a competing scan of the same USB bus. connect() resolves the
  // id against this list, so without it a secondary output would answer
  // «Устройство не найдено».
  setScanResults(results) {
    this.lastScanResults = Array.isArray(results) ? results : [];
  }

  // `manual` = explicit user action (IPC dmx-connect / dmx-auto-connect): only
  // then do we clear userDisconnected. The supervisor calls with manual:false so
  // an auto-reconnect NEVER overrides a manual «Отключить» (DMX-004 invariant 1).
  // Public connect — serialized via _connectLock (BUG-005). Two rapid IPC connects could
  // otherwise both pass the (null) activeTransport check during the async open() and leave
  // the first transport orphaned: open, clocking the wire, leaking the serial/USB handle.
  // The queued connect runs only after the previous one fully settles, so its
  // _teardownActive() closes the prior transport before a new one opens.
  async connect(deviceId, options = {}, opts = {}) {
    const attempt = this._beginBeaconAttempt(deviceId, options, opts);
    let deferredBlocked = false;
    let manualBlocked = false;
    if (this._licenseSuspended || (deferredBlocked = isDeferredConnectionBlocked())
        || (manualBlocked = isManualConnectionBlocked())) {
      this._noteBeaconAttempt(attempt, { phase: 0, admission: 2, deny: deferredBlocked ? 4 : manualBlocked ? 1 : 0 }, 1);
      this._finishBeaconAttempt(attempt);
      return { success: false, ...deferredConnectResult(this._licenseSuspended) };
    }
    const run = this._connectLock.then(() => this._doConnect(deviceId, options, opts, attempt));
    this._connectLock = run.then(
      () => { this._finishBeaconAttempt(attempt); },
      () => { this._finishBeaconAttempt(attempt, 5); },
    ); // keep the chain alive past rejections; both callbacks still return undefined
    return run;
  }

  async _doConnect(deviceId, options = {}, { manual = true } = {}, attempt = null) {
    // Re-check inside the serialized critical section: a queued connection may have waited
    // behind another open while logout/A transitioned at the boundary.
    this._noteBeaconAttempt(attempt, { phase: 1 });
    let deferredBlocked = false;
    let manualBlocked = false;
    if (this._licenseSuspended || (deferredBlocked = isDeferredConnectionBlocked())
        || (manualBlocked = isManualConnectionBlocked())) {
      this._noteBeaconAttempt(attempt, { admission: 2, deny: deferredBlocked ? 4 : manualBlocked ? 1 : 0 }, 1);
      return { success: false, ...deferredConnectResult(this._licenseSuspended) };
    }
    this._noteBeaconAttempt(attempt, { admission: 1 });
    if (manual) this.userDisconnected = false;
    const replacingActiveTransport = !!this.activeTransport;
    await this._teardownActive(
      replacingActiveTransport ? 'device_change' : 'ordinary_teardown',
      { preserveReconnectLease: !manual },
    );

    this._noteBeaconAttempt(attempt, { phase: 2 });
    // Teardown is asynchronous. R/A/logout or an explicit disconnect may land
    // while the previous handle is closing; re-check before even constructing
    // and opening the replacement so self-clocked transports and sidecars never
    // start work during that gap. The post-open check below remains the second
    // barrier for a transition that happens inside transport.open().
    deferredBlocked = false;
    manualBlocked = false;
    if (this.userDisconnected || this._licenseSuspended
        || (deferredBlocked = isDeferredConnectionBlocked())
        || (manualBlocked = isManualConnectionBlocked())) {
      this._noteBeaconAttempt(attempt, this.userDisconnected ? {} : {
        admission: 2, deny: deferredBlocked ? 4 : manualBlocked ? 1 : 0,
      }, this.userDisconnected ? 6 : 1);
      return this.userDisconnected
        ? { success: false, error: 'Отключено пользователем' }
        : { success: false, ...deferredConnectResult(this._licenseSuspended) };
    }
    const deviceInfo = this.lastScanResults.find(d => d.id === deviceId);
    if (!deviceInfo) {
      this._noteBeaconAttempt(attempt, {}, 2);
      return { success: false, error: 'Устройство не найдено. Выполните повторное сканирование.' };
    }

    const mergedInfo = { ...deviceInfo, ...options };
    const edgeAdapter = normalizeEdgeAdapter(mergedInfo);

    let transport;
    switch (mergedInfo.type) {
      case 'udmx':
        transport = new UdmxTransport(mergedInfo);
        break;
      case 'enttec-pro':
        transport = new EnttecProTransport(mergedInfo);
        break;
      case 'open-dmx':
        transport = new FtdiOpenDmxTransport(mergedInfo);
        break;
      case 'artnet':
        transport = new ArtNetTransport(mergedInfo);
        break;
      case 'sunlite':
        transport = new SunliteTransport(mergedInfo);
        break;
      case 'martin':
        transport = new MartinTransport(mergedInfo);
        break;
      case 'sacn':
        transport = new SacnTransport(mergedInfo);
        break;
      default:
        this._noteBeaconAttempt(attempt, {}, 3);
        return { success: false, error: `Неизвестный тип интерфейса: ${mergedInfo.type}` };
    }

    const diagnosticContext = this._bindTransportDiagnostics(transport, mergedInfo);
    this._recordDiagnostic('connect-attempt', {
      sessionId: diagnosticContext.sessionId,
      device: diagnosticContext.device,
      manual,
    });

    // Every automatic OPEN attempt is a separate fact, including failures.
    // Manual attempts deliberately carry no previous-transport lease.
    const reconnectAttemptId = manual ? null : nextEdgeReconnectAttemptId();
    const previousTransportId = manual ? null : this._edgeReconnectPreviousTransportId;
    if (!manual && this._dmxObserver && typeof this._dmxObserver.noteReconnectAttempt === 'function') {
      try {
        this._dmxObserver.noteReconnectAttempt({
          attemptId: reconnectAttemptId,
          previousTransportId,
          adapter: edgeAdapter,
          attemptMonoMs: edgeMonotonicNowMs(),
        });
      } catch (_) { /* N1 fail-open */ }
    }
    if (!manual && this._dmxObserverB && typeof this._dmxObserverB.noteReconnectAttempt === 'function') {
      try {
        this._dmxObserverB.noteReconnectAttempt({
          attemptId: reconnectAttemptId,
          previousTransportId,
          adapter: edgeAdapter,
          attemptMonoMs: edgeMonotonicNowMs(),
        });
      } catch (_) { /* N1-B fail-open */ }
    }
    this._noteBeaconAttempt(attempt, { phase: 3 });
    const success = await transport.open();
    // close↔reconnect race: the user may have pressed «Отключить» while the port
    // was opening (open() yields to the event loop). At that point activeTransport
    // was still null, so disconnect()'s teardown couldn't close this transport.
    // Re-check the flag now and honour it — never leave an orphaned live transport
    // clocking the wire against the user's explicit disconnect.
    if (success && (this.userDisconnected || this._licenseSuspended
        || (deferredBlocked = isDeferredConnectionBlocked())
        || (manualBlocked = isManualConnectionBlocked()))) {
      // A user's «Отключить» cancels an admitted attempt; only a barrier or a
      // license clear withdraws the admission itself.
      this._noteBeaconAttempt(attempt, this.userDisconnected ? {} : {
        admission: 2, deny: deferredBlocked ? 4 : manualBlocked ? 1 : 0,
      }, 6);
      try { await transport.close(); } catch (e) { /* dead device */ }
      transport.onDiagnostic = null;
      this._recordDiagnostic('connect-aborted-by-user', {
        sessionId: diagnosticContext.sessionId,
        device: diagnosticContext.device,
      }, { level: 'INFO' });
      return this.userDisconnected
        ? { success: false, error: 'Отключено пользователем' }
        : { success: false, ...deferredConnectResult(this._licenseSuspended) };
    }
    if (success) {
      this.activeTransport = transport;
      this._activeDiagnosticSession = diagnosticContext;
      // N1 — безопасная точка «подключение открыто» (ТЗ звонарей §12): успешное открытие уже
      // ПОСЛЕ connGate (isDeferredConnectionBlocked выше честь уже отдали). Сообщаем звонарю факт
      // и даём ему безопасную точку отправки (kick). Снимок пропуска обновляем принудительно —
      // это холодная точка. Всё под try/catch: наблюдение НИКОГДА не влияет на подключение.
      this._edgeTransportId = nextEdgeTransportId();
      this._edgeAdapter = edgeAdapter;
      if (this._dmxObserver) {
        let facts = null;
        try { facts = this._edgeConnectionFacts(true, reconnectAttemptId, previousTransportId); }
        catch (_) { /* fail-open */ }
        if (facts && typeof this._dmxObserver.noteConnectionOpen === 'function') {
          try { this._dmxObserver.noteConnectionOpen(facts); } catch (_) { /* fail-open */ }
        }
        if (typeof this._dmxObserver.kick === 'function') {
          try { Promise.resolve(this._dmxObserver.kick('connect')).catch(() => {}); }
          catch (_) { /* fail-open */ }
        }
      }
      if (this._dmxObserverB) {
        let factsB = null;
        try { factsB = this._edgeConnectionFactsB(true, reconnectAttemptId, previousTransportId); }
        catch (_) { /* fail-open */ }
        if (factsB && typeof this._dmxObserverB.noteConnectionOpen === 'function') {
          try { this._dmxObserverB.noteConnectionOpen(factsB); } catch (_) { /* N1-B fail-open */ }
        }
        if (typeof this._dmxObserverB.kick === 'function') {
          try { Promise.resolve(this._dmxObserverB.kick('connect')).catch(() => {}); }
          catch (_) { /* N1-B fail-open */ }
        }
      }
      // A successful linked auto-open consumed the unexpected-loss lease. A
      // manual open never reaches this point with a retained lease: teardown
      // above revoked it as ordinary_teardown.
      this._edgeReconnectPreviousTransportId = null;
      this._edgeReconnectAdapter = null;
      // Remember what we connected to, and wire unplug detection (DMX-004).
      this.lastConnect = { deviceInfo, options };
      transport.onDisconnect = (reason) => this._onTransportLost(reason);
      // Чужой источник света в сети (Art-Net HTP-мерж) — наблюдение, а не авария:
      // подключение остаётся рабочим, наверх уходит предупреждение (см.
      // dmx/artnet/foreignSourceWatch.js и разбор в DMX_CONTROLLER_TROUBLESHOOTING §7).
      transport.onForeignSource = (info) => this._onForeignSource(info);
      const needsProof = this._lostActive
        && transport.requiresDmxTransferConfirmation === true;
      // Proof is only demanded while it is achievable: it needs a frame the output
      // gates already allowed AND a licence that still lets frames reach the wire.
      // Without both, the badge could never turn green again — an amber deadlock is
      // worse than the pre-verification behaviour.
      const awaitingFirstDmx = needsProof && this._canProveReconnect();
      this._noteBeaconAttempt(attempt, { phase: awaitingFirstDmx ? 5 : 4 }, 7);
      this._reconnectVerificationSessionId = awaitingFirstDmx
        ? diagnosticContext.sessionId
        : null;
      // UDMX-010: a fresh session opened inside an outage IS a reconnect, and
      // this is what finally fills outageJournal.reconnectCount — the counter
      // existed from UDMX-006 but could only ever read 0, because no caller
      // recorded the 'reconnect' stage.
      if (this._lostActive) {
        this._diagnostics.noteOutageStage('reconnect', {
          awaitingFirstDmx,
          manual,
        }, { sessionId: diagnosticContext.sessionId });
      }
      this._recordDiagnostic('connect-success', {
        sessionId: diagnosticContext.sessionId,
        device: diagnosticContext.device,
        manual,
        awaitingFirstDmx,
      }, { level: this._lostActive ? 'INFO' : null });
      if (awaitingFirstDmx) {
        // For direct IPC connects, let the invoke() response update the renderer's
        // amber state before requesting a frame. Supervisor reconnects have no
        // response race and can request it immediately.
        if (manual) setImmediate(() => this._sendReconnectProbe(diagnosticContext.sessionId));
        else this._sendReconnectProbe(diagnosticContext.sessionId);
      } else if (this._lostActive) {
        if (needsProof) {
          this._recordDiagnostic('reconnect-verification-unavailable', {
            sessionId: diagnosticContext.sessionId,
            device: diagnosticContext.device,
            reason: this._lastPermittedDmxFrames.has(1) ? 'license-gate' : 'no-frame',
          }, { level: 'WARN' });
        }
        // Nothing provable (a transport without transfer confirmation, or no
        // achievable proof): finish the reconnect right here. A manual connect
        // during an outage used to leave _lostActive latched — only the supervisor
        // path cleared it — which silently disarmed the drop handler for the NEXT
        // outage (_onTransportLost returns early while the latch is set).
        this._completeReconnect({ confirmation: 'open' });
      }
      return { success: true, awaitingFirstDmx };
    } else {
      this._noteBeaconAttempt(attempt, {}, 4);
      transport.onDiagnostic = null;
      this._recordDiagnostic('connect-failed', {
        sessionId: diagnosticContext.sessionId,
        device: diagnosticContext.device,
        manual,
        error: transport.lastError || null,
      }, { level: 'WARN' });
      return { success: false, error: transport.lastError || 'Не удалось подключиться' };
    }
  }

  // Public intentional disconnect. Existing callers omit the argument and keep
  // the user-action cause; main.js supplies shutdown during process teardown.
  async disconnect(cause = 'manual_disconnect') {
    const closeCause = EDGE_CLOSE_CAUSES.has(cause) ? cause : 'manual_disconnect';
    this._recordDiagnostic(closeCause === 'manual_disconnect' ? 'manual-disconnect' : 'intentional-disconnect', {
      sessionId: this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId,
      device: this._activeDiagnosticSession && this._activeDiagnosticSession.device,
      cause: closeCause,
    }, { level: 'INFO' });
    this.userDisconnected = true;
    this._lostActive = false;
    this._lostAtMs = null;
    this._cancelReconnectVerification();
    this._lastAutoResultSig = null;
    this._stopSupervisor();
    await this._teardownActive(closeCause); // also clears throttle/lastData/lastWasBlackout
    // UDMX-010: an outage stays open until a frame really gets through, and after
    // «Отключить» no frame ever will. It would sit open indefinitely and then be
    // filed by the NEXT successful transfer with all the deliberate offline time
    // inside its duration — corrupting the one number support reads to judge how
    // long the hole actually was. `closed` also keeps it out of the `minor`
    // counter: an outage nobody resolved is not a background STALL.
    this._diagnostics.endOutage('closed');
    this.lastConnect = null;
    this._activeDiagnosticSession = null;
    this._lastPermittedDmxFrames.clear();
  }

  // Authoritative license-clear boundary. Close the physical output but preserve reconnect
  // intent (lastConnect/userDisconnected) so a later independently verified login can resume
  // automatically. The suspension flag also closes the async-open race.
  async suspendForLicenseClear() {
    this._licenseSuspended = true;
    this._stopSupervisor();
    this._cancelReconnectVerification();
    await this._teardownActive('license_clear');
    this._diagnostics.endOutage('closed'); // same reason as disconnect() above
  }

  // Called only after main/TokenValidator accepted a fresh token. The gates independently
  // verify it before allowing output; kickSupervisor merely resumes the ordinary attempt loop.
  resumeAfterVerifiedToken() {
    this._licenseSuspended = false;
    this.kickSupervisor();
  }

  // Closes the active transport and clears the throttle timer, WITHOUT touching
  // reconnect/userDisconnected state. Shared by connect() and _onTransportLost().
  async _teardownActive(cause = 'ordinary_teardown', { notifyClosed = true, preserveReconnectLease = false } = {}) {
    const closeCause = EDGE_CLOSE_CAUSES.has(cause) ? cause : 'ordinary_teardown';
    const edgeTransportId = this._edgeTransportId;
    const edgeAdapter = this._edgeAdapter;
    // UDMX-004: a transport being torn down can never finish healing — clear the
    // degraded latch so a later reconnect starts from a clean status.
    this._degradedActive = false;
    this._cancelReconnectVerification();
    if (this.activeTransport) {
      const t = this.activeTransport;
      const diagnosticContext = this._activeDiagnosticSession;
      try {
        banGate.noteSessionClosed(this._outputId, diagnosticContext && diagnosticContext.sessionId);
      } catch (_) { /* R must never make teardown throw */ }
      // Улики чужого источника снимаем ДО закрытия: close() обнуляет наблюдателя, а
      // отчёт поддержки почти всегда собирают уже после отключения (аудит 2026-09-05).
      if (typeof t.foreignSources === 'function') {
        try { this._rememberForeignSources(t.foreignSources()); } catch (e) { /* dead device */ }
      }
      this.activeTransport = null;
      t.onDisconnect = null; // detach before close so close() can't re-fire it
      if (notifyClosed && edgeTransportId && this._dmxObserver
          && typeof this._dmxObserver.noteTransportClosed === 'function') {
        try {
          this._dmxObserver.noteTransportClosed({
            transportId: edgeTransportId,
            adapter: edgeAdapter,
            cause: closeCause,
          });
        } catch (_) { /* N1 fail-open */ }
      }
      if (notifyClosed && edgeTransportId && this._dmxObserverB
          && typeof this._dmxObserverB.noteTransportClosed === 'function') {
        try {
          this._dmxObserverB.noteTransportClosed({
            transportId: edgeTransportId,
            adapter: edgeAdapter,
            cause: closeCause,
          });
        } catch (_) { /* N1-B fail-open */ }
      }
      this._recordDiagnostic('teardown-started', {
        sessionId: diagnosticContext && diagnosticContext.sessionId,
        device: diagnosticContext && diagnosticContext.device,
      });
      // Bound the wait: a hung device's close() can never resolve (DMXMGR-003).
      // closeWithTimeout swallows close() errors itself, so no try/catch needed.
      const { timedOut } = await closeWithTimeout(t, TEARDOWN_TIMEOUT_MS);
      t.onDiagnostic = null;
      this._activeDiagnosticSession = null;
      this._recordDiagnostic('teardown-finished', {
        sessionId: diagnosticContext && diagnosticContext.sessionId,
        device: diagnosticContext && diagnosticContext.device,
        timedOut,
      }, { level: timedOut ? 'WARN' : null });
      if (timedOut) {
        console.log(`⚠️ DMX teardown: close() не ответил за ${TEARDOWN_TIMEOUT_MS} мс — старый транспорт отброшен (orphan), продолжаем`);
      }
    }

    // An unexpected-loss lease outlives the dead transport so the automatic
    // successor can claim it. Every intentional boundary revokes that lease,
    // even when the device was already physically gone and activeTransport=null.
    if (!preserveReconnectLease && this._edgeReconnectPreviousTransportId) {
      if (notifyClosed && this._dmxObserver
          && typeof this._dmxObserver.noteTransportClosed === 'function') {
        try {
          this._dmxObserver.noteTransportClosed({
            transportId: this._edgeReconnectPreviousTransportId,
            adapter: this._edgeReconnectAdapter,
            cause: closeCause,
          });
        } catch (_) { /* N1 fail-open */ }
      }
      if (notifyClosed && this._dmxObserverB
          && typeof this._dmxObserverB.noteTransportClosed === 'function') {
        try {
          this._dmxObserverB.noteTransportClosed({
            transportId: this._edgeReconnectPreviousTransportId,
            adapter: this._edgeReconnectAdapter,
            cause: closeCause,
          });
        } catch (_) { /* N1-B fail-open */ }
      }
      this._edgeReconnectPreviousTransportId = null;
      this._edgeReconnectAdapter = null;
    }
    for (const s of this.throttle.values()) {
      if (s.sendTimeout) clearTimeout(s.sendTimeout);
    }
    this.throttle.clear();
    // A late close must never erase a newer transport that opened while the old
    // native close callback was still pending.
    if (this._edgeTransportId === edgeTransportId) {
      this._edgeTransportId = null;
      this._edgeAdapter = null;
    }
  }

  // ─── Connection supervisor (DMX-004) ──────────────────────────────────────
  // One mechanism keeps a connection alive while the window is active and the
  // user hasn't manually disconnected:
  //   • lastConnect set  → reconnect to the SAME device that was lost (drop).
  //   • lastConnect null → cold-start auto-connect (autoConnect picks the single
  //     unambiguous device; with several devices it waits for a manual choice).
  // Minimized window pauses the loop entirely (no scanning/reconnect).

  // Public: window minimize/restore from main.js.
  setWindowActive(active) {
    this.windowActive = !!active;
    this._recordDiagnostic('window-activity-changed', {
      active: this.windowActive,
      reconnectPaused: !this.windowActive && !this.activeTransport,
    });
    if (this.windowActive) this.kickSupervisor();
    else this._stopSupervisor(); // pause; intent (lastConnect/userDisconnected) is kept
  }

  // Public: start keeping a connection alive (called at app start by main.js).
  kickSupervisor() {
    if (this.supervising || this.supervisorTimer || !this._shouldSupervise()) return;
    this.supervising = true;
    this._watchUsbAttach();
    this._supervisorTick(); // first attempt immediately, then every interval
  }

  _shouldSupervise() {
    return !this._licenseSuspended
      && !isDeferredConnectionBlocked()
      && !isManualConnectionBlocked()
      && !this.activeTransport
      && !this.userDisconnected
      && this.windowActive;
  }

  _activeName() {
    return this.activeTransport && this.activeTransport.getDisplayName
      ? this.activeTransport.getDisplayName() : null;
  }

  // Called by a transport when it detects the device physically vanished.
  _onTransportLost(reason) {
    if (this.userDisconnected) return; // intentional close — not a drop
    const verificationFailed = this._reconnectVerificationSessionId != null;
    if (this._lostActive && !verificationFailed) return; // already handling a loss
    const lostTransportId = this._edgeTransportId;
    const lostAdapter = this._edgeAdapter;
    if (lostTransportId) {
      this._edgeReconnectPreviousTransportId = lostTransportId;
      this._edgeReconnectAdapter = lostAdapter;
      if (this._dmxObserver && typeof this._dmxObserver.noteTransportLost === 'function') {
        try {
          this._dmxObserver.noteTransportLost({
            transportId: lostTransportId,
            adapter: lostAdapter,
            lostMonoMs: edgeMonotonicNowMs(),
          });
        } catch (_) { /* N1 fail-open */ }
      }
      if (this._dmxObserverB && typeof this._dmxObserverB.noteTransportLost === 'function') {
        try {
          this._dmxObserverB.noteTransportLost({
            transportId: lostTransportId,
            adapter: lostAdapter,
            lostMonoMs: edgeMonotonicNowMs(),
          });
        } catch (_) { /* N1-B fail-open */ }
      }
    }
    console.log(`⚠️ DMX устройство потеряно (${reason}) — запуск авто-переподключения`);
    const firstLoss = !this._lostActive;
    if (firstLoss) this._lostAtMs = Date.now();
    this._recordDiagnostic('transport-lost', {
      sessionId: this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId,
      device: this._activeDiagnosticSession && this._activeDiagnosticSession.device,
      reason: reason || null,
      windowActive: this.windowActive,
      reconnectVerificationFailed: verificationFailed,
    }, { level: 'ERROR' });
    // UDMX-006: `open: true` — a clean unplug (NO_DEVICE) produces no error run
    // of its own, and it is still an outage the user lived through.
    this._diagnostics.noteOutageStage('lost', {
      reason: reason || null,
      reconnectVerificationFailed: verificationFailed,
    }, {
      open: true,
      sessionId: this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId,
    });
    this._lostActive = true;
    this._cancelReconnectVerification();
    if (firstLoss) {
      this._emit({ type: 'lost', reason: reason || null, deviceName: this._activeName() });
      if (this.lastConnect) {
        this._emit({ type: 'reconnecting', deviceName: this.lastConnect.deviceInfo.name || null });
      }
    }
    this._teardownActive('ordinary_teardown', {
      notifyClosed: false,
      preserveReconnectLease: true,
    }).finally(() => this.kickSupervisor());
  }

  _cancelReconnectVerification() {
    if (this._reconnectProbeTimer) {
      clearTimeout(this._reconnectProbeTimer);
      this._reconnectProbeTimer = null;
    }
    if (this._reconnectVerificationSessionId == null) return false;
    this._reconnectVerificationSessionId = null;
    return true;
  }

  // Can a provisional session ever prove itself? Only with a frame the output
  // gates already allowed and a licence that still permits output — the probe
  // deliberately reuses sendThrottled and never bypasses either.
  _canProveReconnect() {
    if (!this._lastPermittedDmxFrames.has(1)) return false;
    if (this._licenseGate && !this._licenseGate()) return false;
    try {
      const sessionId = this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId;
      if (!banGate.maySendFrame(this._outputId, sessionId)) return false;
    } catch (_) { return false; }
    return true;
  }

  // Re-offers the proof frame at the transport's own frame clock until the link
  // is confirmed or given up. A single attempt is not enough: one failed frame
  // leaves the uDMX recovery ladder one error in, and with the renderer's output
  // gate shut nothing else would ever drive it to its verdict — the badge would
  // stay amber forever with no further reconnect attempt.
  _sendReconnectProbe(sessionId) {
    if (this._reconnectVerificationSessionId !== sessionId) return;
    const transport = this.activeTransport;
    if (!transport) return; // torn down — teardown/lost already cancelled the probe
    if (!this._canProveReconnect()) {
      // The licence closed mid-outage: no frame can reach the wire any more, so
      // holding the session provisional would deadlock the badge.
      this._recordDiagnostic('reconnect-verification-unavailable', {
        sessionId,
        device: this._activeDiagnosticSession && this._activeDiagnosticSession.device,
        reason: 'license-gate',
      }, { level: 'WARN' });
      this._cancelReconnectVerification();
      this._completeReconnect({ confirmation: 'open' });
      return;
    }
    this.sendThrottled(1, this._lastPermittedDmxFrames.get(1));
    // Same cadence as normal output: the transport's recovery thresholds are
    // calibrated for that clock, so the outage plays out exactly as it would
    // with the renderer feeding frames.
    const intervalMs = transport.minFrameIntervalMs || DEFAULT_FRAME_INTERVAL_MS;
    this._reconnectProbeTimer = setTimeout(() => {
      this._reconnectProbeTimer = null;
      this._sendReconnectProbe(sessionId);
    }, intervalMs);
    if (typeof this._reconnectProbeTimer.unref === 'function') this._reconnectProbeTimer.unref();
  }

  _completeReconnect({ confirmation, sessionId = null, transferSequence = null } = {}) {
    if (!this._lostActive) return false;
    if (this._reconnectVerificationSessionId != null) {
      if (confirmation !== 'dmx-transfer'
          || sessionId !== this._reconnectVerificationSessionId) return false;
    }

    const downtimeMs = this._lostAtMs == null ? null : Date.now() - this._lostAtMs;
    this._lostActive = false;
    this._cancelReconnectVerification();
    console.log('✅ DMX переподключён');
    this._recordDiagnostic('transport-reconnected', {
      sessionId: this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId,
      device: this._activeDiagnosticSession && this._activeDiagnosticSession.device,
      downtimeMs,
      confirmation: confirmation || 'open',
      transferSequence,
    }, { level: 'INFO' });
    this._lostAtMs = null;
    this._emit({ type: 'reconnected', deviceName: this._activeName(), outageMs: downtimeMs });
    return true;
  }

  _confirmReconnectAfterTransfer(context, event) {
    if (!event.success || this._reconnectVerificationSessionId == null) return false;
    if (!context || context.sessionId !== this._reconnectVerificationSessionId) return false;
    if (!this.activeTransport || !this.activeTransport.isConnected()) return false;
    return this._completeReconnect({
      confirmation: 'dmx-transfer',
      sessionId: context.sessionId,
      transferSequence: event.transferSequence || null,
    });
  }

  _scheduleSupervisorTick() {
    this.supervisorTimer = setTimeout(() => this._supervisorTick(), SUPERVISOR_INTERVAL_MS);
  }

  // ─── UDMX-006: hotplug shortcut for the reconnect wait ─────────────────────
  // A uDMX that survives a stall storm comes back by RE-ENUMERATING: it leaves
  // the bus and returns at an unpredictable moment (17+ s in the 2026-08-14
  // report). The supervisor would then sit out the rest of its 3 s tick — up to
  // 3 more seconds of frozen fixtures on top of a hole the user already felt.
  // Hotplug is best-effort (not every Windows/libusb build delivers it), so it
  // may only ever SHORTEN the wait: the 3 s timer keeps running underneath and
  // remains the guarantee. Nothing here may connect by itself — it just brings
  // the next ordinary supervisor tick forward.
  _watchUsbAttach() {
    if (this._usbAttachUnsubscribe) return;
    this._usbAttachUnsubscribe = UdmxTransport.watchAttach(device => this._onUsbAttach(device));
  }

  _unwatchUsbAttach() {
    if (this._attachKickTimer) {
      clearTimeout(this._attachKickTimer);
      this._attachKickTimer = null;
    }
    if (!this._usbAttachUnsubscribe) return;
    const unsubscribe = this._usbAttachUnsubscribe;
    this._usbAttachUnsubscribe = null;
    try { unsubscribe(); } catch { /* usb module already torn down */ }
  }

  _onUsbAttach(device) {
    if (this._attachKickTimer || !this._shouldSupervise()) return;
    this._recordDiagnostic('usb-attach-kick', {
      device: device || null,
      settleMs: ATTACH_SETTLE_MS,
    }, { level: 'INFO' });
    this._diagnostics.noteOutageStage('usb-attach', {
      path: (device && device.path) || null,
      address: (device && device.address) != null ? device.address : null,
    });
    // libusb announces the attach before Windows has finished binding libusbK to
    // the new device object — opening it right away fails and would burn the
    // shortcut. Let the enumeration settle first.
    this._attachKickTimer = setTimeout(() => {
      this._attachKickTimer = null;
      // Only when the loop is idle between ticks: with no timer pending an
      // attempt is already in flight, and a second one would race it.
      if (!this.supervisorTimer || !this._shouldSupervise()) return;
      clearTimeout(this.supervisorTimer);
      this.supervisorTimer = null;
      this.supervising = true;
      this._supervisorTick();
    }, ATTACH_SETTLE_MS);
    if (typeof this._attachKickTimer.unref === 'function') this._attachKickTimer.unref();
  }

  // The supervisor is done for now (connected, paused or disabled): drop the
  // hotplug subscription with it, so an idle app holds no USB event listeners.
  _endSupervising() {
    this.supervising = false;
    this._unwatchUsbAttach();
  }

  async _supervisorTick() {
    this.supervisorTimer = null;
    if (!this._shouldSupervise()) { this._endSupervising(); return; }

    let connected = false;
    try {
      connected = await this._attemptConnection();
    } catch (e) {
      // Never let an attempt error leave the supervisor dead (supervising=true,
      // no timer). Log and fall through to reschedule.
      console.log('⚠️ DMX supervisor attempt error:', e && e.message ? e.message : e);
      connected = false;
    }

    // State may have changed while we awaited (manual disconnect / minimize / success).
    if (connected && (!this.activeTransport || !this.activeTransport.isConnected())) {
      connected = false;
    }
    if (connected) {
      this._endSupervising();
      if (this._lostActive) {
        // uDMX open() only proves that the handle was acquired. Its transfer
        // callback will complete the reconnect after a real DMX frame succeeds.
        if (this._reconnectVerificationSessionId == null) {
          this._completeReconnect({ confirmation: 'open' });
        } else {
          console.log('🔎 uDMX переоткрыт — жду первую успешную DMX-передачу');
        }
      }
      return;
    }
    if (!this._shouldSupervise()) { this._endSupervising(); return; }
    this._scheduleSupervisorTick(); // keep trying
  }

  // One connection attempt. Returns true on success. Does not touch the timer.
  async _attemptConnection() {
    if (this.lastConnect) {
      // Reconnect to the same lost device. Snapshot lastConnect BEFORE the await:
      // a manual disconnect during scan() nulls it, and we must honour that rather
      // than reconnect against the user's will (DMX-004 invariant 1).
      const intended = this.lastConnect;
      try {
        await this.scan({ beaconSource: 3 });
      } catch (e) {
        this._noteBeaconSelection(3, 3);
        this._recordDiagnostic('reconnect-scan-failed', {
          error: e && e.message ? e.message : String(e),
        }, { level: 'WARN' });
        return false;
      }
      if (this.userDisconnected || !this.lastConnect) return false;
      const target = findReconnectTarget(this.lastScanResults, intended.deviceInfo);
      this._recordDiagnostic('reconnect-scan-result', {
        intendedDevice: cleanDeviceInfo(intended.deviceInfo),
        target: cleanDeviceInfo(target),
        devices: this.lastScanResults.map(cleanDeviceInfo),
      });
      if (!target) {
        this._noteBeaconSelection(3, 4);
        return false;
      }
      if (this.userDisconnected) return false; // re-check just before connecting
      const result = await this.connect(target.id, intended.options || {}, { manual: false, beaconSource: 3 });
      this._recordDiagnostic('reconnect-attempt-result', {
        target: cleanDeviceInfo(target),
        success: !!(result && result.success),
        error: result && result.error ? result.error : null,
      }, { level: result && result.success ? null : 'WARN' });
      return !!(result && result.success);
    }
    // Cold-start auto-connect (no remembered device yet). autoConnect scans and
    // connects only when exactly one device is unambiguous; with several it
    // returns without connecting (we keep waiting for a manual choice).
    if (this.userDisconnected) return false;
    // Fresh scan each cold-start tick so a newly plugged device is noticed
    // (autoConnect reuses lastScanResults when non-empty).
    try { await this.scan({ beaconSource: 2 }); } catch (e) {
      this._noteBeaconSelection(2, 3);
      return false;
    }
    if (this.userDisconnected) return false;
    const result = await this.autoConnect({ manual: false });
    // Emit only when the outcome changed — avoid spamming the renderer with an
    // identical 'no_devices'/'multiple_devices' result every 3s (R2).
    const sig = result.autoConnected
      ? `ok:${result.deviceName || ''}`
      // Текст отказа входит в подпись: у `connect_failed` причина «драйвер не дал
      // доступ» и «устройство исчезло» требуют РАЗНЫХ действий человека, а без неё
      // вторая молча донашивала бы формулировку первой (кейс 20.09.2026, §17).
      // Тексты отказов детерминированы, поэтому спама каждые 3,5 с это не даёт.
      : `no:${result.reason || ''}:${(result.devices && result.devices.length) || 0}:${result.error || ''}`;
    if (sig !== this._lastAutoResultSig) {
      this._lastAutoResultSig = sig;
      this._emit({ type: 'autoconnect-result', result: this._cleanResult(result) });
    }
    return !!(result && result.autoConnected);
  }

  _stopSupervisor() {
    this._endSupervising();
    if (this.supervisorTimer) {
      clearTimeout(this.supervisorTimer);
      this.supervisorTimer = null;
    }
  }

  // Strip non-serializable internals (usb device handle) before sending to renderer.
  _cleanResult(result) {
    const clean = { ...result };
    if (Array.isArray(clean.devices)) {
      clean.devices = clean.devices.map(({ _usbDevice, ...rest }) => rest);
    }
    return clean;
  }

  // MULTI-UNIVERSE: per-universe throttle slot (lazily created). Universe 1 always
  // exists for the primary output; extra universes appear when fixtures use them.
  _throttleSlot(universe) {
    let s = this.throttle.get(universe);
    if (!s) {
      s = {
        lastData: null,
        lastWasBlackout: false,
        sendTimeout: null,
        edgeFacts: null,
        edgeFactsB: null,
      };
      this.throttle.set(universe, s);
    }
    return s;
  }

  sendThrottled(universe, dmxData) {
    // Back-compat: old single-arg callers passed only the buffer → universe 1.
    if (dmxData === undefined) { dmxData = universe; universe = 1; }
    universe = Math.max(1, Math.floor(universe) || 1);

    if (!this.activeTransport || !this.activeTransport.isConnected()) return;
    // R2 last-mile barrier. During BANNED only the exact output/session pairs that
    // were open at the transition remain eligible; the set can only shrink.
    try {
      const sessionId = this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId;
      if (!banGate.maySendFrame(this._outputId, sessionId)) return;
    } catch (_) { return; }
    // WAVE-2: last-mile gate (барьер 2, независимый от main.js IPC-барьера). На
    // ПЕРВОЙ строке — ДО ветки selfClocked ниже, иначе Open DMX обходил бы проверку.
    // Чистый блок: кадр не уходит на железо (свет замирает на последнем кадре,
    // overlay в renderer объясняет «нужна лицензия»). Не портим, не гасим резко.
    if (this._licenseGate && !this._licenseGate()) return;
    // WAVE-6 / Рубеж B (барьер 2, ОТДЕЛЬНОЕ условие — §В.1 п.5): истёкший runtime_ticket (~117д
    // офлайна) блокирует кадры НЕ через license-gate, поэтому патч setLicenseGate(()=>true) его
    // не снимает. Прямой вызов обфусцированного frameGate; снять эту строку = tamper DmxManager
    // (integrity fail-closed). fail-open + латч в frameGate (ALLOW липкий → свет на шоу не гаснет,
    // ALLOW→BLOCK в идущей сессии невозможен); в dev/непроверенной сборке inert. Свой try/catch —
    // на горячем ~40fps пути даже гипотетический throw (дрейф экспорта) не должен оборвать вывод.
    let _frameBlocked = false;
    try { _frameBlocked = frameGate.isFrameBlocked(); } catch (_) { _frameBlocked = false; }
    if (_frameBlocked) return;

    const transport = this.activeTransport;
    // A single physical DMX output (USB dongle) is universe 1 only — drop the rest.
    // Network transports (sACN/Art-Net) carry the universe inside each packet and
    // advertise `supportsMultiUniverse`.
    if (!transport.supportsMultiUniverse && universe !== 1) return;

    // Snapshot only after every output gate has allowed the frame. This copy is
    // intentionally separate from throttle state, which teardown must clear.
    this._lastPermittedDmxFrames.set(universe, Array.from(dmxData));

    // N1 — точка наблюдения «реальная работа» СТРОГО после всех гейтов (_licenseGate + frameGate +
    // connected/multiverse выше). Строим факты допуска ОДИН раз (момент допуска = сейчас) и
    // сообщаем их звонарю во ВСЕХ трёх ветках физической отправки ниже. Отложенный throttle несёт
    // эти же факты вместе с кадром (slot.edgeFacts), поэтому кадр, допущенный до exp и ушедший
    // после, классифицируется как допуск до exp — честный хвост (§9-бис.3 п.2). Звонарь получает
    // только факты; проверку и решение делает сам. null наблюдатель (dev/тесты) → нулевая цена.
    const obs = this._dmxObserver;
    let edgeFacts = null;
    if (obs) { try { edgeFacts = this._edgeFacts(false); } catch (_) { /* N1 fail-open */ } }
    const obsB = this._dmxObserverB;
    let edgeFactsB = null;
    if (obsB) { try { edgeFactsB = this._edgeFactsB(false); } catch (_) { /* N1-B fail-open */ } }

    // Self-clocked transports (Open DMX / Art-Net) own the wire timing via their own
    // ~40Hz loop; send() is just a cheap memory update. Bypass the throttle so that
    // loop is the SINGLE frame clock — otherwise two ~25ms timers beat against
    // each other and produce duplicated/dropped frames (BUG-006). The renderer
    // may push at 60 FPS here; only the transport loop touches the wire.
    if (transport.selfClocked) {
      // Throttle state is intentionally NOT tracked here — selfClocked transports
      // keep their own frame memory and never go through this throttle.
      transport.send(dmxData, universe);
      if (obs && edgeFacts) { try { obs.noteFrameAdmitted(edgeFacts); } catch (_) { /* N1 fail-open */ } }
      if (obsB && edgeFactsB) { try { obsB.noteFrameAdmitted(edgeFactsB); } catch (_) { /* N1-B fail-open */ } }
      return;
    }

    const slot = this._throttleSlot(universe);
    slot.lastData = dmxData;
    slot.edgeFacts = edgeFacts; // N1: факты допуска ТЕКУЩЕГО кадра для отложенного throttle-колбэка
    slot.edgeFactsB = edgeFactsB; // N1-B: separate admission snapshot; never derived from A's cache

    // Blackout safety (DMXMGR-001): the transition INTO an all-zero frame must
    // reach the wire immediately — never wait up to 25ms (where the next frame
    // could overwrite lastData and the blackout would be lost, leaving fixtures
    // lit). Flush only the blackout edge; sustained zeros fall through to the
    // throttle so we don't flood the wire. Per-universe edge detector.
    const blackout = isBlackoutFrame(dmxData);
    if (blackout && !slot.lastWasBlackout) {
      slot.lastWasBlackout = true;
      if (slot.sendTimeout) { clearTimeout(slot.sendTimeout); slot.sendTimeout = null; }
      transport.send(dmxData, universe);
      if (obs && edgeFacts) { try { obs.noteFrameAdmitted(edgeFacts); } catch (_) { /* N1 fail-open */ } }
      if (obsB && edgeFactsB) { try { obsB.noteFrameAdmitted(edgeFactsB); } catch (_) { /* N1-B fail-open */ } }
      return;
    }
    slot.lastWasBlackout = blackout;

    if (slot.sendTimeout) return;

    slot.sendTimeout = setTimeout(() => {
      slot.sendTimeout = null;
      const sessionId = this._activeDiagnosticSession && this._activeDiagnosticSession.sessionId;
      let manualAllowed = false;
      try { manualAllowed = banGate.maySendFrame(this._outputId, sessionId); } catch (_) {}
      if (manualAllowed && slot.lastData && this.activeTransport && this.activeTransport.isConnected()) {
        this.activeTransport.send(slot.lastData, universe);
        // N1: кадр ушёл отложенным throttle. Классифицируем по моменту ДОПУСКА (сохранён в
        // slot.edgeFacts при планировании), а не по времени wire-tick — иначе кадр, допущенный
        // до exp и отправленный после, ложно читался бы как работа без лицензии (§9-бис.3 п.2).
        const f = slot.edgeFacts;
        if (this._dmxObserver && f) { try { this._dmxObserver.noteFrameAdmitted(f); } catch (_) { /* N1 fail-open */ } }
        const fB = slot.edgeFactsB;
        if (this._dmxObserverB && fB) {
          try { this._dmxObserverB.noteFrameAdmitted(fB); } catch (_) { /* N1-B fail-open */ }
        }
      }
    }, transport.minFrameIntervalMs || DEFAULT_FRAME_INTERVAL_MS);
  }

  async autoConnect({ manual = true } = {}) {
    if (this.lastScanResults.length === 0) {
      try { await this.scan({ beaconSource: 2 }); } catch (error) {
        this._noteBeaconSelection(2, 3);
        throw error;
      }
    }

    // Auto-connect candidates = physical USB/serial devices only. Art-Net и sACN
    // всегда «доступны» (виртуальные UDP-интерфейсы, без path) и требуют ручной
    // настройки IP/universe — их НЕЛЬЗЯ считать за физическое устройство, иначе
    // один воткнутый uDMX + всегда-присутствующий sACN = «несколько устройств» и
    // автоподключение не срабатывает. Любые entries с supported:false (например
    // ещё неподдержанное железо) тоже прочь. Sunlite теперь supported:true.
    const usbDevices = this.lastScanResults.filter(d =>
      d.type !== 'artnet' && d.type !== 'sacn' && d.supported !== false
    );

    // Count unique physical devices (same serial port = 1 device)
    const uniquePhysical = [];
    const seenPaths = new Set();
    for (const d of usbDevices) {
      if (d.path) {
        if (!seenPaths.has(d.path)) {
          seenPaths.add(d.path);
          uniquePhysical.push(d);
        }
      } else {
        uniquePhysical.push(d);
      }
    }

    if (uniquePhysical.length === 0) {
      // A blocked search already recorded its own result; «no devices» would hide it.
      if (!(this._lastSerialScan && this._lastSerialScan.blocked === true)) this._noteBeaconSelection(2, 1);
      return {
        autoConnected: false,
        reason: 'no_devices',
        devices: this.lastScanResults
      };
    }

    if (uniquePhysical.length > 1) {
      this._noteBeaconSelection(2, 2);
      return {
        autoConnected: false,
        reason: 'multiple_devices',
        devices: this.lastScanResults
      };
    }

    const device = uniquePhysical[0];

    // These USB families have an unambiguous native protocol, connect immediately.
    if (device.type === 'udmx' || device.type === 'sunlite' || device.type === 'martin') {
      const result = await this.connect(device.id, {}, { manual, beaconSource: 2 });
      if (result.success) {
        return { autoConnected: true, deviceName: device.name };
      }
      return {
        autoConnected: false,
        reason: 'connect_failed',
        error: result.error,
        // Кейс 20.09.2026 (§17 справочника): без типа устройства main не может
        // подобрать человеческую формулировку отказа — у Sunlite и uDMX один и тот
        // же текст ошибки означает разное.
        deviceType: device.type,
        // §7.10: отказ тихого слоя несёт только номер; без него автоподключение
        // возвращало бы пустую причину, и человеку было бы нечего назвать поддержке.
        noticeCode: result.noticeCode,
        devices: this.lastScanResults
      };
    }

    // Serial port (FTDI/CH340) — выбираем протокол по чипу:
    //   • FTDI (VID 0403) → Open DMX (Enttec Open DMX USB и большинство брендовых свистков на FTDI
    //     используют bitbang с break/MAB; оригинальный Enttec Pro — редкость, выбирается вручную).
    //   • CH340 (VID 1a86) → Enttec Pro (массовые Aliexpress-свистки сейчас идут с Enttec-прошивкой;
    //     bare-CH340 без прошивки — реже, выбирается вручную как «Open DMX (CH340, COMx)»).
    // Если умолчание не подошло — пользователь явно кликает другой вариант в списке.
    if (device.type === 'enttec-pro' || device.type === 'open-dmx') {
      const isCh340 = (device.vendorId || '').toLowerCase() === '1a86';
      const preferredType = isCh340 ? 'enttec-pro' : 'open-dmx';
      const preferred = this.lastScanResults.find(d =>
        d.type === preferredType && d.path === device.path
      );
      if (preferred) {
        const result = await this.connect(preferred.id, {}, { manual, beaconSource: 2 });
        if (result.success) {
          return { autoConnected: true, deviceName: preferred.name };
        }
      } else {
        this._noteBeaconSelection(2, 4);
      }

      return {
        autoConnected: false,
        reason: 'connect_failed',
        error: `Не удалось подключиться (${preferredType === 'enttec-pro' ? 'Enttec Pro' : 'Open DMX'})`,
        deviceType: preferredType,
        devices: this.lastScanResults
      };
    }

    return {
      autoConnected: false,
      reason: 'unknown_type',
      devices: this.lastScanResults
    };
  }

  // Device whose Windows driver the support report should probe: the live one, else
  // the last one we connected to. Support cases arrive both ways — "it died mid-show"
  // (transport still active) and "it will not open" (only lastConnect survives).
  getActiveDeviceInfo() {
    const transport = this.activeTransport;
    if (transport && transport.deviceInfo) return cleanDeviceInfo(transport.deviceInfo);
    if (this.lastConnect && this.lastConnect.deviceInfo) return cleanDeviceInfo(this.lastConnect.deviceInfo);
    return null;
  }

  getStatus() {
    if (!this.activeTransport) {
      return {
        connected: false,
        deviceName: null,
        deviceType: null,
        error: null
      };
    }
    return {
      connected: this.activeTransport.isConnected()
        && this._reconnectVerificationSessionId == null,
      deviceName: this.activeTransport.getDisplayName(),
      deviceType: this.activeTransport.deviceInfo.type,
      error: this.activeTransport.lastError
    };
  }

  /**
   * Подтверждение сетевого подключения (2026-08-22).
   *
   * Возвращает { required, supported, confirmed, reason, nodes }:
   *   required  — транспорт вообще нуждается в подтверждении (только сетевой);
   *   supported — подтверждение технически возможно (Art-Net — да, sACN — нет);
   *   confirmed — узел ответил.
   *
   * Для USB `required: false`: устройство открыто драйвером, это и есть доказательство.
   * Опрос никогда не влияет на вывод света и не бросает — «не подтверждено» это
   * «мы не знаем», а не «сломалось».
   */
  async confirmNode(options = {}) {
    const transport = this.activeTransport;
    if (!transport || !transport.isConnected()) {
      return { required: false, supported: false, confirmed: false, reason: 'not-connected', nodes: [] };
    }
    if (transport.requiresNodeConfirmation !== true) {
      return { required: false, supported: false, confirmed: true, reason: 'device-open', nodes: [] };
    }
    try {
      const result = await transport.probeNode(options);
      return {
        required: true,
        supported: !!(result && result.supported),
        confirmed: !!(result && result.confirmed),
        reason: (result && result.reason) || 'unknown',
        // Наш Port-Address: без него подсказка «узел слушает другой юниверс» не может
        // назвать, ЧТО с чем не сошлось, а абстрактное «проверьте настройки» бесполезно.
        portAddress: result && typeof result.portAddress === 'number' ? result.portAddress : null,
        // Вещательная ли цель — решает транспорт, а не разбор строки адреса на другом
        // конце (ревью 14.09.2026): подсказка человеку зависит от этого признака.
        broadcast: !!(result && result.broadcast),
        nodes: (result && result.nodes) || [],
      };
    } catch (e) {
      return { required: true, supported: false, confirmed: false, reason: 'error', broadcast: false, nodes: [] };
    }
  }

  /**
   * Поиск Art-Net узлов в сети (2026-08-22, блок A мастера настройки).
   *
   * Единственная точка входа: только здесь создаётся `ArtNetDiscovery`, поэтому
   * два одновременных поиска невозможны — второй вызов получает уже идущий.
   * Два параллельных опроса делят порт 6454 и на Windows растаскивают ответы
   * между собой недетерминированно, из-за чего часть узлов «пропадала» бы.
   *
   * НЕ вызывается из `scan()`: тот дёргается супервайзером каждые 3 секунды, а
   * сетевой опрос длится секунды — фоновая работа встала бы колом.
   *
   * Никогда не бросает: худший исход — пустой список с описанием помех.
   */
  discoverArtNetNodes(options = {}) {
    if (isManualConnectionBlocked()) {
      return Promise.resolve({
        nodes: [], interfaces: [], skipped: [], errors: [{ reason: 'unavailable' }],
        cancelled: false, outcome: 'failed',
      });
    }
    if (this._artNetDiscoveryPromise) return this._artNetDiscoveryPromise;
    const ArtNetDiscovery = require('./artnet/ArtNetDiscovery');
    // Порт 6454 нельзя привязывать дважды: если он уже у рабочего транспорта, поиск
    // подписывается на ЕГО сокет, иначе на Windows ответы растаскиваются между двумя
    // привязками и рабочий приёмник на время поиска слепнет (аудит 2026-09-05).
    const discovery = new ArtNetDiscovery({ attachReceiver: this._activeArtNetReceiver() });
    this._artNetDiscovery = discovery;
    this._artNetDiscoveryPromise = discovery.discover(options)
      .catch(() => ({
        nodes: [], interfaces: [], skipped: [], errors: [{ reason: 'error' }],
        cancelled: false, outcome: 'failed',
      }))
      .then((result) => {
        this._artNetDiscoveryPromise = null;
        this._artNetDiscovery = null;
        return result;
      });
    return this._artNetDiscoveryPromise;
  }

  /** Приёмник 6454 активного Art-Net транспорта, если он есть (иначе null). */
  _activeArtNetReceiver() {
    const t = this.activeTransport;
    if (!t || typeof t.sharedReceiverSocket !== 'function') return null;
    try { return t.sharedReceiverSocket(); } catch (e) { return null; }
  }

  /** Отмена идущего поиска — окно мастера закрыли, ждать больше некому. */
  cancelArtNetDiscovery() {
    if (this._artNetDiscovery) {
      try { this._artNetDiscovery.cancel(); } catch (e) { /* уже завершился */ }
    }
  }

  // 2026-09-19: итоги провалов без сборки полного отчёта — см. DmxDiagnostics.
  getOutageCounters() {
    return this._diagnostics.outageCounters();
  }

  getDiagnostics({ selectedDevice = null } = {}) {
    const snapshot = this._diagnostics.snapshot({
      status: this.getStatus(),
      activeSession: this._activeDiagnosticSession,
      lastConnectDevice: this.lastConnect ? cleanDeviceInfo(this.lastConnect.deviceInfo) : null,
      userDisconnected: this.userDisconnected,
      windowActive: this.windowActive,
      supervising: this.supervising,
      reconnectScheduled: !!this.supervisorTimer,
      lostActive: this._lostActive,
      degradedActive: this._degradedActive,
      licenseSuspended: this._licenseSuspended,
      awaitingFirstDmxSessionId: this._reconnectVerificationSessionId,
      lostAt: this._lostAtMs == null ? null : new Date(this._lostAtMs).toISOString(),
      supervisorIntervalMs: SUPERVISOR_INTERVAL_MS,
      teardownTimeoutMs: TEARDOWN_TIMEOUT_MS,
      frameIntervalMs: this.activeTransport
        ? (this.activeTransport.minFrameIntervalMs || DEFAULT_FRAME_INTERVAL_MS)
        : null,
      lastSerialScan: this._lastSerialScan
        ? {
          ...this._lastSerialScan,
          devices: this._lastSerialScan.devices.map(device => ({ ...device })),
          errors: this._lastSerialScan.errors.map(error => ({ ...error })),
        }
        : null,
    });
    if (selectedDevice && typeof selectedDevice.id === 'string') {
      snapshot.selectedTransferTotals = this._diagnostics.deviceTransferStats(selectedDevice.id);
      snapshot.selectedTransferScope = 'selected_device';
    }
    return snapshot;
  }
}

module.exports = DmxManager;
