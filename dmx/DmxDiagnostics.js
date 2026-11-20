const DEFAULT_MAX_EVENTS = 500;
const DEFAULT_MAX_PERSISTENT_EVENTS = 100;
const DEFAULT_WINDOW_MS = 5000;

// ─── UDMX-006: outage journal ────────────────────────────────────────────────
// Field lesson (support case 2026-08-14): during a STALL storm the transport
// produces ~25 errors/s, every one of them WARN-level. In 5 seconds they evict
// the whole 100-slot persistent buffer AND the app.log tail, so a report taken
// after the fourth outage of the evening carries no trace of the first three —
// exactly the history support needs to answer "how often does it drop?".
// Two independent fixes:
//   1. one bounded journal of OUTAGES (start → end, what happened in between),
//      which the per-error spam can never evict;
//   2. persistence throttling for the errors themselves — the first of a run,
//      every kind change, every Nth, and the give-up are kept; the rest stay in
//      the volatile recent-events ring only.
const DEFAULT_MAX_OUTAGES = 40;
// Per record: enough to see the whole ladder (reopen/reset/lost/reconnect/USB
// presence) of even a multi-session outage, bounded so a flapping link cannot
// grow one record without limit.
const MAX_OUTAGE_STAGES = 24;
// UDMX-010: the same reasoning for the session list. One outage that spans a
// give-up, a reconnect and a re-enumeration collects one id per session, and a
// stick that is visible but unopenable can repeat that every ~10 s for hours —
// an unbounded array that is also scanned linearly on every single error.
const MAX_OUTAGE_SESSIONS = 24;
// A single STALL is normal background for uDMX (proven 2026-07): journalling
// every one of them would push the real outages out of the ring. Anything below
// BOTH thresholds is counted in `minor` instead of taking a slot.
// UDMX-007: the ceiling must clear the keep-alive period. A single background
// STALL forces the next frame to be a full one — but when the stage is idle the
// next frame IS the 1 s keep-alive, so the outage stays open exactly that long
// through no fault of the link. At 1000 ms those healthy singles crossed the
// line and took journal slots as if they were real outages (seen 2026-08-22:
// 7 records, one error each, 1001-1056 ms).
const MINOR_OUTAGE_MAX_MS = 1500;
const MINOR_OUTAGE_MAX_ERRORS = 5;
// Keep every Nth error of a long run as persistent evidence (~1 line per second
// at the storm retry cadence) so the timeline is still readable in app.log.
const PERSIST_EVERY_NTH_ERROR = 25;
// UDMX-010: and a hard floor on how often a "new event" line may be written.
// The rules above are all shaped around a RUN of failures, but a link that fails
// one frame in three never builds one: every success closes the outage
// (`endOutage('recovered')` on any successful transfer), so the next error is
// once again "the first error of an outage" AND "a kind change" — both gates
// open, and app.log fills at the error rate, which is exactly the flood UDMX-006
// set out to stop. The periodic every-Nth line is deliberately NOT floored, so
// the timeline of a real storm keeps its ~1 line per second.
const PERSIST_MIN_GAP_MS = 1000;

// ─── UDMX-007: failure rate by payload size ──────────────────────────────────
// The 2026-08-22 case cost a full evening precisely because the report could
// answer "how many transfers failed" but not "failed at WHICH size" — the answer
// had to be reconstructed from log lines and then proven by a separate hardware
// A/B. These buckets put that answer in every future report: the boundary that
// mattered (a range that fits one low-speed USB packet vs a wider one) is now
// visible at a glance, for any stick and any firmware revision.
// Mirrors UDMX_KEEPALIVE_CHUNK_CHANNELS in UdmxTransport. Kept as a local
// constant instead of an import because DmxDiagnostics must stay loadable
// without the native `usb` addon that the transport pulls in.
const UDMX_KEEPALIVE_CHUNK_CHANNELS_REF = 64;

const PAYLOAD_BUCKETS = [
  { key: '1-4', max: 4 },
  { key: '5-16', max: 16 },
  { key: '17-64', max: 64 },
  { key: '65-256', max: 256 },
  { key: '257-512', max: 512 },
];

function payloadBucketKey(channelCount) {
  if (!Number.isFinite(channelCount) || channelCount <= 0) return null;
  const bucket = PAYLOAD_BUCKETS.find(b => channelCount <= b.max);
  return bucket ? bucket.key : PAYLOAD_BUCKETS[PAYLOAD_BUCKETS.length - 1].key;
}

function emptyPayloadStats() {
  const out = {};
  for (const bucket of PAYLOAD_BUCKETS) out[bucket.key] = { attempts: 0, errors: 0 };
  return out;
}

// ─── UDMX-010: WHICH KIND of payload it was, not just how big ────────────────
// payloadSizes answers "at which size did it break", but a 257-512 byte transfer
// can be two very different things: the one full frame that seeds the firmware
// after open, or an ordinary delta that happened to span the whole rig (channel
// 1 and channel 512 changed in the same frame — the planner sends ONE contiguous
// range). The 2026-09-01 analysis had to assume that bucket meant "full frame",
// and that assumption is exactly what decides whether capping the width of an
// ordinary delta is worth its cost. These counters remove the guess:
//   full       — the seeding frame after open/reopen/reset
//   keepalive  — a UDMX-008 refresh chunk
//   delta      — a real change range
//   wideDelta  — the subset of `delta` longer than one refresh chunk (NOT a
//                separate population: it is counted in `delta` as well)
//   seedProbe  — UDMX-012: the one short write that gates the seed. Its own
//                bucket on purpose: the whole 2026-09-18 case turns on "does a
//                64-channel write pass while a 512-channel one fails?", and
//                that question is only answerable if the two are counted apart.
//                Reading it: probe errors ≈ 0 with full-frame errors high means
//                the stick is alive and only length breaks it; both high means
//                it is dead to everything, which is what that client had.
const WIDE_DELTA_MIN_CHANNELS = UDMX_KEEPALIVE_CHUNK_CHANNELS_REF + 1;

function emptyFrameKindStats() {
  return {
    full: { attempts: 0, errors: 0 },
    keepalive: { attempts: 0, errors: 0 },
    delta: { attempts: 0, errors: 0 },
    wideDelta: { attempts: 0, errors: 0 },
    seedProbe: { attempts: 0, errors: 0 },
  };
}

// ─── 2026-09-11: чем подтверждён успех передачи ──────────────────────────────
// До этой даты счётчики передач были инструментированы ТОЛЬКО в UdmxTransport,
// поэтому у владельца Sunlite, Enttec, Open DMX, Art-Net или sACN весь раздел
// `transferTotals` оставался нулевым даже при идеально работающем свете —
// отличить «поток идёт» от «молчит» по отчёту было нельзя (разбор клиентского
// отчёта 11.09.2026, ДОК/DMX_CONTROLLER_TROUBLESHOOTING §12).
//
// Теперь кадры считают все транспорты, но цена слова «успех» у них РАЗНАЯ, и
// отчёт обязан это показывать: иначе «кадр отдан драйверу» прочитается как
// «прибор принял кадр» — ровно та подмена, от которой предостерегает §3
// справочника. Уровень объявляет сам транспорт (`transferConfirmation`), а
// штампует им события DmxManager — один раз на подключение.
const CONFIRMATION_MEANING = {
  device: 'устройство подтвердило приём кадра (USB control transfer)',
  driver: 'драйвер ОС завершил запись кадра в порт; сам прибор подтверждения не даёт',
  socket: 'ядро приняло UDP-пакет к отправке; приёмник в этом протоколе не отвечает',
  sidecar: 'кадр принят 32-битным посредником SDK; подтверждения на кадр SDK не даёт',
  buffer: 'кадр положен в буфер сторонней библиотеки, провод тактует она сама',
};

const { modelOf } = require('./udmxModels');

// Non-enumerable marker: an event that stays in the volatile recent ring but
// must NOT reach the persistent sink (app.log). Hidden from JSON on purpose —
// the diagnostics file must not grow a field that means nothing to a reader.
const NO_PERSIST = Symbol('noPersist');

// The one place that decides whether an event may reach the persistent sink.
function shouldPersistEvent(event) {
  return !!(event && event.level && !event[NO_PERSIST]);
}

function round(value, digits = 2) {
  if (!Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function classifyUsbError(error) {
  const text = [
    error && error.name,
    error && error.message,
    error && error.code,
    error && error.errno,
  ].filter(v => v !== undefined && v !== null).join(' ').toUpperCase();

  // UDMX-011: `NOT[ _]FOUND` — libusb says `LIBUSB_ERROR_NOT_FOUND` with an
  // UNDERSCORE, and that is exactly what a uDMX yanked out of the port reports
  // (measured 2026-09-05 on the bench). The space-only spelling matched a
  // wording libusb never emits, so every unplug was filed as `OTHER`.
  // Behaviour is unaffected: the ladder branches only on `PIPE` (a STALL means
  // the stick answered), and both spellings land in the same bucket.
  if (/NO_DEVICE|DISCONNECT|ENXIO|ENODEV|NOT[ _]FOUND/.test(text)) return 'NO_DEVICE';
  if (/TIMED_OUT|TIMEOUT|ETIMEDOUT/.test(text)) return 'TIMED_OUT';
  if (/BUSY|EBUSY/.test(text)) return 'BUSY';
  if (/PIPE|STALL|EPIPE/.test(text)) return 'PIPE';
  if (/\bIO\b|ERROR_IO|EIO/.test(text)) return 'IO';
  return 'OTHER';
}

function serializeUsbError(error) {
  if (!error) return null;
  return {
    kind: classifyUsbError(error),
    name: error.name || null,
    message: error.message || String(error),
    code: error.code !== undefined ? error.code : null,
    errno: error.errno !== undefined ? error.errno : null,
  };
}

// Every uDMX-class stick we support, not just the original one: hotplug events
// and USB-presence snapshots must cover the same models the transport scans, or
// a clone would appear in the device list yet stay invisible to reports.
function isUdmxDevice(device) {
  return !!modelOf(device);
}

function snapshotUsbDevice(device) {
  const descriptor = (device && device.deviceDescriptor) || {};
  const ports = Array.isArray(device && device.portNumbers)
    ? device.portNumbers.map(Number)
    : [];
  const bus = device && device.busNumber != null ? device.busNumber : null;
  const address = device && device.deviceAddress != null ? device.deviceAddress : null;
  return {
    vendorId: descriptor.idVendor != null ? descriptor.idVendor : null,
    productId: descriptor.idProduct != null ? descriptor.idProduct : null,
    vendorIdHex: descriptor.idVendor != null
      ? descriptor.idVendor.toString(16).padStart(4, '0').toUpperCase()
      : null,
    productIdHex: descriptor.idProduct != null
      ? descriptor.idProduct.toString(16).padStart(4, '0').toUpperCase()
      : null,
    bcdDevice: descriptor.bcdDevice != null ? descriptor.bcdDevice : null,
    deviceClass: descriptor.bDeviceClass != null ? descriptor.bDeviceClass : null,
    deviceSubClass: descriptor.bDeviceSubClass != null ? descriptor.bDeviceSubClass : null,
    deviceProtocol: descriptor.bDeviceProtocol != null ? descriptor.bDeviceProtocol : null,
    bus,
    ports,
    path: bus != null ? `${bus}-${ports.length ? ports.join('.') : `a${address ?? '?'}`}` : null,
    address,
  };
}

function usbDeviceSignature(devices) {
  return (devices || [])
    .map(device => `${device.path || '?'}@${device.address ?? '?'}`)
    .sort()
    .join('|');
}

function snapshotUdmxDevices(usbApi) {
  try {
    const devices = usbApi && typeof usbApi.getDeviceList === 'function'
      ? usbApi.getDeviceList().filter(isUdmxDevice).map(snapshotUsbDevice)
      : [];
    devices.sort((a, b) => String(a.path || '').localeCompare(String(b.path || ''), undefined, { numeric: true }));
    return {
      ok: true,
      signature: usbDeviceSignature(devices),
      devices,
      error: null,
    };
  } catch (error) {
    return {
      ok: false,
      signature: null,
      devices: [],
      error: serializeUsbError(error),
    };
  }
}

function cleanDeviceInfo(deviceInfo) {
  if (!deviceInfo) return null;
  return {
    id: deviceInfo.id || null,
    type: deviceInfo.type || null,
    name: deviceInfo.name || null,
    path: deviceInfo.path || null,
    vendorId: deviceInfo.vendorId || null,
    productId: deviceInfo.productId || null,
    serialNumber: deviceInfo.serialNumber || null,
  };
}

function emptyTransferStats() {
  return {
    attempts: 0,
    successes: 0,
    errors: 0,
    errorsByKind: {},
    coalescedFrames: 0,
    durationCount: 0,
    durationTotalMs: 0,
    minDurationMs: null,
    maxDurationMs: null,
    lastSuccessAt: null,
    lastErrorAt: null,
  };
}

function addDuration(stats, durationMs) {
  if (!Number.isFinite(durationMs)) return;
  stats.durationCount++;
  stats.durationTotalMs += durationMs;
  stats.minDurationMs = stats.minDurationMs == null
    ? durationMs
    : Math.min(stats.minDurationMs, durationMs);
  stats.maxDurationMs = stats.maxDurationMs == null
    ? durationMs
    : Math.max(stats.maxDurationMs, durationMs);
}

function statsSnapshot(stats, elapsedMs = null) {
  return {
    attempts: stats.attempts,
    successes: stats.successes,
    errors: stats.errors,
    errorsByKind: { ...stats.errorsByKind },
    coalescedFrames: stats.coalescedFrames,
    minDurationMs: round(stats.minDurationMs),
    averageDurationMs: stats.durationCount
      ? round(stats.durationTotalMs / stats.durationCount)
      : null,
    maxDurationMs: round(stats.maxDurationMs),
    actualSuccessHz: elapsedMs && elapsedMs > 0
      ? round(stats.successes * 1000 / elapsedMs)
      : null,
    lastSuccessAt: stats.lastSuccessAt,
    lastErrorAt: stats.lastErrorAt,
  };
}

class DmxDiagnostics {
  constructor(options = {}) {
    this.maxEvents = options.maxEvents || DEFAULT_MAX_EVENTS;
    this.maxPersistentEvents = options.maxPersistentEvents || DEFAULT_MAX_PERSISTENT_EVENTS;
    this.maxOutages = options.maxOutages || DEFAULT_MAX_OUTAGES;
    this.windowMs = options.windowMs || DEFAULT_WINDOW_MS;
    this._now = options.now || (() => Date.now());
    this.startedAt = new Date(this._now()).toISOString();
    this.sequence = 0;
    this.events = [];
    this.persistentEvents = [];
    this.totals = emptyTransferStats();
    // Отдельно от суммарного счётчика: Art-Net кадры одного сеанса нельзя
    // приписывать uDMX при последующем сбое USB. Ключ — тип транспорта без
    // путей, серийников и других идентификаторов устройства.
    this.totalsByType = Object.create(null);
    this.confirmationsByType = Object.create(null);
    // Полный ID железки используется как внутренний ключ счётчиков. В snapshot()
    // эту карту не кладём: ID может содержать USB-путь или серийный номер.
    this.totalsByDeviceId = new Map();
    this.confirmationsByDeviceId = new Map();
    this.window = this._newWindow();
    // UDMX-006 outage journal.
    this.outages = [];
    this.outageSequence = 0;
    this.minorOutages = { count: 0, errors: 0 };
    // 2026-09-19: ИТОГИ по настоящим провалам, отдельно от кольца записей. Кольцо
    // держит 40 штук и вытесняет старые, а инвентарю интерфейсов (clientHealth)
    // нужен монотонный счётчик за всю сессию: «сколько раз свет замирал и на
    // сколько секунд». Считаем только НЕ-minor — одиночный фоновый STALL живёт
    // ~1 с, лечится следующим кадром и человеком не виден.
    this.filedOutages = { count: 0, totalMs: 0, longestMs: 0 };
    // 2026-09-11: чем подтверждались успехи — и сколько каких. Карта, а не одна
    // строка: за сессию пользователь мог переключить протокол (uDMX → Art-Net), и
    // тогда общий счётчик передач складывается из разных по силе доказательств.
    this.confirmations = {};
    this.lastConfirmation = null;
    // UDMX-007: попытки/ошибки в разрезе размера посылки.
    this.payloadStats = emptyPayloadStats();
    // UDMX-010: те же попытки/ошибки в разрезе ВИДА посылки.
    this.frameKinds = emptyFrameKindStats();
    this._openOutage = null;
    this._lastPersistedErrorKind = null;
    // Survives outage boundaries on purpose — that is the whole point of it.
    this._lastPersistedErrorAtMs = 0;
    // Такой же пол частоты для строки «связь восстановилась» (см. _shouldPersistRecovery).
    this._lastPersistedRecoveryAtMs = 0;
    // The last failure was a lone watchdog skip kept out of app.log (see recordTransfer).
    this._heldBackWatchdog = false;
  }

  _newWindow() {
    return {
      startedAtMs: this._now(),
      stats: emptyTransferStats(),
    };
  }

  recordEvent(type, data = {}, options = {}) {
    const event = {
      sequence: ++this.sequence,
      at: new Date(this._now()).toISOString(),
      type,
      ...data,
    };
    if (options.level) event.level = options.level;
    this.events.push(event);
    if (this.events.length > this.maxEvents) {
      this.events.splice(0, this.events.length - this.maxEvents);
    }
    // UDMX-006: `persist: false` keeps the level visible in the recent ring (so a
    // support engineer still sees the severity of every single error) while
    // keeping the throttled duplicates out of the persistent buffer AND out of
    // app.log — both of which are consumed by the same sink downstream.
    if (options.level && options.persist === false) {
      Object.defineProperty(event, NO_PERSIST, { value: true, enumerable: false });
    }
    if (options.level && options.persist !== false) {
      this.persistentEvents.push(event);
      if (this.persistentEvents.length > this.maxPersistentEvents) {
        this.persistentEvents.splice(
          0,
          this.persistentEvents.length - this.maxPersistentEvents,
        );
      }
    }
    return event;
  }

  // ═══ UDMX-006: outage journal ══════════════════════════════════════════════
  // One outage = one hole the user actually sees on stage. It starts at the
  // first failed transfer (or a hard loss) and ends only when a frame really
  // gets through again — so a storm that spans a give-up, a reconnect and a
  // re-enumeration stays ONE record with the whole ladder inside it, instead of
  // three unrelated fragments.

  _openOutageRecord(nowMs, seed = {}) {
    if (this._openOutage) return this._openOutage;
    this._openOutage = {
      sequence: ++this.outageSequence,
      startedAtMs: nowMs,
      startedAt: new Date(nowMs).toISOString(),
      firstErrorKind: seed.kind || null,
      errors: 0,
      errorsByKind: {},
      sessionIds: [],
      _droppedSessions: new Set(),
      stages: [],
      stagesDropped: 0,
      reopenCount: 0,
      resetCount: 0,
      lostCount: 0,
      reconnectCount: 0,
      deviceAbsentMs: 0,
      deviceWasAbsent: false,
      _absentSinceMs: null,
    };
    return this._openOutage;
  }

  _noteSession(outage, sessionId) {
    if (sessionId == null || outage.sessionIds.includes(sessionId)) return;
    if (outage.sessionIds.length >= MAX_OUTAGE_SESSIONS) {
      // A Set, not a counter: _noteSession runs on EVERY failed transfer, so a
      // plain ++ would count errors instead of sessions and a single dropped
      // session with 300 errors would read as 300 lost sessions.
      outage._droppedSessions.add(sessionId);
      return;
    }
    outage.sessionIds.push(sessionId);
  }

  // A failed transfer. Opens the outage on the first one.
  noteOutageError({ kind = 'OTHER', sessionId = null } = {}) {
    const nowMs = this._now();
    const outage = this._openOutageRecord(nowMs, { kind });
    if (!outage.firstErrorKind) outage.firstErrorKind = kind;
    outage.errors++;
    outage.errorsByKind[kind] = (outage.errorsByKind[kind] || 0) + 1;
    this._noteSession(outage, sessionId);
    return outage;
  }

  // A ladder / connection milestone inside the outage. `open: true` starts an
  // outage that had no failed transfer of its own (a clean NO_DEVICE unplug).
  noteOutageStage(step, detail = {}, { open = false, sessionId = null } = {}) {
    const nowMs = this._now();
    if (!this._openOutage && !open) return null;
    const outage = this._openOutageRecord(nowMs);
    this._noteSession(outage, sessionId);
    if (step === 'reopen') outage.reopenCount++;
    else if (step === 'reset') outage.resetCount++;
    else if (step === 'lost') outage.lostCount++;
    else if (step === 'reconnect') outage.reconnectCount++;
    if (outage.stages.length < MAX_OUTAGE_STAGES) {
      outage.stages.push({ at: new Date(nowMs).toISOString(), step, ...detail });
    } else {
      outage.stagesDropped++;
    }
    return outage;
  }

  // USB enumeration came or went while an outage is open — this is what tells
  // "the stick stalls but is still there" from "the stick left the bus".
  noteDevicePresence(present) {
    const outage = this._openOutage;
    if (!outage) return null;
    const nowMs = this._now();
    if (!present && outage._absentSinceMs == null) {
      outage._absentSinceMs = nowMs;
      outage.deviceWasAbsent = true;
    } else if (present && outage._absentSinceMs != null) {
      outage.deviceAbsentMs += nowMs - outage._absentSinceMs;
      outage._absentSinceMs = null;
    }
    return outage;
  }

  // A frame got through again (or the user closed the link). Files the record.
  endOutage(resolution = 'recovered') {
    const outage = this._openOutage;
    if (!outage) return null;
    this._openOutage = null;
    // UDMX-010: `_lastPersistedErrorKind` deliberately SURVIVES the outage. It
    // used to be cleared here so the first error of the next outage always got a
    // line — but an intermittent link closes and reopens an outage on every
    // single error, so clearing it made "the kind changed" true every time and
    // the throttle never engaged. The first error of an outage still gets its own
    // rule below; the kind rule now means what it says.
    const nowMs = this._now();
    if (outage._absentSinceMs != null) {
      outage.deviceAbsentMs += nowMs - outage._absentSinceMs;
      outage._absentSinceMs = null;
    }
    const record = this._outageSnapshot(outage, nowMs);
    record.resolution = resolution;
    // Single background STALLs are normal for uDMX (field-proven 2026-07):
    // journalling them would push the real outages out of the ring.
    // UDMX-010: the numeric thresholds decide, not the resolution. `resolution`
    // used to be part of it, which meant a user pressing «Отключить» during the
    // ~1 s an ordinary background STALL keeps an outage open filed a full journal
    // record — and on a healthy stick those singles come 88 times in two minutes,
    // so they would evict the real outages from the 40 slots. What the record
    // must NOT be silenced by is size: a long or many-error outage still takes a
    // slot no matter how it ended.
    const minor = record.durationMs < MINOR_OUTAGE_MAX_MS
      && record.errors < MINOR_OUTAGE_MAX_ERRORS
      && !record.deviceWasAbsent
      && record.lostCount === 0;
    if (minor) {
      this.minorOutages.count++;
      this.minorOutages.errors += record.errors;
      return record;
    }
    this.filedOutages.count++;
    this.filedOutages.totalMs += record.durationMs;
    if (record.durationMs > this.filedOutages.longestMs) this.filedOutages.longestMs = record.durationMs;
    this.outages.push(record);
    if (this.outages.length > this.maxOutages) {
      this.outages.splice(0, this.outages.length - this.maxOutages);
    }
    return record;
  }

  /**
   * Дешёвый срез итогов по провалам — БЕЗ сборки полного snapshot().
   * Нужен инвентарю интерфейсов: он опрашивает счётчики на каждом событии связи,
   * а snapshot() собирает кольца событий и весь журнал целиком.
   */
  outageCounters() {
    return { ...this.filedOutages };
  }

  _outageSnapshot(outage, nowMs) {
    const absentMs = outage.deviceAbsentMs
      + (outage._absentSinceMs == null ? 0 : nowMs - outage._absentSinceMs);
    return {
      sequence: outage.sequence,
      startedAt: outage.startedAt,
      endedAt: new Date(nowMs).toISOString(),
      durationMs: nowMs - outage.startedAtMs,
      firstErrorKind: outage.firstErrorKind,
      errors: outage.errors,
      errorsByKind: { ...outage.errorsByKind },
      sessionIds: outage.sessionIds.slice(),
      sessionsDropped: outage._droppedSessions.size,
      reopenCount: outage.reopenCount,
      resetCount: outage.resetCount,
      lostCount: outage.lostCount,
      reconnectCount: outage.reconnectCount,
      deviceWasAbsent: outage.deviceWasAbsent,
      deviceAbsentMs: absentMs,
      stages: outage.stages.slice(),
      stagesDropped: outage.stagesDropped,
    };
  }

  // Persistence throttle for the per-error spam: keep the first error of the
  // outage, every kind change, every Nth, and the give-up — drop the rest.
  // UDMX-010: count the ERRORS OF THE OUTAGE, not the current consecutive run.
  // The run counter is reset by every success, so a link that fails one frame in
  // three (error, success, error, …) came back to `consecutiveErrors === 1` each
  // time and persisted 100 % of its errors — the exact app.log flood UDMX-006
  // set out to stop, just with successes mixed in. The open outage already
  // counts every failure of the hole, whether or not they were consecutive.
  _shouldPersistError(kind, consecutiveErrors, thresholdReached) {
    const nowMs = this._now();
    const keep = () => {
      this._lastPersistedErrorKind = kind;
      this._lastPersistedErrorAtMs = nowMs;
      return true;
    };
    // The give-up is the verdict of the whole outage — it is never throttled.
    if (thresholdReached) return keep();

    // The failure before this one was a lone watchdog skip held back from app.log,
    // so THIS line is the first written evidence of the run — never throttled.
    if (this._heldBackWatchdog) return keep();

    // A different SYMPTOM is never throttled either: "the stalls turned into no
    // answer" is the single most informative line of an outage, and it can
    // happen exactly once (the last error before a recovery), so a time floor
    // could swallow it for good. This is safe against the flood below only
    // because `_lastPersistedErrorKind` now survives endOutage() — otherwise
    // every reopened outage would look like a kind change.
    if (kind !== this._lastPersistedErrorKind) return keep();

    // recordTransfer runs BEFORE noteOutageError, so the open record does not yet
    // include the error being logged right now — hence the +1. With no outage
    // open this IS the first error and the run counter is all we have.
    const errorsSoFar = this._openOutage ? this._openOutage.errors + 1 : consecutiveErrors;

    // Periodic marker of a long run: keeps the timeline readable and is already
    // rare by construction (~1 line/s at the storm cadence), so no extra floor.
    if (errorsSoFar > 1 && errorsSoFar % PERSIST_EVERY_NTH_ERROR === 0) return keep();

    // First error of an outage, or first of a fresh run after a success. Both are
    // worth a line — but not more often than PERSIST_MIN_GAP_MS, because a link
    // that fails one frame in three re-triggers both on every single failure.
    // Throttled here means "not delivered": the event keeps its level and stays
    // in the detailed recent ring, so support loses nothing.
    if (errorsSoFar <= 1 || consecutiveErrors <= 1) {
      if (nowMs - this._lastPersistedErrorAtMs < PERSIST_MIN_GAP_MS) return false;
      return keep();
    }
    return false;
  }

  // Тот же пол частоты, что у ошибок (PERSIST_MIN_GAP_MS), но для строки «связь
  // восстановилась» — и по зеркальной причине. Мигающая связь (ошибка → успех → ошибка)
  // делает КАЖДЫЙ успех «восстановлением»: на 40 Гц это до 20 синхронных записей в
  // app.log в секунду прямо на такте вывода, а кольцо persistentEvents (100 слотов)
  // вымывается за секунды — телеметрия берёт оттуда последние 12 событий, и в отчёт о
  // сбое поехали бы 12 строк «восстановилось» вместо настоящих улик (`sunlite-open` и
  // прочих). До 11.09.2026 этот путь был только у uDMX; общий учёт кадров открыл его
  // всем транспортам, где чередование «ошибка/успех» на сетевых сбоях обычное дело.
  // Глушится ДОСТАВКА, а не улика: событие остаётся в подробном кольце recentEvents со
  // своим уровнем. Настоящее восстановление после провала приходит редко и проходит
  // через этот пол всегда.
  _shouldPersistRecovery() {
    const nowMs = this._now();
    if (nowMs - this._lastPersistedRecoveryAtMs < PERSIST_MIN_GAP_MS) return false;
    this._lastPersistedRecoveryAtMs = nowMs;
    return true;
  }

  recordCoalesced() {
    this.totals.coalescedFrames++;
    this.window.stats.coalescedFrames++;
  }

  recordTransfer(data = {}) {
    const nowMs = this._now();
    const at = new Date(nowMs).toISOString();
    const success = !!data.success;
    const errorKind = data.error && data.error.kind ? data.error.kind : 'OTHER';
    const out = [];

    const deviceType = data.device && typeof data.device.type === 'string'
      && /^[a-z0-9-]{1,32}$/.test(data.device.type)
      ? data.device.type : null;
    if (deviceType && !this.totalsByType[deviceType]
        && Object.keys(this.totalsByType).length < 16) {
      this.totalsByType[deviceType] = emptyTransferStats();
      this.confirmationsByType[deviceType] = Object.create(null);
    }
    const scopedStats = deviceType ? this.totalsByType[deviceType] : null;
    const deviceId = data.device && typeof data.device.id === 'string'
      && data.device.id.length > 0 && data.device.id.length <= 200 ? data.device.id : null;
    if (deviceId && !this.totalsByDeviceId.has(deviceId) && this.totalsByDeviceId.size < 32) {
      this.totalsByDeviceId.set(deviceId, emptyTransferStats());
      this.confirmationsByDeviceId.set(deviceId, Object.create(null));
    }
    const deviceStats = deviceId ? this.totalsByDeviceId.get(deviceId) : null;
    for (const stats of [this.totals, this.window.stats, scopedStats, deviceStats].filter(Boolean)) {
      stats.attempts++;
      addDuration(stats, data.durationMs);
      if (success) {
        stats.successes++;
        stats.lastSuccessAt = at;
      } else {
        stats.errors++;
        stats.errorsByKind[errorKind] = (stats.errorsByKind[errorKind] || 0) + 1;
        stats.lastErrorAt = at;
      }
    }

    // Только ключи из словаря: карта уровней обязана оставаться маленькой и целиком
    // описанной. Незнакомое значение (опечатка в новом транспорте) молча отбрасывается —
    // счётчики кадров от этого не страдают, а в отчёт не попадёт уровень без расшифровки.
    const confirmation = typeof data.confirmation === 'string'
      && Object.prototype.hasOwnProperty.call(CONFIRMATION_MEANING, data.confirmation)
      ? data.confirmation
      : null;
    if (confirmation) {
      this.confirmations[confirmation] = (this.confirmations[confirmation] || 0) + 1;
      this.lastConfirmation = confirmation;
      if (scopedStats) {
        const byLevel = this.confirmationsByType[deviceType];
        byLevel[confirmation] = (byLevel[confirmation] || 0) + 1;
      }
      if (deviceStats) {
        const byLevel = this.confirmationsByDeviceId.get(deviceId);
        byLevel[confirmation] = (byLevel[confirmation] || 0) + 1;
      }
    }

    const channelCount = Number(data.channelCount);
    const bucketKey = payloadBucketKey(data.fullFrame ? 512 : channelCount);
    if (bucketKey) {
      const bucket = this.payloadStats[bucketKey];
      bucket.attempts++;
      if (!success) bucket.errors++;

      // UDMX-010: same tally, split by what the payload WAS. Guarded by the same
      // bucket check so a transport that reports no size at all (the serial
      // ones) cannot silently land in `delta`.
      // UDMX-012: the probe is not a delta — it is the gate in front of the
      // seed, and lumping it into `delta` would hide exactly the comparison it
      // exists to make.
      const kindKey = data.fullFrame
        ? 'full'
        : (data.seedProbe ? 'seedProbe' : (data.keepalive ? 'keepalive' : 'delta'));
      const kind = this.frameKinds[kindKey];
      kind.attempts++;
      if (!success) kind.errors++;
      if (kindKey === 'delta' && Number.isFinite(channelCount)
          && channelCount >= WIDE_DELTA_MIN_CHANNELS) {
        this.frameKinds.wideDelta.attempts++;
        if (!success) this.frameKinds.wideDelta.errors++;
      }
    }

    if (!success) {
      const consecutiveErrors = data.consecutiveErrors || 0;
      // A lone watchdog skip (Open DMX / Enttec Pro: the driver answered late, the
      // next frame went out fine) is background noise — ~1 per 3000 frames on a
      // healthy stick, mostly while the app is still starting (2026-11-02). It keeps
      // its WARN in the recent ring and in every counter, but stays out of app.log;
      // a second failure in a row is written instead, as the run's first line.
      const heldBack = data.phase === 'watchdog'
        && consecutiveErrors <= 1
        && !data.thresholdReached;
      const persist = heldBack ? false : this._shouldPersistError(
        errorKind,
        consecutiveErrors,
        !!data.thresholdReached,
      );
      this._heldBackWatchdog = heldBack;
      out.push(this.recordEvent('transfer-error', {
        sessionId: data.sessionId || null,
        device: data.device || null,
        transferSequence: data.transferSequence || null,
        durationMs: round(data.durationMs),
        phase: data.phase || 'callback',
        // Чем ЭТОТ транспорт подтверждает успех: без уровня строка ошибки у Art-Net
        // («ядро не приняло пакет») читалась бы так же, как у uDMX («прибор не
        // ответил»), а это разные по тяжести события.
        confirmation: confirmation,
        // Сетевые транспорты несут свет в несколько вселенных одним подключением —
        // упавшая вселенная должна быть названа, иначе по журналу не понять, весь
        // ли зал потемнел или один его угол.
        universe: data.universe == null ? null : data.universe,
        error: data.error || null,
        consecutiveErrors,
        thresholdReached: !!data.thresholdReached,
        // UDMX-006: what was actually on the wire when it failed. Without this a
        // report cannot answer "did the FIRST failure hit a partial range or a
        // full frame?" — the question that separates a delta-scheme bug from a
        // sick stick (successes carried it, failures did not).
        channelStart: data.channelStart == null ? null : data.channelStart,
        channelCount: data.channelCount == null ? null : data.channelCount,
        fullFrame: data.fullFrame == null ? null : !!data.fullFrame,
        // UDMX-010: frameKinds can say "12 % of refresh chunks fail"; this says
        // WHICH lines those were.
        keepalive: data.keepalive == null ? null : !!data.keepalive,
        // UDMX-012: был ли это короткий пробник перед засевом.
        seedProbe: data.seedProbe == null ? null : !!data.seedProbe,
        usbPresence: data.usbPresence || null,
      }, { level: data.thresholdReached ? 'ERROR' : 'WARN', persist }));
    } else {
      // Recovery from a held-back lone skip has nothing in app.log to close.
      const healedHeldBack = this._heldBackWatchdog && data.recoveredAfterErrors === 1;
      this._heldBackWatchdog = false;
      if (data.recoveredAfterErrors > 0) {
        out.push(this.recordEvent('transfer-recovered', {
          sessionId: data.sessionId || null,
          device: data.device || null,
          transferSequence: data.transferSequence || null,
          recoveredAfterErrors: data.recoveredAfterErrors,
          durationMs: round(data.durationMs),
        }, { level: 'INFO', persist: healedHeldBack ? false : this._shouldPersistRecovery() }));
      }
    }

    const elapsedMs = nowMs - this.window.startedAtMs;
    if (elapsedMs >= this.windowMs) {
      out.push(this.recordEvent('transfer-summary', {
        windowStartedAt: new Date(this.window.startedAtMs).toISOString(),
        elapsedMs,
        stats: statsSnapshot(this.window.stats, elapsedMs),
      }));
      this.window = this._newWindow();
    }
    return out;
  }

  snapshot(currentState = null) {
    const nowMs = this._now();
    return {
      schema: 'svetomaster-dmx-diagnostics/2',
      startedAt: this.startedAt,
      generatedAt: new Date(nowMs).toISOString(),
      limits: {
        maxRecentEvents: this.maxEvents,
        maxPersistentEvents: this.maxPersistentEvents,
        maxOutages: this.maxOutages,
        transferWindowMs: this.windowMs,
      },
      // UDMX-006: the history a support engineer reads FIRST — every outage of
      // the whole session, immune to the per-error spam that evicts the rings.
      outageJournal: {
        total: this.outageSequence,
        journalled: this.outages.length,
        minor: { ...this.minorOutages },
        open: this._openOutage ? this._outageSnapshot(this._openOutage, nowMs) : null,
        records: this.outages.slice(),
      },
      currentState,
      transferTotals: statsSnapshot(this.totals, Math.max(1, nowMs - Date.parse(this.startedAt))),
      transferByType: Object.fromEntries(Object.entries(this.totalsByType)
        .map(([type, stats]) => [type, {
          ...statsSnapshot(stats),
          confirmationByLevel: { ...this.confirmationsByType[type] },
        }])),
      // 2026-09-11: чем подтверждены эти успехи. Пустая карта = кадров не было
      // вовсе («молчит»), и это тоже ответ — раньше такой же ноль показывал
      // исправно работающий Sunlite или Art-Net просто потому, что их никто не
      // считал. Расшифровка идёт вместе с цифрами: отчёт читают и человек, и ИИ,
      // и ни один из них не обязан помнить наш словарь уровней.
      transferConfirmation: {
        last: this.lastConfirmation,
        byLevel: { ...this.confirmations },
        meaning: Object.fromEntries(
          Object.keys(this.confirmations).map(key => [key, CONFIRMATION_MEANING[key]]),
        ),
      },
      // UDMX-007: где именно рвётся — по размеру посылки.
      payloadSizes: Object.fromEntries(
        Object.entries(this.payloadStats).map(([key, value]) => [key, {
          attempts: value.attempts,
          errors: value.errors,
          errorRatePct: value.attempts ? round(value.errors * 100 / value.attempts) : null,
        }]),
      ),
      // UDMX-010: и по ВИДУ посылки. `wideDelta` — подмножество `delta`
      // (дельта шире одного куска освежения), а не отдельная популяция.
      frameKinds: Object.fromEntries(
        Object.entries(this.frameKinds).map(([key, value]) => [key, {
          attempts: value.attempts,
          errors: value.errors,
          errorRatePct: value.attempts ? round(value.errors * 100 / value.attempts) : null,
        }]),
      ),
      currentTransferWindow: {
        startedAt: new Date(this.window.startedAtMs).toISOString(),
        elapsedMs: Math.max(0, nowMs - this.window.startedAtMs),
        stats: statsSnapshot(this.window.stats, Math.max(1, nowMs - this.window.startedAtMs)),
      },
      persistentEvents: this.persistentEvents.slice(),
      recentEvents: this.events.slice(),
    };
  }

  /** Только итоги выбранной железки, без её ID в возвращаемом объекте. */
  deviceTransferStats(deviceId) {
    if (typeof deviceId !== 'string' || !this.totalsByDeviceId.has(deviceId)) return null;
    return {
      ...statsSnapshot(this.totalsByDeviceId.get(deviceId)),
      confirmationByLevel: { ...this.confirmationsByDeviceId.get(deviceId) },
    };
  }
}

module.exports = {
  DmxDiagnostics,
  CONFIRMATION_MEANING,
  shouldPersistEvent,
  classifyUsbError,
  serializeUsbError,
  isUdmxDevice,
  snapshotUsbDevice,
  snapshotUdmxDevices,
  usbDeviceSignature,
  cleanDeviceInfo,
};
