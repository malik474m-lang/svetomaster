const usb = require('usb');
const BaseDmxTransport = require('./BaseDmxTransport');
const { isDeviceGoneError, isLibusbDeviceLostError } = require('./reconnectUtils');
const banGate = require('../main/license/banGate');
const {
  isUdmxDevice,
  snapshotUsbDevice,
  snapshotUdmxDevices,
  serializeUsbError,
  classifyUsbError,
} = require('./DmxDiagnostics');

const {
  UDMX_MODELS,
  SESSION_REQUEST,
  SESSION_VALUE,
  SESSION_INDEX_BASE,
  SESSION_ANSWER_MASK,
  modelOf,
  modelByIds,
} = require('./udmxModels');

const UDMX_VID = 0x16C0;
const UDMX_PID = 0x05DC;
const FRAME_SIZE = 512;
// cmd_SetChannelRange. On clones with a session handshake the byte actually put
// on the wire is this value XOR the session mask (see _openSession).
const CMD_SET_CHANNEL_RANGE = 0x02;

// DMXMGR-002: stable physical USB location (bus + port path) — the USB analog of a
// serial COM-port `path`. uDMX exposes NO serialNumber/path, so two identical
// sticks were indistinguishable (id was a volatile getDeviceList() array index),
// making the device list order and auto-reconnect "jump" between the two units.
// portNumbers is the physical topology position: two devices can never share a
// port, so it is BOTH stable across re-enumeration/power-blips AND unique. When
// portNumbers is unavailable we fall back to the device address — unique within a
// single enumeration (so the autoConnect dedup never collapses two sticks into one)
// but less stable across replug (reconnect then degrades to the deterministic
// fallback, same as a serial COM-port that got reassigned).
function usbLocationOf(dev) {
  const bus = (dev && dev.busNumber != null) ? dev.busNumber : '?';
  const ports = (dev && Array.isArray(dev.portNumbers) && dev.portNumbers.length)
    ? dev.portNumbers.join('.')
    : 'a' + ((dev && dev.deviceAddress != null) ? dev.deviceAddress : '?');
  return `${bus}-${ports}`;
}

// Unplug detection: consecutive controlTransfer failures (no success in between)
// mean the device is gone. ~20 frames ≈ 0.8s at the UDMX-002 25 FPS clock. A success
// resets the counter, so rare transient TIMED_OUTs during normal operation never
// trip it. Needed because Windows libusb often returns TIMED_OUT (not NO_DEVICE)
// on unplug — a message-only check missed it and the uDMX stayed "green" but dead.
// UDMX-004: this fast path now covers ONLY the "device stopped answering" errors
// (TIMED_OUT/IO/…). A STALL means the stick DID answer on the wire, so it is
// physically present and goes through the recovery ladder instead.
const UDMX_MAX_CONSEC_ERRORS = 20;

// UDMX-011: how long the answer to "is the stick still on the bus?" may be
// reused. Only a failed transfer whose error is ambiguous (`NOT_FOUND`) asks,
// and a real unplug is decided on the first one, so the TTL is not what keeps
// the cost down in the normal case. It matters for the one case that repeats:
// a storm of ambiguous errors on a stick that IS present — there this cache is
// what stops the probe from adding an enumeration per frame. Note the failure
// path already enumerates on its own (`snapshotUdmxDevices` in
// _handleTransferFailure), so the probe is an addition to that, not the first
// one; 250 ms keeps it at 4/s per transport.
const UDMX_BUS_PROBE_TTL_MS = 250;

// ─── UDMX-002: frame pacing ──────────────────────────────────────────────────
// uDMX is a low-speed (1.5 Mbit) V-USB device: a full 512-byte control transfer
// physically occupies ~35 ms of wire time. The shared 25 ms (≈40 Hz) DmxManager
// clock therefore asks for frames faster than the stick can ever deliver, so the
// bus runs permanently saturated and every hiccup snowballs into coalescing.
// 40 ms ≈ 25 Hz stays inside the DMX refresh range and leaves real headroom.
const UDMX_MIN_FRAME_INTERVAL_MS = 40;

// ─── UDMX-003: partial channel ranges ────────────────────────────────────────
// cmd_SetChannelRange (bRequest 0x02) takes wValue = channel count and
// wIndex = first channel. The firmware keeps its own 512-byte buffer and clocks
// the DMX line from it, so we only have to push what actually changed: a
// 24-channel delta is ~4 ms of wire time instead of ~35 ms for the full frame.
// Invariants that keep the firmware buffer and our mirror in sync:
//   • the first frame after every open/reopen/reset is the FULL 512 — it seeds
//     the firmware buffer (and its max-channel watermark) and clears stale data;
//   • any failed transfer makes the device state unknown → next frame is full;
//   • an unchanged frame is not put on the wire at all, except for a periodic
//     full keep-alive so a silently dead stick is still noticed.
const UDMX_KEEPALIVE_MS = 1000;

// ─── UDMX-008: refresh in chunks instead of one 512-byte frame ───────────────
// The 2026-09-01 field report (Core Ultra 5 225H laptop) was the first to carry
// the payload-size breakdown, and it came out MIRRORED to ours:
//   deltas      2421 transfers / 1 error   = 0,04 %
//   full frames  295 transfers / 85 errors = 28,81 %
// A full frame is 64 packets back to back and ~35 ms of uninterrupted bus time;
// that host cannot carry a transfer that long, while short ones pass cleanly.
// Two of our own mechanisms hit such a host hardest: the once-per-second
// keep-alive, and "any error forces a full frame". The second one was a loop —
// a failed full frame forced another full frame with the same odds of failing,
// which is where the 44- and 42-error storms in that same report came from.
// The full refresh period stays EXACTLY as before (one second); only the slicing
// changes: 8 chunks of 64 channels every 125 ms instead of one 512-byte frame.
// So the window in which mirror and device could drift apart has not grown, and
// on healthy hardware the cost is nearly the same (8x~6 ms against one ~35 ms).
const UDMX_KEEPALIVE_CHUNK_CHANNELS = 64;
const UDMX_KEEPALIVE_CHUNK_MS = Math.round(
  UDMX_KEEPALIVE_MS / (FRAME_SIZE / UDMX_KEEPALIVE_CHUNK_CHANNELS),
);
// The refresh yields to real changes — otherwise a smooth chase would eat a
// frame of delay on every chunk. But never for longer than this: a busy stage
// must not be able to starve it. Once per second one frame may go out a tick
// late, which is exactly what the old full-frame keep-alive already cost.
const UDMX_KEEPALIVE_DEFER_MAX_MS = 1000;

// ─── UDMX-007: never put a one-packet range on the wire ──────────────────────
// Measured on real hardware (2026-08-22, uDMX bcdDevice 0x0102, A/B with payload
// size as the ONLY variable, three interleaved rounds, ~9 300 transfers):
//   1 channel  → 1,83 % STALL      22 channels  → 0 % of 1675
//   2 channels → 4,09 % STALL      58 channels  → 0 % of 1247
//   4 channels → 4,57 % STALL      512 (full)   → 0 % of  902
// Zero errors in 3824 transfers of >= 22 channels against 189 in 5403 transfers
// of <= 4 channels: the firmware stumbles on the SIZE, not on the address (the
// same starts pass in the wider profiles) and not on the rate (the clock is the
// same everywhere).
// A second sweep pinned the boundary to a single channel, and it lands exactly
// where the USB spec says it would — low-speed carries 8 bytes per data packet:
//   4 ch 5,92 %   6 ch 9,98 %   8 ch 12,23 %  ← one data packet: broken
//   5 ch 5,96 %   7 ch 12,15 %  9 ch  0,00 %  ← two packets: clean, and stays
//                                                clean at 10/12/16/22/512
// The failure rate even RISES towards the packet limit and then vanishes, and
// the latency signature follows it (p95 28 ms below the boundary, 3,7-4,8 ms
// above). So the firmware mishandles a control-OUT whose data stage fits in one
// packet — nothing about DMX, addresses or timing is involved.
// So the UDMX-003 delta scheme was feeding the stick its least digestible
// request — a chase that smoothly moves one head produced a 1-4 byte write every
// 40 ms and, with it, ~4 % failed transfers plus a forced full frame after each.
// Every partial range is therefore grown to at least this many channels. The
// extra bytes are the CURRENT frame values, so a wider write is always as correct
// as the narrow one it replaces, and padding costs nothing worth counting
// (p50 2,7 ms → 4,4 ms). The value is 4x the measured boundary on purpose: clone
// firmwares are not obliged to break in the same place.
const UDMX_MIN_RANGE_CHANNELS = 32;

// ─── UDMX-004: staged recovery ───────────────────────────────────────────────
// Field evidence (2026-07/08): one USB environment produced long runs of STALL
// and direct libusbK also failed intermittently, while the same physical uDMX
// with the same driver version passed cleanly on another PC. The exact root
// cause is therefore unresolved; the application only contains the outage and
// must not turn a temporary USB-environment failure into a false recovery.
// Ladder (Microsoft's own order: clear the error, then reset, then re-init):
//   1. single errors            → nothing, the next frame just retries;
//   2. N consecutive errors     → close + reopen the libusb handle, and (STALL
//                                 only) drop to the UDMX-006 storm cadence;
//   3. no success for 1.5 s     → ONE device.reset() (port reset), rate-limited
//                                 — OFF by default since UDMX-006, see below;
//   4. no success for 10 s      → give up, hand over to the reconnect supervisor.
const UDMX_REOPEN_AFTER_ERRORS = 5;
const UDMX_RESET_AFTER_MS = 1500;
const UDMX_LOST_AFTER_MS = 10000;

// ─── UDMX-012: knock before carrying the piano in ────────────────────────────
// Field case 2026-09-18 (`m***@mail.ru`, 15 outages in 39 min). Every outage
// followed the same script: the stick stops answering, the ladder reopens the
// handle, `_needFullFrame` then demands the seed, and because the flag only
// clears on a SUCCESSFUL full frame, the 512-byte seed was repeated every 250 ms
// for the whole 10-second give-up window. 1020 of 1036 full frames in that
// report are that one retry loop.
// Two things are wrong with answering a failure this way. Practically: the
// heaviest transfer we own is the worst thing to spend a dead stick's time on,
// and on a host that cannot carry a long transfer (the 2026-09-01 profile) it is
// self-defeating. Evidentially: while the loop runs we send NOTHING else, so the
// report cannot say whether the stick died outright or only chokes on long
// transfers — the one question the whole case turns on. The 7 host-diagnostic
// runs of 2026-09-18 could not answer it either, because that tool sends 512 and
// nothing but 512.
// So the seed is now gated by a probe of exactly one refresh chunk. The probe is
// an ordinary, correct DMX write of the current frame values (same shape the
// keep-alive uses all day), it costs ~5 ms instead of ~33 ms, and its outcome
// versus the seed's is recorded separately. A failed seed re-arms the probe, so
// the ladder can never sit there repeating a 512 into a stick that has already
// refused a 64.
// NOT a new width: it reuses UDMX_KEEPALIVE_CHUNK_CHANNELS on purpose, because
// that is already the size this firmware family demonstrably digests best
// (UDMX-007 floor of 32, UDMX-008 chunk of 64, and 7223 of 7237 such transfers
// passing in the very report that prompted this).
// device.reset() is not a free "clear the error" call — it can re-enumerate the
// stick. Never fire it twice inside this window, so a flapping link can't turn
// into a reset storm that keeps the device permanently re-enumerating.
const UDMX_RESET_COOLDOWN_MS = 20000;

// ─── UDMX-006: the port-reset step is OFF by default ─────────────────────────
// Verdict from two independent field cases (Acer Spin 2026-07, i5-13420H
// 2026-08-14) covering two PCs and two sticks: the reset never once shortened an
// outage. Both times it reported ok — and the stall storm continued unchanged
// until the stick itself left the bus. In the August report the second reset was
// followed 1.7 s later by the device vanishing from USB enumeration for 17+ s:
// a port reset re-enumerates the device, so the step can only ever have turned
// a 13-second stall storm into a 30-second hole. Verified harmful-or-useless
// beats theoretically-helpful, so the ladder now ends at reopen → give up.
// The step is kept (not deleted) behind a switch: the moment a stick shows up
// that a port reset DOES rescue, `SVETO_UDMX_PORT_RESET=1` brings it back
// without a rebuild — and support can ask a single user to try it.
function portResetEnabled() {
  return process.env.SVETO_UDMX_PORT_RESET === '1';
}

// A close+open (or a reset that rebinds the descriptor) is a new connection,
// not continuation on the already admitted handle. Fail closed specifically for
// this recovery boundary; ordinary sends on the still-open handle stay untouched.
function mayRecoverConnection() {
  try { return banGate.mayAttemptConnection(); } catch (_) { return false; }
}

// ─── UDMX-006: gentle retry while a stall storm is running ───────────────────
// A single STALL is normal background for uDMX and must be retried at once — the
// next frame is only 40 ms away and nobody sees it. A RUN of them is different:
// the August report shows 165 failed control transfers in 10 s, i.e. we kept
// hammering a stick that had already stopped answering, and libusb/libusbK kept
// walking the whole USB stack for every one of them. Once the cheap ladder step
// has already failed (UDMX_REOPEN_AFTER_ERRORS in a row), back off to a much
// slower cadence: it gives the V-USB firmware room to come back on its own,
// stops us from adding bus traffic to a bus that is already in trouble, and
// keeps the log readable. The ladder still advances — the timers below run off
// wall-clock, not off the error count.
// Only for STALL (the stick ANSWERED): a run of no-answer errors is how Windows
// reports an unplug, and that path must stay fast so the badge goes red quickly.
const UDMX_STORM_RETRY_MS = 250;

// ─── UDMX-007: the amber badge belongs to a CONFIRMED outage ─────────────────
// A single STALL is normal background for uDMX and heals on the very next frame
// (~40 ms). Announcing `degraded` on the FIRST error therefore painted the whole
// header amber for one frame — 88 times in two minutes on a healthy stick while
// a chase was running (2026-08-22). A healthy system must not look broken, and a
// badge nobody can trust is worse than no badge, so the amber state waits until
// the outage is confirmed by the same measure the ladder uses.
const UDMX_DEGRADED_AFTER_MS = 500;
// The 250 ms after-snapshot is evidence, not telemetry: one per two seconds is
// plenty to see "still enumerated" turn into "gone".
const UDMX_PRESENCE_RECHECK_MIN_GAP_MS = 2000;
// device.reset() goes through the Windows USB stack — on the very host that
// misbehaves it can hang. Without a bound, a reset that never calls back would
// park every frame forever and the ladder could never reach its give-up step.
const UDMX_RESET_WATCHDOG_MS = 3000;

// Module scope on purpose: a give-up destroys the transport and the reconnect
// builds a NEW one, so an instance field could never rate-limit anything across
// an outage. The August report caught exactly that — two port resets 10 s apart
// despite a 20 s cooldown, because session 13 started with a clean instance.
// Keyed by USB location so two sticks never share a limiter.
const lastPortResetAtMsByLocation = new Map();

class UdmxTransport extends BaseDmxTransport {
  constructor(deviceInfo) {
    super(deviceInfo);
    this.device = null;
    this.minFrameIntervalMs = UDMX_MIN_FRAME_INTERVAL_MS; // UDMX-002
    // A successful device.open() proves only that Windows returned a handle.
    // Recovery is confirmed by the first successful controlTransfer callback.
    this.requiresDmxTransferConfirmation = true;
    // Самое сильное подтверждение из всех наших транспортов: успех здесь — это
    // ответ самого устройства на USB control transfer, а не «драйвер принял».
    this.transferConfirmation = 'device';
    this._consecErrors = 0; // consecutive controlTransfer failures (DMX-004)
    this._inFlight = false;  // UDMX-001: coalescing gate — one USB transfer at a time
    this._pending = null;    // UDMX-001: latest undelivered frame (Buffer | null)
    this._transferSequence = 0;
    this._usbAttachHandler = null;
    this._usbDetachHandler = null;
    // UDMX-003: mirror of what the stick's own buffer is believed to hold. Only a
    // CONFIRMED (successful) transfer updates it — an error leaves it unknown.
    this._deviceState = Buffer.alloc(FRAME_SIZE);
    this._needFullFrame = true;
    // UDMX-012: пока true, засев ждёт короткого пробника — см. _planTransfer.
    this._seedProbePending = true;
    // UDMX-008: курсор освежения и диапазон, который надо починить после ошибки.
    this._keepaliveStart = 0;
    this._nextChunkAtMs = 0;
    this._dirtyStart = -1;
    this._dirtyEnd = -1;
    this._skippedIdenticalFrames = 0;
    // UDMX-004: current outage (null while healthy), and the reset rate limiter.
    this._outage = null;
    this._recovering = false;
    // UDMX-006: storm back-off + diagnostics throttling.
    this._retryTimer = null;
    this._lastAttemptAtMs = 0;
    this._lastPresenceRecheckAtMs = 0;
    // UDMX-011: cached answer of the "still on the bus?" probe (see _stickOnBus),
    // plus the verdict of the last probe so the report can show WHY the link was
    // declared dead ('gone' — the bus confirmed it; null — the error alone did).
    this._busProbeAtMs = 0;
    this._busProbeResult = true;
    this._lastBusVerdict = null;
    // Which stick this is (see udmxModels). Falls back to the original uDMX so a
    // deviceInfo built by older code keeps working unchanged.
    this._model = modelByIds(deviceInfo && deviceInfo.vid, deviceInfo && deviceInfo.pid)
      || modelByIds(UDMX_VID, UDMX_PID);
    // Raw bRequest for a DMX frame. Plain uDMX uses the constant; a clone with a
    // handshake gets it masked per session, and null means "session not open yet".
    this._dmxRequest = this._model.session ? null : CMD_SET_CHANNEL_RANGE;
    this._sessionInFlight = false;
  }

  static scan() {
    const results = [];
    const devices = usb.getDeviceList();
    devices.forEach((dev) => {
      const model = modelOf(dev);
      if (model) {
        const loc = usbLocationOf(dev);
        results.push({
          // DMXMGR-002: id and path derive from the stable USB location (not the
          // volatile array index) so two identical uDMX sticks are distinguishable
          // and re-findable across re-enumeration. `path` mirrors the serial
          // transports' COM-port path, so the generic dedup / reconnect-by-path /
          // stable-sort logic in DmxManager + reconnectUtils works uniformly.
          id: `${model.idPrefix}-${loc}`,
          type: 'udmx',
          name: model.name,
          path: `usb:${loc}`,
          // Carried so a reconnect re-binds to the SAME model, not merely to the
          // first uDMX-class stick that happens to be plugged in.
          vid: model.vid,
          pid: model.pid,
          _usbDevice: dev
        });
      }
    });
    return results;
  }

  // UDMX-006: tell the caller the moment a uDMX (re-)appears on the bus. When a
  // stick re-enumerates after an outage the supervisor would otherwise sit out
  // the rest of its 3 s scan tick — up to 3 more seconds of dark fixtures on top
  // of a hole the user already felt. Kept here, not in DmxManager, so the 'usb'
  // native module stays a transport-level dependency. Returns an unsubscribe fn;
  // a no-op one when hotplug is unavailable, so callers need no platform checks.
  static watchAttach(handler) {
    if (typeof handler !== 'function' || typeof usb.on !== 'function') return () => {};
    const listener = (device) => {
      if (!isUdmxDevice(device)) return;
      try { handler(snapshotUsbDevice(device)); } catch { /* never break USB events */ }
    };
    try {
      usb.on('attach', listener);
      // Hotplug polling must not keep the process (or a vitest run) alive.
      if (typeof usb.unrefHotplugEvents === 'function') usb.unrefHotplugEvents();
    } catch {
      return () => {};
    }
    return () => {
      try {
        if (typeof usb.removeListener === 'function') usb.removeListener('attach', listener);
      } catch { /* module already torn down */ }
    };
  }

  // Always look up the uDMX freshly in the current device list — used by open()
  // and as a fallback when a cached _usbDevice handle has gone stale after replug.
  _findFreshDevice() {
    const matches = usb.getDeviceList().filter(d =>
      d.deviceDescriptor.idVendor === this._model.vid &&
      d.deviceDescriptor.idProduct === this._model.pid
    );
    if (matches.length === 0) return null;

    // DMXMGR-002: with two identical uDMX sticks, re-bind to the one at the SAME
    // physical USB location — otherwise a reconnect would grab "the first uDMX
    // found" and could drive the WRONG unit. The intended location is carried on
    // deviceInfo.path (`usb:<loc>`, set in scan()).
    const wantLoc = (this.deviceInfo && typeof this.deviceInfo.path === 'string')
      ? this.deviceInfo.path.replace(/^usb:/, '')
      : null;
    if (wantLoc) {
      const exact = matches.find(d => usbLocationOf(d) === wantLoc);
      if (exact) return exact;
    }
    // Location changed (moved to another USB port) or unknown → best-effort first.
    return matches[0];
  }

  // ═══ UDMX-011: is THIS stick still on the bus? ═════════════════════════════
  // Answers the only question that can turn an ambiguous `LIBUSB_ERROR_NOT_FOUND`
  // into a verdict. Two sticks of the same model are told apart by location, so
  // a second uDMX in another port never masks the disappearance of ours.
  // Fail-safe by construction: if the bus cannot be read the answer is "still
  // there", which leaves the outage to the existing ladder instead of tearing
  // the link down on a guess. Throttled because a storm would otherwise
  // enumerate USB 25 times a second — the cached answer is at most 250 ms old,
  // far inside the ~0.8 s the counter path used to need anyway.
  _stickOnBus() {
    const nowMs = Date.now();
    // `age >= 0` guards a backwards clock jump: a negative age would otherwise
    // freeze the cached answer until wall time caught up.
    const age = nowMs - this._busProbeAtMs;
    if (this._busProbeAtMs && age >= 0 && age < UDMX_BUS_PROBE_TTL_MS) {
      return this._busProbeResult;
    }
    let present = true;
    try {
      const matches = usb.getDeviceList().filter(d =>
        d.deviceDescriptor.idVendor === this._model.vid &&
        d.deviceDescriptor.idProduct === this._model.pid);
      if (matches.length === 0) {
        present = false;
      } else if (this.device && matches.includes(this.device)) {
        // The very handle we are driving is still enumerated. node-usb hands out
        // the SAME object for the same libusb device across getDeviceList()
        // calls (measured), so this is an identity check, not a guess — and it
        // is the only question that actually matters here.
        present = true;
      } else {
        // No identity match — fall back to the physical location. It is taken
        // from the OPEN handle first: `deviceInfo.path` is written once by
        // scan() and never updated, so it goes stale whenever the ladder
        // re-bound to another entry (_findFreshDevice falls back to "first of
        // this model") or the address-based location changed on a
        // re-enumeration. Trusting the stale value would report a LIVE stick as
        // gone — exactly the failure this probe exists to prevent.
        const wantLoc = this.device
          ? usbLocationOf(this.device)
          : ((this.deviceInfo && typeof this.deviceInfo.path === 'string')
            ? this.deviceInfo.path.replace(/^usb:/, '')
            : null);
        // Unknown location → "still there": never tear down a link on a guess.
        present = wantLoc ? matches.some(d => usbLocationOf(d) === wantLoc) : true;
      }
    } catch {
      present = true; // enumeration itself failed — do not call the stick gone
    }
    this._busProbeAtMs = nowMs;
    this._busProbeResult = present;
    return present;
  }

  // The unplug shortcut's gate. `NO_DEVICE` and friends are trusted outright;
  // `NOT_FOUND` only counts when the bus confirms the stick really left.
  // The text is assembled the same way classifyUsbError does it: libusb error
  // names reach us in `code` as often as in `message` (see tools/udmx-qc), and a
  // predicate that only reads `message` would miss exactly those.
  _isDeviceGone(err) {
    const text = [err && err.name, err && err.message, err && err.code]
      .filter(v => v !== undefined && v !== null && v !== '')
      .join(' ');
    // Recorded for the report: a support engineer must be able to tell "the bus
    // said the stick is gone" from "the error alone was conclusive".
    this._lastBusVerdict = null;
    if (isDeviceGoneError(text)) return true;
    if (!isLibusbDeviceLostError(text)) return false;
    const onBus = this._stickOnBus();
    this._lastBusVerdict = onBus ? 'present' : 'gone';
    return !onBus;
  }

  // The same fact the `busProbe` report field carries, in words for app.log:
  // an engineer reading the log must see WHY the link was cut on one error.
  _goneReason() {
    if (this._lastBusVerdict !== 'gone') return 'устройство сообщило об отключении';
    const loc = this.device
      ? usbLocationOf(this.device)
      : ((this.deviceInfo && this.deviceInfo.path) || 'локация неизвестна');
    return `палки нет на шине (${loc})`;
  }

  _startUsbMonitoring() {
    if (this._usbAttachHandler || typeof usb.on !== 'function') return;
    this._usbAttachHandler = (device) => {
      if (!isUdmxDevice(device)) return;
      this.notifyDiagnostic({
        type: 'usb-attach',
        changedDevice: snapshotUsbDevice(device),
        usbPresence: snapshotUdmxDevices(usb),
      });
    };
    this._usbDetachHandler = (device) => {
      if (!isUdmxDevice(device)) return;
      this.notifyDiagnostic({
        type: 'usb-detach',
        changedDevice: snapshotUsbDevice(device),
        usbPresence: snapshotUdmxDevices(usb),
      });
    };
    usb.on('attach', this._usbAttachHandler);
    usb.on('detach', this._usbDetachHandler);
  }

  _stopUsbMonitoring() {
    if (this._usbAttachHandler && typeof usb.removeListener === 'function') {
      usb.removeListener('attach', this._usbAttachHandler);
    }
    if (this._usbDetachHandler && typeof usb.removeListener === 'function') {
      usb.removeListener('detach', this._usbDetachHandler);
    }
    this._usbAttachHandler = null;
    this._usbDetachHandler = null;
  }

  // UDMX-006: rate limiter for the port reset, shared by every transport that
  // ever drives this physical stick (see lastPortResetAtMsByLocation).
  _resetLimiterKey() {
    // The map is module-scope and outlives the transport, so the SAME physical
    // stick must always produce the SAME key — hence both sources are reduced to
    // the bare USB location (`1-1`): `path` is `usb:1-1`, `id` is `<model>-1-1`.
    // Mixing the two raw forms would silently split the 20 s cooldown in half.
    // The bare literal is the last resort and would make two path-less sticks
    // share one limiter — the very bug UDMX-006 fixed.
    const info = this.deviceInfo || {};
    if (info.path) return String(info.path).replace(/^usb:/, '');
    if (info.id) return String(info.id).replace(/^[^-]*-/, '');
    return 'udmx';
  }

  _lastPortResetAtMs() {
    return lastPortResetAtMsByLocation.get(this._resetLimiterKey()) || 0;
  }

  // UDMX-006: re-offers the parked frame at the storm cadence. Never stacks —
  // one timer at a time, cleared by close() and by a healthy flush.
  _scheduleStormRetry(delayMs) {
    if (this._retryTimer) return;
    this._retryTimer = setTimeout(() => {
      this._retryTimer = null;
      this._flushPending();
    }, delayMs);
    if (typeof this._retryTimer.unref === 'function') this._retryTimer.unref();
  }

  _cancelStormRetry() {
    if (!this._retryTimer) return;
    clearTimeout(this._retryTimer);
    this._retryTimer = null;
  }

  _scheduleUsbPresenceRecheck(transferSequence, { force = false } = {}) {
    // Capture the current callback: DmxManager may tear the dead transport down
    // before this timer fires, but the 250 ms after-snapshot is exactly what lets
    // support distinguish "still enumerated" from "vanished/re-enumerated".
    const report = this.onDiagnostic;
    if (typeof report !== 'function') return;
    // Throttled outside the two moments that prove something: during a storm the
    // presence answer does not change 25 times a second, and the duplicates only
    // push real events out of the ring.
    const nowMs = Date.now();
    if (!force && nowMs - this._lastPresenceRecheckAtMs < UDMX_PRESENCE_RECHECK_MIN_GAP_MS) return;
    this._lastPresenceRecheckAtMs = nowMs;
    const timer = setTimeout(() => {
      try {
        report({
          type: 'usb-presence-recheck',
          transferSequence,
          delayMs: 250,
          usbPresence: snapshotUdmxDevices(usb),
        });
      } catch { /* diagnostics must never affect DMX I/O */ }
    }, 250);
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  _transferDurationMs(startedNs) {
    try {
      return Number(process.hrtime.bigint() - startedNs) / 1e6;
    } catch {
      return null;
    }
  }

  // Clones of the USBDMX512 kind refuse DMX until the host opens a session: an
  // IN request whose answer is the firmware signature XOR a random byte N. The
  // same N then masks every DMX request number, so the raw bRequest differs on
  // every connection. Plain uDMX has none of this and resolves immediately.
  // Resolves true when frames may be sent.
  _openSession() {
    if (!this._model.session) {
      this._dmxRequest = CMD_SET_CHANNEL_RANGE;
      return Promise.resolve(true);
    }
    return new Promise((resolve) => {
      const n = Math.floor(Math.random() * 256);
      const finish = (ok, error) => {
        this._dmxRequest = ok ? ((n ^ CMD_SET_CHANNEL_RANGE) & 0xFF) : null;
        this.notifyDiagnostic({
          type: 'udmx-session',
          ok,
          model: this._model.name,
          error: error || null,
        });
        resolve(ok);
      };
      try {
        this.device.controlTransfer(
          0xC0, SESSION_REQUEST, SESSION_VALUE, SESSION_INDEX_BASE | (n << 8), 4,
          (err, data) => {
            if (err) return finish(false, serializeUsbError(err));
            const answer = data && data.length >= 4 ? data[3] : null;
            const expected = (n ^ SESSION_ANSWER_MASK) & 0xFF;
            if (answer !== expected) {
              return finish(false, {
                kind: 'SESSION_REJECTED',
                message: `ответ ${answer === null ? 'пуст' : '0x' + answer.toString(16)}, ожидался 0x${expected.toString(16)}`,
              });
            }
            finish(true, null);
          }
        );
      } catch (e) {
        finish(false, serializeUsbError(e));
      }
    });
  }

  async open() {
    // Reset coalescing state on each (re)open — drop any stale pending frame.
    this._inFlight = false;
    this._pending = null;
    this._transferSequence = 0;
    // UDMX-003: a freshly opened stick holds unknown data — the first frame must
    // be the full 512 so the firmware buffer and our mirror start in sync.
    this._resetFrameState();
    this.notifyDiagnostic({
      type: 'transport-open-attempt',
      usbPresence: snapshotUdmxDevices(usb),
    });

    // UDMX-009: did re-enumeration actually hand us a DIFFERENT device object?
    // Field case 2026-09-01: after the stick left the bus for 261 ms and came
    // back at the same address, scan() kept listing it while open() answered
    // LIBUSB_ERROR_NO_DEVICE twelve times in a row — the app never recovered
    // without a restart. If the enumeration keeps returning the same stale entry
    // then the retry below is useless by construction, and that is the single
    // fact the reports could not tell us. Now every failed open carries it.
    let freshHandleDiffered = null;

    try {
      this.device = this.deviceInfo._usbDevice || this._findFreshDevice();
      if (!this.device) {
        this.lastError = 'uDMX не найден';
        this.notifyDiagnostic({
          type: 'transport-open-failed',
          error: { kind: 'NO_DEVICE', name: 'Error', message: this.lastError, code: null, errno: null },
          usbPresence: snapshotUdmxDevices(usb),
        });
        return false;
      }

      try {
        this.device.open();
      } catch (openErr) {
        // DMX-004: a cached _usbDevice handle goes stale after the uDMX is
        // re-plugged (libusb hands out a NEW object for the returned device).
        // Re-enumerate once and open the fresh handle — this is what makes
        // auto-reconnect actually take effect for uDMX.
        const fresh = this._findFreshDevice();
        if (!fresh) throw openErr;
        freshHandleDiffered = fresh !== this.device;
        this.device = fresh;
        this.device.open();
        console.log('🔁 uDMX: открыт свежий хэндл после переподключения');
      }

      // A stick that needs a session is not usable until it grants one: without
      // it every frame would be sent with a request number the firmware ignores,
      // and the badge would go green over a dead output.
      const sessionOk = await this._openSession();
      if (!sessionOk) {
        try { this.device.close(); } catch { /* handle already unusable */ }
        this.lastError = `${this._model.name}: устройство не открыло сессию`;
        this.connected = false;
        this.notifyDiagnostic({
          type: 'transport-open-failed',
          error: { kind: 'SESSION_REJECTED', name: 'Error', message: this.lastError, code: null, errno: null },
          usbPresence: snapshotUdmxDevices(usb),
        });
        console.log('❌ uDMX ошибка:', this.lastError);
        return false;
      }

      this.connected = true;
      this.lastError = null;
      this._consecErrors = 0;
      this._outage = null;
      this._startUsbMonitoring();
      this.notifyDiagnostic({
        type: 'transport-open-success',
        device: snapshotUsbDevice(this.device),
        usbPresence: snapshotUdmxDevices(usb),
      });
      console.log('✅ uDMX подключен');
      return true;
    } catch (err) {
      this.lastError = err.message;
      this.connected = false;
      this._stopUsbMonitoring();
      this.notifyDiagnostic({
        type: 'transport-open-failed',
        error: serializeUsbError(err),
        // null — до повторного перечисления дело не дошло; false — перечисление
        // отдало ТУ ЖЕ запись, и повтор был обречён; true — запись была другой.
        freshHandleDiffered,
        usbPresence: snapshotUdmxDevices(usb),
      });
      console.log('❌ uDMX ошибка:', err.message);
      return false;
    }
  }

  async close() {
    // Drop any in-flight coalescing state before killing the device handle.
    this._inFlight = false;
    this._pending = null;
    this._recovering = false;
    this._cancelStormRetry();
    this._resetFrameState();
    this._stopUsbMonitoring();

    let closeError = null;
    if (this.device) {
      try {
        this.device.close();
      } catch (e) {
        closeError = serializeUsbError(e);
      }
    }
    this.device = null;
    this.connected = false;
    this.notifyDiagnostic({
      type: 'transport-close',
      error: closeError,
      usbPresence: snapshotUdmxDevices(usb),
    });
  }

  send(dmxData) {
    if (!this.device || !this.connected) return;

    // Snapshot the frame to a 512-byte Buffer immediately. This protects against
    // the caller mutating dmxData after returning from send().
    const frame = this._buildFrame(dmxData);

    // Coalescing (UDMX-001): never stack USB controlTransfers. uDMX is slow (a
    // full frame is ~35 ms on low-speed USB) and even the UDMX-002 40 ms clock
    // can overlap it when the host stalls.
    // While one transfer is in-flight, store only the latest frame and return;
    // the callback flushes it. Intermediate (stale) DMX states are intentionally
    // dropped — only the current state matters on the wire.
    if (this._inFlight) {
      this._pending = frame;
      this.notifyDiagnostic({ type: 'frame-coalesced' });
      return;
    }
    this._transmit(frame);
  }

  _buildFrame(dmxData) {
    const data = Buffer.alloc(FRAME_SIZE);
    for (let i = 0; i < FRAME_SIZE; i++) {
      data[i] = (dmxData[i] !== undefined) ? dmxData[i] : 0;
    }
    return data;
  }

  // UDMX-003: forget what the stick is believed to hold. Called on open/close and
  // after every recovery step — the next frame then goes out as a full 512.
  _resetFrameState() {
    // A reopen or a port reset ends the vendor session too: the mask is bound to
    // the handle the firmware granted it for. Dropping it here means every
    // recovery path re-opens one before the next frame (see _transmit).
    if (this._model.session) this._dmxRequest = null;
    this._deviceState.fill(0);
    this._needFullFrame = true;
    this._seedProbePending = true; // UDMX-012
    this._keepaliveStart = 0;
    this._nextChunkAtMs = 0;
    this._dirtyStart = -1;
    this._dirtyEnd = -1;
    this._skippedIdenticalFrames = 0;
  }

  // UDMX-003: decide what actually has to travel over USB for this frame.
  // Returns { start, length, data, full, coversAllChanges } or null when the wire
  // can stay silent.
  _planTransfer(frame) {
    // Seeding after open/reopen: the firmware buffer and its max-channel
    // watermark have to start from a known state, and only the whole frame does
    // that. This is the one place a full 512 is still unavoidable, and it runs
    // once per connection rather than once per second.
    if (this._needFullFrame) {
      // UDMX-012: one refresh chunk first. It carries real current values, so
      // the write is as correct as any keep-alive — it just also answers
      // "is this stick alive at all?" for 5 ms instead of 33.
      if (this._seedProbePending) {
        const length = Math.min(UDMX_KEEPALIVE_CHUNK_CHANNELS, FRAME_SIZE);
        return {
          start: 0,
          length,
          data: frame.subarray(0, length),
          full: false,
          seedProbe: true,
          // Only the probed slice may be mirrored, exactly like a keep-alive.
          coversAllChanges: false,
        };
      }
      return { start: 0, length: FRAME_SIZE, data: frame, full: true, coversAllChanges: true };
    }

    let first = -1;
    let last = -1;
    for (let i = 0; i < FRAME_SIZE; i++) {
      if (frame[i] !== this._deviceState[i]) {
        if (first < 0) first = i;
        last = i;
      }
    }

    // UDMX-008: a range whose transfer failed is "unknown on the device" even
    // once the renderer puts the old value back — the mirror would then claim to
    // be in sync while a half-applied byte lived on the stick until the refresh
    // cycle happened to reach it. Repairing exactly what failed replaces the old
    // "any error forces a full 512", which on a host that chokes on long
    // transfers made every failure spawn another likely failure.
    if (this._dirtyStart >= 0) {
      first = first < 0 ? this._dirtyStart : Math.min(first, this._dirtyStart);
      last = Math.max(last, this._dirtyEnd);
    }

    const nowMs = Date.now();
    if (nowMs >= this._nextChunkAtMs
        && (first < 0 || nowMs - this._nextChunkAtMs >= UDMX_KEEPALIVE_DEFER_MAX_MS)) {
      const start = this._keepaliveStart;
      const length = Math.min(UDMX_KEEPALIVE_CHUNK_CHANNELS, FRAME_SIZE - start);
      this._keepaliveStart = (start + length) % FRAME_SIZE;
      this._nextChunkAtMs = nowMs + UDMX_KEEPALIVE_CHUNK_MS;
      return {
        start,
        length,
        data: frame.subarray(start, start + length),
        full: false,
        keepalive: true,
        // Only when the chunk happens to span every pending change may the whole
        // mirror be trusted afterwards — see the success handler.
        coversAllChanges: first < 0 || (start <= first && start + length > last),
      };
    }

    if (first < 0) {
      // Nothing changed, nothing to repair and the refresh is not due: the stick
      // keeps clocking the DMX line from its own buffer, so silence is right.
      this._skippedIdenticalFrames++;
      return null;
    }

    // One contiguous range covering every change: two transfers would cost more
    // wire time than the gap between them ever saves.
    let start = first;
    let length = last - first + 1;

    // UDMX-007: grow a too-narrow range to the safe minimum. The padding carries
    // the CURRENT frame values, so the write stays correct — it just also
    // (re)states channels that already hold those values. Prefer growing to the
    // right; only when that would run past the frame does the window slide back,
    // so the changed channels always stay inside it.
    if (length < UDMX_MIN_RANGE_CHANNELS) {
      length = UDMX_MIN_RANGE_CHANNELS;
      if (start + length > FRAME_SIZE) start = FRAME_SIZE - length;
    }

    return {
      start,
      length,
      data: frame.subarray(start, start + length),
      full: false,
      coversAllChanges: true,
    };
  }

  // UDMX-006: how long this frame must wait before touching the wire. 0 while
  // healthy — the pacing gate exists only inside a confirmed outage.
  // UDMX-010: the gate is no longer a boolean but the interval itself, because
  // it does two jobs at once and they need different numbers. It throttles a
  // stall storm (250 ms), AND it is the clock of the self-driven retry loop —
  // the loop that keeps the ladder moving when the renderer has gone quiet.
  // Switching the storm off by clearing a boolean therefore also switched the
  // loop off, and with no frames there are no failures, so neither the 20-error
  // shortcut nor the 10 s give-up could ever be reached: amber forever. Now a
  // stick that stopped answering hands the clock back to the normal 40 ms
  // instead of turning the gate off.
  _stormDelayMs() {
    const outage = this._outage;
    if (!outage || !outage.retryIntervalMs) return 0;
    const waitedMs = Date.now() - this._lastAttemptAtMs;
    return waitedMs >= outage.retryIntervalMs ? 0 : outage.retryIntervalMs - waitedMs;
  }

  _transmit(frame) {
    // While a recovery step (reopen/reset) is running the handle is not usable.
    // Park the frame — the step's completion flushes it.
    if (this._recovering) {
      this._pending = frame;
      return;
    }

    // A stall storm is in progress: park the frame and let the timer re-offer the
    // LATEST state later. Dropping it instead would be wrong twice over — the
    // fixtures would keep the pre-outage look after recovery, and with the
    // renderer quiet no further failure would ever drive the ladder to its
    // verdict, leaving the badge amber forever.
    const delayMs = this._stormDelayMs();
    if (delayMs > 0) {
      this._pending = frame;
      this._scheduleStormRetry(delayMs);
      return;
    }

    // Session lost (first frame after a reopen/reset on a clone that needs one):
    // park the frame, re-open the session, then let the flush deliver it.
    if (this._dmxRequest === null) {
      this._pending = frame;
      if (this._sessionInFlight) return;
      this._sessionInFlight = true;
      this._openSession().then(() => {
        this._sessionInFlight = false;
        if (this._dmxRequest !== null) this._flushPending();
      });
      return;
    }

    const plan = this._planTransfer(frame);
    if (!plan) return; // identical to what the stick already holds

    this._inFlight = true;
    this._lastAttemptAtMs = Date.now();
    const transferSequence = ++this._transferSequence;
    const startedNs = process.hrtime.bigint();
    try {
      this.device.controlTransfer(
        0x40, this._dmxRequest, plan.length, plan.start, plan.data,
        (err) => {
          this._inFlight = false;
          const durationMs = this._transferDurationMs(startedNs);
          if (!err) {
            const recoveredAfterErrors = this._consecErrors;
            const skippedIdenticalFrames = this._skippedIdenticalFrames;
            this._skippedIdenticalFrames = 0;
            // A delta covers every difference, so after it the whole frame is
            // confirmed on the device and all 512 bytes may be mirrored. A
            // keep-alive chunk does NOT necessarily cover the pending changes
            // (UDMX-008), and mirroring the whole frame after one would make the
            // transport believe it had delivered bytes it never sent — the light
            // would then simply stop following the console.
            if (plan.coversAllChanges) {
              frame.copy(this._deviceState);
            } else {
              frame.copy(this._deviceState, plan.start, plan.start, plan.start + plan.length);
            }
            if (plan.seedProbe) {
              // UDMX-012: the stick answered a short write, so the seed is now
              // worth its 512 bytes — but nothing has been seeded YET, so the
              // full-frame requirement must survive this success.
              this._seedProbePending = false;
            } else {
              this._needFullFrame = false;
            }
            if (plan.full) {
              // A full frame refreshed everything, so the chunk cycle restarts.
              this._keepaliveStart = 0;
              this._nextChunkAtMs = Date.now() + UDMX_KEEPALIVE_CHUNK_MS;
            }
            // The repair is done once a transfer that spans it has landed.
            if (this._dirtyStart >= 0
                && plan.start <= this._dirtyStart
                && plan.start + plan.length > this._dirtyEnd) {
              this._dirtyStart = -1;
              this._dirtyEnd = -1;
            }
            this.notifyDiagnostic({
              type: 'transfer-result',
              success: true,
              transferSequence,
              durationMs,
              recoveredAfterErrors,
              channelStart: plan.start,
              channelCount: plan.length,
              // UDMX-010: successes carry the payload identity too. Without it a
              // report can bucket a failure by size but cannot compare "full
              // frame" against "delta that happened to span the whole rig" — the
              // 2026-09-01 analysis had to assume the 257-512 bucket meant the
              // keep-alive frame.
              fullFrame: plan.full,
              keepalive: !!plan.keepalive,
              // UDMX-012: отделяет пробник от настоящего засева в отчёте.
              seedProbe: !!plan.seedProbe,
              skippedIdenticalFrames,
            });
            this._consecErrors = 0; // healthy frame — reset
            this._finishOutage(durationMs);
          } else if (this._isDeviceGone(err)) {
            // Fast path: clean NO_DEVICE → reconnect immediately.
            this.notifyDiagnostic({
              type: 'transfer-result',
              success: false,
              transferSequence,
              durationMs,
              phase: 'callback',
              error: serializeUsbError(err),
              consecutiveErrors: this._consecErrors + 1,
              thresholdReached: false,
              disconnectReason: 'usb-gone',
              busProbe: this._lastBusVerdict,
              channelStart: plan.start,
              channelCount: plan.length,
              fullFrame: plan.full,
              keepalive: !!plan.keepalive,
              // UDMX-012: отделяет пробник от настоящего засева в отчёте.
              seedProbe: !!plan.seedProbe,
              usbPresence: snapshotUdmxDevices(usb),
            });
            this._scheduleUsbPresenceRecheck(transferSequence, { force: true });
            this._cancelStormRetry(); // the ladder is over — nothing left to pace
            this._pending = null;
            this.connected = false;
            console.log(`❌ uDMX: ${this._goneReason()} — связь разорвана`);
            this.notifyDisconnect('usb-gone');
            return;
          } else {
            // Robust path: any other error (incl. TIMED_OUT and STALL) goes
            // through the UDMX-004 ladder, which decides whether to retry, heal
            // the handle, reset the port, or finally give up.
            const gaveUp = this._handleTransferFailure(err, {
              transferSequence,
              durationMs,
              phase: 'callback',
              plan,
            });
            if (gaveUp) return;
            // UDMX-006: keep the storm loop self-driven. Retries are normally
            // powered by whatever the renderer sends next — but it may go quiet
            // at any moment (nothing changes on stage, or its output gate shuts
            // for the outage). Without re-parking the frame the retries would
            // stop, no further failure would drive the ladder to its verdict and
            // the badge would stay amber forever. Only inside a confirmed storm:
            // there the timer paces this loop at UDMX_STORM_RETRY_MS.
            if (!this._pending && this._outage && this._outage.retryIntervalMs) {
              this._pending = frame;
            }
          }
          // Flush the coalesced latest frame that arrived while we were in flight.
          if (this._pending) {
            const next = this._pending;
            this._pending = null;
            if (this.connected) this._transmit(next);
          }
        }
      );
    } catch (err) {
      // controlTransfer can also throw SYNCHRONOUSLY (libusb does that when the
      // handle is already dead). UDMX-010: only the device-gone branch may drop
      // the parked frame — every other error has to end up where the async
      // callback ends up, or the self-driven storm loop simply stops here and
      // the ladder never reaches its verdict.
      this._inFlight = false;
      const durationMs = this._transferDurationMs(startedNs);
      if (this._isDeviceGone(err)) {
        this._pending = null; // drop pending — device is gone
        this.notifyDiagnostic({
          type: 'transfer-result',
          success: false,
          transferSequence,
          durationMs,
          phase: 'synchronous-throw',
          error: serializeUsbError(err),
          consecutiveErrors: this._consecErrors + 1,
          thresholdReached: false,
          disconnectReason: 'usb-gone',
          busProbe: this._lastBusVerdict,
          channelStart: plan.start,
          channelCount: plan.length,
          fullFrame: plan.full,
          keepalive: !!plan.keepalive,
          // UDMX-012: отделяет пробник от настоящего засева в отчёте.
          seedProbe: !!plan.seedProbe,
          usbPresence: snapshotUdmxDevices(usb),
        });
        this._scheduleUsbPresenceRecheck(transferSequence, { force: true });
        this._cancelStormRetry(); // the ladder is over — nothing left to pace
        this.connected = false;
        console.log(`❌ uDMX: ${this._goneReason()} — связь разорвана`);
        this.notifyDisconnect('usb-gone');
        return;
      }
      const gaveUp = this._handleTransferFailure(err, {
        transferSequence,
        durationMs,
        phase: 'synchronous-throw',
        plan,
      });
      if (gaveUp) return;
      // Same rule as the callback path, and the same guard: re-park only inside
      // a confirmed storm, where the 250 ms timer paces the retry. Calling
      // _transmit() straight from this catch would recurse on a handle that
      // throws every single time.
      if (this._outage && this._outage.retryIntervalMs) {
        if (!this._pending) this._pending = frame;
        // 0 from _stormDelayMs() means "due now", so it must not fall through to
        // the full interval the way `||` would.
        const delayMs = this._stormDelayMs();
        this._scheduleStormRetry(delayMs > 0 ? delayMs : this._outage.retryIntervalMs);
      }
    }
  }

  // ═══ UDMX-004: staged recovery ═════════════════════════════════════════════

  // One failed transfer. Records the evidence, advances the ladder and returns
  // true when the link was given up (caller must stop touching the handle).
  _handleTransferFailure(err, { transferSequence, durationMs, phase, plan = null }) {
    const nowMs = Date.now();
    const kind = classifyUsbError(err);
    // A STALL is an ANSWER from the stick: it is physically present, so the
    // "device was pulled" shortcut must not fire — only the time-based ladder.
    const answered = kind === 'PIPE';
    this._consecErrors++;

    // UDMX-012: a seed that failed must not be the next thing we try. Re-arm the
    // probe so the retry costs one chunk, and so the report records whether the
    // short write passes while the long one does not — on a host that only
    // chokes on length that pair of lines IS the diagnosis.
    if (plan && plan.full) this._seedProbePending = true;

    if (!this._outage) {
      this._outage = {
        firstErrorAtMs: nowMs,
        errors: 0,
        firstErrorKind: kind,
        addressBefore: this._deviceAddress(),
        reopenAtMs: null,
        reopenOk: null,
        resetAtMs: null,
        resetOk: null,
        stage: 'errors',
        // UDMX-006/010: null while the renderer's own clock is enough; 250 ms in
        // a confirmed stall storm; UDMX_MIN_FRAME_INTERVAL_MS once the stick has
        // stopped answering and the unplug shortcut needs its fast clock back.
        retryIntervalMs: null,
        degradedAnnounced: false, // UDMX-007: amber badge waits for confirmation
      };
      this.notifyDiagnostic({
        type: 'udmx-recovery-started',
        firstErrorKind: kind,
        firstErrorAt: new Date(nowMs).toISOString(),
        error: serializeUsbError(err),
        usbPresence: snapshotUdmxDevices(usb),
      });
    }
    this._outage.errors++;
    const outageMs = nowMs - this._outage.firstErrorAtMs;

    // UDMX-007: now — not on the first error — the outage is real enough to show.
    if (!this._outage.degradedAnnounced
        && (this._consecErrors >= UDMX_REOPEN_AFTER_ERRORS || outageMs >= UDMX_DEGRADED_AFTER_MS)) {
      this._outage.degradedAnnounced = true;
      this.notifyDiagnostic({ type: 'recovery-state', state: 'degraded', reason: kind });
    }

    // UDMX-010: ...and it has to be GIVEN BACK the moment the stick stops
    // answering. The back-off gate in _stormDelayMs() paces EVERY frame, not
    // only the STALLs that armed it, so a storm that turned into "no answer"
    // (the August sequence: STALL storm, then the stick leaves the bus) kept the
    // 250 ms cadence and stretched the 20-error unplug shortcut from ~0,6 s to
    // ~3,7 s. The hand-back shows in the journal as a second `udmx-storm-backoff`
    // whose retryIntervalMs is the fast clock again.
    if (!answered && this._outage.retryIntervalMs === UDMX_STORM_RETRY_MS) {
      this._outage.retryIntervalMs = UDMX_MIN_FRAME_INTERVAL_MS;
      this._cancelStormRetry(); // re-armed below at the faster cadence
      this.notifyDiagnostic({
        type: 'udmx-storm-backoff',
        outageMs,
        consecutiveErrors: this._consecErrors,
        retryIntervalMs: UDMX_MIN_FRAME_INTERVAL_MS,
        kind,
      });
    }

    // UDMX-006: a confirmed stall storm — the cheap step has had its chance and
    // the stick keeps answering STALL. Drop to the gentle cadence. Only STALL
    // qualifies: no-answer errors must stay on the fast clock so an unplug is
    // still detected within the usual ~0.8 s.
    // The gate is armed once per outage: a mixed storm (PIPE interleaved with
    // TIMED_OUT) would otherwise flip it on every other error, and each flip is
    // a journal stage — 24 slots filled with `storm-backoff` while reopen / lost
    // / give-up fall off the end. Once handed back, it stays handed back.
    if (answered && this._consecErrors >= UDMX_REOPEN_AFTER_ERRORS
        && this._outage.retryIntervalMs == null) {
      this._outage.retryIntervalMs = UDMX_STORM_RETRY_MS;
      this.notifyDiagnostic({
        type: 'udmx-storm-backoff',
        outageMs,
        consecutiveErrors: this._consecErrors,
        retryIntervalMs: UDMX_STORM_RETRY_MS,
        kind,
      });
    }

    // Old fast path, now restricted to "no answer at all" errors: a sustained
    // run of TIMED_OUT with no success is how Windows libusb reports an unplug.
    const pulledOut = !answered && this._consecErrors >= UDMX_MAX_CONSEC_ERRORS;
    const outOfPatience = outageMs >= UDMX_LOST_AFTER_MS;
    const thresholdReached = pulledOut || outOfPatience;

    this.notifyDiagnostic({
      type: 'transfer-result',
      success: false,
      transferSequence,
      durationMs,
      phase,
      error: serializeUsbError(err),
      consecutiveErrors: this._consecErrors,
      thresholdReached,
      disconnectReason: thresholdReached ? 'usb-no-response' : null,
      outageMs,
      recoveryStage: this._outage.stage,
      channelStart: plan ? plan.start : null,
      channelCount: plan ? plan.length : null,
      fullFrame: plan ? plan.full : null,
      keepalive: plan ? !!plan.keepalive : null,
      // UDMX-012: отделяет пробник от настоящего засева в отчёте.
      seedProbe: plan ? !!plan.seedProbe : null,
      usbPresence: snapshotUdmxDevices(usb),
    });
    // Force the after-snapshot at the two moments it actually proves something:
    // the first error of a run and the give-up. In between it is throttled — 635
    // rechecks filled half the recent-event ring in the August report.
    this._scheduleUsbPresenceRecheck(transferSequence, {
      force: this._outage.errors === 1 || thresholdReached,
    });

    // UDMX-008: the failed range is unknown on the device now. Mark exactly that
    // range for repair instead of forcing a full 512 — on a host where long
    // transfers are the thing that fails, the old rule answered every failure
    // with the most failure-prone payload we have. Without a plan (a synchronous
    // throw before one was built) the size is unknown, so fall back to the frame.
    if (plan) {
      const failedEnd = plan.start + plan.length - 1;
      this._dirtyStart = this._dirtyStart < 0 ? plan.start : Math.min(this._dirtyStart, plan.start);
      this._dirtyEnd = Math.max(this._dirtyEnd, failedEnd);
    } else {
      this._needFullFrame = true;
    }

    if (thresholdReached) {
      this.notifyDiagnostic({
        type: 'udmx-recovery-failed',
        outageMs,
        errors: this._outage.errors,
        reason: pulledOut ? 'no-answer' : 'timeout',
        reopenOk: this._outage.reopenOk,
        resetOk: this._outage.resetOk,
        stage: this._outage.stage,
      });
      console.log(`❌ uDMX не отвечает ${Math.round(outageMs / 1000)} с (${this._outage.errors} ошибок) — передаю переподключению`);
      this._cancelStormRetry();
      this._pending = null;
      this._outage = null;
      this.connected = false;
      this.notifyDisconnect('usb-no-response');
      return true;
    }

    // Cheap step always first: with the normal 40 ms clock the error count trips
    // long before the reset timer, but a slow frame rate must not let the ladder
    // skip straight to the port reset.
    if (this._outage.reopenAtMs == null
        && (this._consecErrors >= UDMX_REOPEN_AFTER_ERRORS || outageMs >= UDMX_RESET_AFTER_MS)) {
      this._recoverReopen(outageMs);
    } else if (portResetEnabled() && outageMs >= UDMX_RESET_AFTER_MS && this._outage.resetAtMs == null
        && nowMs - this._lastPortResetAtMs() >= UDMX_RESET_COOLDOWN_MS) {
      this._recoverReset(outageMs);
    } else if (!answered && !String(err.message || err).includes('TIMED_OUT')) {
      console.log('⚠️ uDMX send error:', err.message);
    }
    return false;
  }

  // Ladder step 2 — heal the handle: close and reopen it (cheapest fix for a
  // pipe left in an error state, and free of any re-enumeration risk).
  // Deferred off the failing transfer's own callback: libusb must not be asked to
  // close a handle from inside a completion it is still unwinding.
  _recoverReopen(outageMs) {
    const startedMs = Date.now();
    this._outage.reopenAtMs = startedMs;
    this._outage.stage = 'reopen';
    this._recovering = true;
    setImmediate(() => {
      if (!this._recovering) return; // close() won the race
      if (!mayRecoverConnection()) {
        this._abortBlockedRecovery('reopen', outageMs);
        return;
      }
      let ok = false;
      let error = null;
      // UDMX-011: WHY the reopen failed. Until now a failure that found no device
      // reported `ok:false` and nothing else — the report literally said "no
      // details" at the one ladder step the field case dies on (12 failed opens
      // over 36 s). `freshHandleDiffered` is the same evidence open() already
      // carries (UDMX-009): did re-enumeration hand us a DIFFERENT entry, or the
      // very same one — in which case retrying it is doomed by construction.
      let reason = null;
      let freshHandleDiffered = null;
      const previousDevice = this.device;
      try {
        try { this.device.close(); } catch { /* already dead — reopen anyway */ }
        const fresh = this._findFreshDevice();
        if (fresh) {
          freshHandleDiffered = fresh !== previousDevice;
          this.device = fresh;
          this.device.open();
          ok = true;
        } else {
          reason = 'not-enumerated'; // стик пропал с шины — открывать нечего
        }
      } catch (e) {
        reason = 'open-failed'; // запись есть, но драйвер её не отдаёт
        error = serializeUsbError(e);
      }
      this._recovering = false;
      // UDMX-010 considered keeping the mirror here (a reopen is close+open of a
      // stick that never left the bus, so re-seeding answers the outage with the
      // longest transfer we own — the thing UDMX-008 took out of the error path).
      // It was NOT done, and the reasoning is worth keeping: (1) node-usb's
      // open() may re-issue SET_CONFIGURATION, and whether V-USB firmware keeps
      // its DMX buffer across that is unverified; (2) a wrong guess is not cheap
      // — a delta that covers all changes mirrors the WHOLE frame, so a stale
      // mirror is never repaired by deltas, only by the refresh cycle, and on a
      // busy stage the refresh yields to changes and a full round takes ~9 s, not
      // 1 s (UDMX_KEEPALIVE_DEFER_MAX_MS); (3) untouched show channels would hold
      // foreign values for that whole window, and without the watermark the
      // firmware clocks DMX only up to the last channel we sent. The seed is one
      // long transfer per outage against that risk — it stays.
      this._resetFrameState();
      if (this._outage) this._outage.reopenOk = ok;
      this.notifyDiagnostic({
        type: 'udmx-recovery-step',
        step: 'reopen',
        ok,
        outageMs,
        consecutiveErrors: this._consecErrors,
        durationMs: Date.now() - startedMs,
        address: this._deviceAddress(),
        addressChanged: this._deviceAddress() !== (this._outage && this._outage.addressBefore),
        // null при успехе; 'not-enumerated' — палки нет в перечислении;
        // 'open-failed' — запись есть, но открыть её не дали.
        reason,
        // null — до повторного перечисления дело не дошло; false — отдало ТУ ЖЕ
        // запись; true — другую (см. UDMX-009).
        freshHandleDiffered,
        usbPresence: snapshotUdmxDevices(usb),
        error,
      });
      console.log(`🔁 uDMX: переоткрытие handle после ${this._consecErrors} ошибок — `
        + `${ok ? 'ок' : `не удалось (${reason === 'not-enumerated' ? 'палки нет в перечислении' : 'открыть не дали'})`}`);
      this._flushPending();
    });
  }

  // Ladder step 3 — port reset. Heavier than a reopen (the stick may re-enumerate
  // and hand libusb a NEW handle), so it is rate-limited and fired only once per
  // outage, after the cheap step has already failed for UDMX_RESET_AFTER_MS.
  _recoverReset(outageMs) {
    if (!this.device || typeof this.device.reset !== 'function') return;
    const startedMs = Date.now();
    this._outage.resetAtMs = startedMs;
    this._outage.stage = 'reset';
    lastPortResetAtMsByLocation.set(this._resetLimiterKey(), startedMs);
    this._recovering = true;
    console.log(`🔌 uDMX: сброс порта после ${Math.round(outageMs / 1000)} с без ответа`);

    let watchdog = null;
    const finish = (ok, error) => {
      if (watchdog) { clearTimeout(watchdog); watchdog = null; }
      if (!this._recovering) return; // close() happened while the reset was in flight
      if (!mayRecoverConnection()) {
        this._abortBlockedRecovery('reset', outageMs);
        return;
      }
      this._recovering = false;
      // After a reset the old handle may be stale — rebind to the current device.
      let rebound = false;
      try {
        const fresh = this._findFreshDevice();
        if (fresh && fresh !== this.device) {
          try { this.device.close(); } catch { /* stale handle */ }
          this.device = fresh;
          this.device.open();
          rebound = true;
        }
      } catch (e) {
        error = error || serializeUsbError(e);
        ok = false;
      }
      this._resetFrameState();
      if (this._outage) this._outage.resetOk = ok;
      this.notifyDiagnostic({
        type: 'udmx-recovery-step',
        step: 'reset',
        ok,
        rebound,
        outageMs,
        consecutiveErrors: this._consecErrors,
        durationMs: Date.now() - startedMs,
        address: this._deviceAddress(),
        addressChanged: this._deviceAddress() !== (this._outage && this._outage.addressBefore),
        error,
        usbPresence: snapshotUdmxDevices(usb),
      });
      this._flushPending();
    };

    // A reset that never calls back would park every frame forever (no more
    // failures → the ladder could never reach the give-up step). Bound the wait.
    watchdog = setTimeout(() => finish(false, {
      kind: 'TIMED_OUT',
      name: 'Error',
      message: `device.reset() не ответил за ${UDMX_RESET_WATCHDOG_MS} мс`,
      code: null,
      errno: null,
    }), UDMX_RESET_WATCHDOG_MS);
    if (typeof watchdog.unref === 'function') watchdog.unref();

    // Off the failing transfer's own callback (same reason as _recoverReopen).
    setImmediate(() => {
      if (!this._recovering) return;
      if (!mayRecoverConnection()) {
        if (watchdog) { clearTimeout(watchdog); watchdog = null; }
        this._abortBlockedRecovery('reset', outageMs);
        return;
      }
      try {
        this.device.reset(err => (err ? finish(false, serializeUsbError(err)) : finish(true, null)));
      } catch (e) {
        finish(false, serializeUsbError(e));
      }
    });
  }

  _abortBlockedRecovery(step, outageMs) {
    if (!this._recovering) return false;
    this._recovering = false;
    this._cancelStormRetry();
    this._pending = null;
    let error = null;
    try { if (this.device) this.device.close(); } catch (closeError) { error = serializeUsbError(closeError); }
    this.connected = false;
    this._resetFrameState();
    if (this._outage) {
      if (step === 'reopen') this._outage.reopenOk = false;
      if (step === 'reset') this._outage.resetOk = false;
    }
    this.notifyDiagnostic({
      type: 'udmx-recovery-step',
      step,
      ok: false,
      outageMs,
      consecutiveErrors: this._consecErrors,
      reason: 'not-admitted',
      error,
      usbPresence: snapshotUdmxDevices(usb),
    });
    this.notifyDisconnect('reconnect-not-admitted');
    return true;
  }

  // Push the frame parked during a recovery step, instead of idling until the
  // DmxManager clock produces the next one.
  _flushPending() {
    if (!this.connected || !this._pending || this._inFlight || this._recovering) return;
    const next = this._pending;
    this._pending = null;
    this._transmit(next);
  }

  // A frame got through — close out the outage with the numbers support needs to
  // tell "the reset actually shortened it" from "it healed on its own anyway".
  _finishOutage(durationMs) {
    this._cancelStormRetry(); // healthy again — back to the normal 40 ms clock
    if (!this._outage) return;
    const outage = this._outage;
    this._outage = null;
    const outageMs = Date.now() - outage.firstErrorAtMs;
    this.notifyDiagnostic({
      type: 'udmx-recovered',
      outageMs,
      errors: outage.errors,
      firstErrorAt: new Date(outage.firstErrorAtMs).toISOString(),
      firstErrorKind: outage.firstErrorKind,
      stage: outage.stage,
      reopenOk: outage.reopenOk,
      resetOk: outage.resetOk,
      msSinceReset: outage.resetAtMs == null ? null : Date.now() - outage.resetAtMs,
      addressBefore: outage.addressBefore,
      addressAfter: this._deviceAddress(),
      addressChanged: this._deviceAddress() !== outage.addressBefore,
      firstSuccessDurationMs: durationMs,
    });
    // UDMX-007: symmetric with the amber announcement — an outage the user never
    // saw must not end with a «связь восстановлена» the user cannot place.
    if (outage.degradedAnnounced) {
      this.notifyDiagnostic({ type: 'recovery-state', state: 'recovered', outageMs });
    }
    console.log(`✅ uDMX ответил снова через ${Math.round(outageMs)} мс (${outage.errors} ошибок, стадия «${outage.stage}»)`);
  }

  _deviceAddress() {
    return (this.device && this.device.deviceAddress != null) ? this.device.deviceAddress : null;
  }
}

module.exports = UdmxTransport;
