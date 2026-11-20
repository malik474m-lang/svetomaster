// reconnectUtils.js
//
// Pure helper for DMX auto-reconnect (DMX-004) — NO native deps, so it is
// shared by DmxManager AND directly importable in vitest.

// Deterministic ordering for scan results (DMXMGR-002). SerialPort.list() returns
// ports in an OS-dependent order that is NOT stable between scans, so two
// physically identical FTDI sticks would otherwise swap places run-to-run, making
// the UI list and the reconnect fallback "jump" between the two ports. We impose a
// stable total order on a composite key:
//   serialNumber → path → id (natural sort so COM3 sorts before COM10).
// serialNumber leads because it is the device "passport": it survives a cable
// replug that reassigns the COM port, whereas path does not.
function compareDevicesStable(a, b) {
  const cmp = (x, y) =>
    String(x || '').localeCompare(String(y || ''), undefined, { numeric: true });
  return (
    cmp(a && a.serialNumber, b && b.serialNumber) ||
    cmp(a && a.path, b && b.path) ||
    cmp(a && a.id, b && b.id)
  );
}

// After a device was lost and we re-scanned, pick the device to reconnect to.
// The physical device may come back under a different id (COM port can change,
// usb index can shift), so we match by stable traits rather than the old id, in
// priority order (DMXMGR-002):
//   • USB model (vid/pid) — a HARD filter, not a preference, applied before
//     everything else and only when the lost device published one (uDMX-class
//     sticks do; serial transports publish a string vendorId instead and are
//     unaffected). One `type` can mean two different products, so without this
//     the last-resort rule below could hand back a neighbour of another model.
//   • serialNumber — the device "passport"; survives a COM-port reassignment, so
//     with two identical FTDI sticks we reconnect to the SAME physical unit.
//   • path (COM port) — exact same port came back.
//   • vendorId — same chip family, deterministically picked (lowest in stable order).
//   • first of type, in stable order — last-resort fallback.
// Non-serial (uDMX): first device of the same type AND model — with no model
// match on the bus we wait rather than bind to a different product.
// All fallbacks run over a stably-sorted list so the choice never depends on the
// volatile SerialPort.list() order. Returns the matching scan-result (CURRENT id)
// or null.
function findReconnectTarget(scanResults, lostInfo) {
  if (!lostInfo || !Array.isArray(scanResults)) return null;
  let candidates = scanResults.filter(d => d.type === lostInfo.type);
  // Martin names are editable and empty on real hardware. Bind only the exact
  // Windows USB instance; never adopt another box of the same family as fallback.
  if (lostInfo.type === 'martin') {
    const instanceOf = (device) => String(device.pnpInstanceId || device.path || '').trim().toUpperCase();
    const instance = instanceOf(lostInfo);
    if (!/^USB\\VID_11BE&PID_(F028|F0A8)\\/.test(instance) || candidates.length !== 1) return null;
    return instanceOf(candidates[0]) === instance ? candidates[0] : null;
  }
  // UDMX-010: `type` alone stopped being enough once one type could mean two
  // different physical products. Every uDMX-class stick reports type 'udmx'
  // (original and clones alike), and none of them exposes a serialNumber, so a
  // lost original whose port stayed empty fell all the way through to "first of
  // type" and could land on a CLONE in another port — driving the wrong unit,
  // the exact failure DMXMGR-002 exists to prevent. When the lost device carries
  // a USB model id, only that model may be a candidate; if it is not on the bus
  // we wait for it instead of grabbing a neighbour. Serial transports publish
  // `vendorId` (a string) and no `vid`/`pid`, so nothing changes for them.
  if (lostInfo.vid != null && lostInfo.pid != null) {
    candidates = candidates.filter(d => d.vid === lostInfo.vid && d.pid === lostInfo.pid);
  }
  const sameType = candidates.sort(compareDevicesStable);
  if (sameType.length === 0) return null;

  if (lostInfo.serialNumber) {
    const bySerial = sameType.find(d => (d.serialNumber || '') === lostInfo.serialNumber);
    if (bySerial) return bySerial;
  }

  if (lostInfo.path) {
    const byPath = sameType.find(d => d.path === lostInfo.path);
    if (byPath) return byPath;
    if (lostInfo.vendorId) {
      const byVid = sameType.find(d => (d.vendorId || '') === lostInfo.vendorId);
      if (byVid) return byVid;
    }
    return sameType[0];
  }

  return sameType[0];
}

// Close a transport with a hard timeout (DMXMGR-003). A hung device can leave a
// callback-based close() (serialport port.close(cb), dgram socket.close(cb))
// pending forever, so `await transport.close()` inside DmxManager._teardownActive
// would block connect()/disconnect()/reconnect indefinitely. We race close()
// against a timer: if close() wins, the timer is cleared; if the timer wins, we
// stop waiting and return { timedOut: true }, ORPHANING the old transport (its
// pending close() resolves harmlessly later — onDisconnect is detached and the
// reference is dropped, so it never re-clocks the wire). close() errors/sync
// throws are swallowed (matches the prior try/catch on a dead device) and the
// background promise keeps a .catch so a late rejection is never unhandled.
function closeWithTimeout(transport, timeoutMs) {
  if (!transport || typeof transport.close !== 'function') {
    return Promise.resolve({ timedOut: false });
  }
  let timer = null;
  const closePromise = Promise.resolve()
    .then(() => transport.close())
    .then(() => ({ timedOut: false }))
    .catch(() => ({ timedOut: false }));
  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });
  return Promise.race([closePromise, timeoutPromise]).then((result) => {
    if (timer) clearTimeout(timer);
    return result;
  });
}

// Whether a transport-reported error means the device physically disappeared
// (vs a transient timeout we should ignore). uDMX/libusb surfaces NO_DEVICE on
// unplug; serialport surfaces disconnect via the 'close'/'error' events.
function isDeviceGoneError(message) {
  if (!message) return false;
  return /NO_DEVICE|DISCONNECT|not found|ENXIO|ENODEV/i.test(String(message));
}

// UDMX-011: a WEAKER signal than the one above, and deliberately kept apart.
// A uDMX pulled out of the port reports `LIBUSB_ERROR_NOT_FOUND` (measured on
// the bench 2026-09-05: 3 replugs out of 3), which `isDeviceGoneError` never
// matched — its `not found` needs a space. Reporting the link dead on the first
// such error alone would be the opposite mistake: `NOT_FOUND` also comes back
// from a live device whose handle went bad, and today the ladder rides that out.
// So this predicate only says "the message is consistent with the stick being
// gone" — the caller must confirm with the bus itself before tearing the link
// down (see UdmxTransport._isDeviceGone).
function isLibusbDeviceLostError(message) {
  if (!message) return false;
  return /LIBUSB_ERROR_NOT_FOUND/i.test(String(message));
}

module.exports = {
  findReconnectTarget,
  isDeviceGoneError,
  isLibusbDeviceLostError,
  closeWithTimeout,
  compareDevicesStable,
};
