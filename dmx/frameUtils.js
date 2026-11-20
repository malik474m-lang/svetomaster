// frameUtils.js
//
// Pure helpers for the DMX frame pipeline — NO native deps (serialport/usb),
// so they are shared by DmxManager / transports AND directly importable in
// vitest (which runs in jsdom and cannot load native modules).

// True when a frame is a full blackout (every channel is 0). Used by the
// DmxManager throttle to guarantee a blackout reaches the wire immediately
// (DMXMGR-001 — lights must never stay on after a blackout command).
// A null / empty frame is NOT a blackout (it is "no frame at all").
function isBlackoutFrame(data) {
  if (!data || data.length === 0) return false;
  for (let i = 0; i < data.length; i++) {
    if (data[i]) return false;
  }
  return true;
}

// Guard predicate for the self-clocked Open DMX frame loop. Every async
// callback (port.set / port.write) and every intra-frame timer must re-check
// this before touching the port, because close() can run mid-flight
// (OPEN-DMX-002 / BUG-004 — no write() into a closed/null port, no zombie loop).
function canRunFrame({ isLoopRunning, stopping, portOpen, connected }) {
  return !!(isLoopRunning && !stopping && portOpen && connected);
}

module.exports = { isBlackoutFrame, canRunFrame };
