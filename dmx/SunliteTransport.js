const usb = require('usb');
const BaseDmxTransport = require('./BaseDmxTransport');
const { getSharedBridge } = require('./siudi/SiudiBridge');

// USB vendor IDs of the Nicolaudie / LightingSoft (Sunlite / SIUDI / Daslight)
// hardware family. Used ONLY as a cheap presence gate: we spin up the 32-bit SDK
// sidecar solely when such a device is actually plugged in, so the ~99% of users
// with no Nicolaudie hardware never pay for a sidecar process. Extend this list if
// a user's genuine Nicolaudie interface is not detected.
//   0x0962 — Digital Enterprise Ltd (Nicolaudie): SUITE2/3, SLESA-U9, …
//   0x6244 — LightingSoft AG: SIUDI (e.g. SIUDI7B, VID_6244/PID_0531)
const NICOLAUDIE_VIDS = [0x0962, 0x6244];

function hasNicolaudieDevice() {
  try {
    return usb.getDeviceList().some(d =>
      d && d.deviceDescriptor && NICOLAUDIE_VIDS.includes(d.deviceDescriptor.idVendor));
  } catch (e) {
    return false;
  }
}

// Bridge-backed transport for Nicolaudie / Sunlite (SIUDI) interfaces. Actual DMX
// I/O runs in a 32-bit sidecar (dmx/siudi) that loads LsHardDevKit.dll — a 64-bit
// Electron process cannot load that DLL directly. Validated end-to-end against a
// real SIUDI7B (see ДОК/siudi-probe, PLAN_SIUDI_SUNLITE.md).
class SunliteTransport extends BaseDmxTransport {
  constructor(deviceInfo) {
    super(deviceInfo);
    this.bridge = getSharedBridge();
    this.deviceIndex = (deviceInfo && deviceInfo.deviceIndex != null) ? deviceInfo.deviceIndex : 0;
    this.universeCount = (deviceInfo && deviceInfo.universeCount) ? deviceInfo.universeCount : 1;
    // A physical USB dongle carrying several DMX universes (SIUDI7B = 3).
    this.supportsMultiUniverse = true;
    // DMX-вывод идёт через 32-битный сайдкар с LsHardDevKit.dll, и SDK не
    // подтверждает отдельный кадр. Значит доказать мы можем ровно одно: строка
    // кадра ушла в сайдкар. Отчёт обязан называть это своим именем.
    this.transferConfirmation = 'sidecar';
  }

  // Names shown to the user and written to the log, kept in ONE place so the pair
  // cannot drift apart. The list gets the FAMILY name: the board model ('SIUDI8A')
  // tells a user nothing, while the second line of the device list already shows
  // `siudi:<serial>`, so two boxes stay distinguishable. The log and the support
  // report get vendor + model + serial — that is what a support case is identified
  // by (client case 2026-09-10: a Daslight box was shown as 'Sunlite SIUDI8A (beta)').
  static deviceNames(type, serial) {
    return {
      name: 'SIUDI (Sunlite/Daslight)',
      fullName: `Nicolaudie ${type} (Sunlite/Daslight), s/n ${serial}`,
    };
  }

  // Async (like the serial transports). Returns [] fast when no Nicolaudie device
  // is present, and [] while the sidecar is still starting — the next scan (≈3s)
  // returns the real list. NEVER throws to DmxManager.
  static async scan() {
    if (!hasNicolaudieDevice()) return [];
    const bridge = getSharedBridge();
    if (!bridge.isAvailable()) return []; // sidecar exe not shipped -> silently off
    let devices;
    try {
      devices = await bridge.scan();
    } catch (e) {
      return [];
    }
    return devices.map((d) => {
      const serial = (d.serial != null) ? String(d.serial) : String(d.index);
      const type = (d.type || d.name || 'SIUDI').trim();
      const names = SunliteTransport.deviceNames(type, serial);
      return {
        id: `sunlite-${serial}`,
        type: 'sunlite',
        // Short family name in the list, full one in the log — see deviceNames().
        name: names.name,
        fullName: names.fullName,
        // serialNumber = device "passport" → reconnect to the SAME unit (reconnectUtils).
        serialNumber: serial,
        path: `siudi:${serial}`,
        supported: true,
        deviceIndex: d.index,
        universeCount: d.universes || 1,
      };
    });
  }

  // Full device name for logs and diagnostics. `fullName` is filled by scan(); a
  // transport restored from a saved device entry (older project, hand-built info)
  // may lack it, and a support case must never lose the model over that.
  fullName() {
    const info = this.deviceInfo || {};
    if (info.fullName) return String(info.fullName);
    const serial = info.serialNumber ? `, s/n ${info.serialNumber}` : '';
    return `Nicolaudie ${info.name || 'SIUDI'}${serial}`;
  }

  async open() {
    try {
      const r = await this.bridge.open(this.deviceIndex);
      if (!r || !r.ok) {
        this.lastError = (r && r.error) ? `Sunlite: ${r.error}` : 'Не удалось открыть Sunlite-устройство';
        this.connected = false;
        // The sidecar packs the DHDK error code into that string — the only place
        // a SIUDI case can be diagnosed from a client's app.log, and what
        // main/clientHealth.js reads to show a plain message (36 = SIUDI firmware
        // older than the SDK supports).
        this.notifyDiagnostic({
          type: 'transport-open-failed',
          error: { kind: 'SIUDI_OPEN_FAILED', name: 'Error', message: this.lastError, code: null, errno: null },
        });
        console.log('❌ Sunlite ошибка:', this.lastError);
        return false;
      }
      if (r.universes) this.universeCount = r.universes;
      // WHICH backend opened the box goes to app.log with the full device name.
      // Today it is always DHDK (the DasHard2006 fallback was removed
      // 2026-09-30); the field stays so an older sidecar in a support log still
      // reads unambiguously.
      const backend = (r.backend) ? String(r.backend) : 'unknown';
      this.notifyDiagnostic({
        type: 'sunlite-open',
        backend,
        universes: this.universeCount,
        // The device list shows a short name on purpose; the log and the support
        // report get the full one (vendor + model + serial), so a case is
        // identifiable without asking the client which box they own.
        fullName: this.fullName(),
        detail: r.diagnostic ? String(r.diagnostic) : null,
      });
      console.log(`💡 ${this.fullName()} подключён: backend=${backend}, вселенных=${this.universeCount}` +
        (r.diagnostic ? ` | ${r.diagnostic}` : ''));
      // Unplug / sidecar-death detection routes to the one-shot disconnect hook.
      this.bridge.onLost = () => this.notifyDisconnect('device gone');
      this.bridge.onExit = () => { if (this.connected) this.notifyDisconnect('sidecar exited'); };
      this.connected = true;
      this.lastError = null;
      return true;
    } catch (e) {
      this.lastError = 'Sunlite: ' + e.message;
      this.connected = false;
      return false;
    }
  }

  async close() {
    this.connected = false;
    // Detach our listeners so a later scan / other transport isn't hit by them.
    this.bridge.onLost = null;
    this.bridge.onExit = null;
    try {
      await this.bridge.close();
    } catch (e) {
      /* dead sidecar — nothing to release */
    }
    // The shared sidecar stays alive for subsequent scans; it is disposed on app quit.
  }

  // DmxManager passes (dmxData, universe) with a 1-based logical universe.
  send(dmxData, universe = 1) {
    if (!this.connected) return;
    const idx = (universe || 1) - 1; // logical 1-based -> SDK 0-based
    if (idx < 0 || idx >= this.universeCount) return;
    const delivered = this.bridge.send(idx, dmxData);
    // Счётчик кадров для отчёта (2026-09-11). Мёртвый сайдкар — это не «ошибка
    // прибора», а «поток прервался»: канал закрыт, и ни один кадр до платы не
    // доедет, пока не пересоберётся мост. Вид ошибки — тот же, что у пропавшего
    // USB-устройства, потому что для зала последствие одно.
    this.noteTransfer({
      success: delivered,
      universe,
      error: delivered ? null : {
        kind: 'NO_DEVICE',
        name: 'SiudiBridge',
        message: 'кадр не ушёл: канал к 32-битному посреднику SDK закрыт',
        code: null,
        errno: null,
      },
    });
  }

  isConnected() {
    return this.connected;
  }
}

module.exports = SunliteTransport;
