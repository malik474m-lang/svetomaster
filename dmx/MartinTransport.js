const usb = require('usb');
const { createHash, randomUUID } = require('crypto');
const BaseDmxTransport = require('./BaseDmxTransport');
const { getSharedBridge } = require('./martin/MartinBridge');

function hasMartinDevice(usbApi = usb) {
  try {
    return usbApi.getDeviceList().some(device => {
      const descriptor = device && device.deviceDescriptor;
      return descriptor && descriptor.idVendor === 0x11be && [0xf028, 0xf0a8].includes(descriptor.idProduct);
    });
  } catch { return false; }
}

function transferError(result) {
  const code = result.code || 'MARTIN_ERROR';
  return {
    kind: /TIMEOUT|TIMED_OUT/.test(code) ? 'TIMED_OUT' : (result.fatal ? 'NO_DEVICE' : 'IO'),
    name: 'MartinBridge', message: result.error || 'Ошибка передачи Martin', code, errno: null,
  };
}

class MartinTransport extends BaseDmxTransport {
  constructor(deviceInfo, opts = {}) {
    super(deviceInfo);
    this.bridge = opts.bridge || getSharedBridge();
    this.universeCount = 2;
    this.supportsMultiUniverse = true;
    this.requiresDmxTransferConfirmation = true;
    // SDK5 accepts a frame into its own clocked buffer; it does not confirm light.
    this.transferConfirmation = 'buffer';
    this._sessionId = null;
    this._generation = 0;
    this._unsubscribe = null;
    this._opening = null;
  }

  static deviceInfo(device) {
    const instanceId = typeof device.instanceId === 'string' ? device.instanceId.trim().toUpperCase() : '';
    const productId = String(device.productId || '').replace(/^0x/i, '').toUpperCase();
    const identity = /^USB\\VID_11BE&PID_(F028|F0A8)(?:&[^\\]*)?\\.+$/.exec(instanceId);
    if (!identity || identity[1] !== productId) return null;
    const name = productId === 'F0A8' ? 'Martin Universal USB-DMX 2' : 'Martin Universal USB-DMX';
    return {
      id: 'martin-' + createHash('sha256').update(instanceId).digest('hex').slice(0, 24),
      type: 'martin', name, fullName: name,
      path: instanceId, pnpInstanceId: instanceId,
      vendorId: '11BE', productId, supported: true, universeCount: 2,
      problemCode: device.problemCode ?? null, service: device.service || null,
    };
  }

  static async scan(opts = {}) {
    if (!hasMartinDevice(opts.usb || usb)) return [];
    const bridge = opts.bridge || getSharedBridge();
    if (!bridge.isAvailable()) return [];
    const devices = await bridge.scan();
    return devices.map(device => MartinTransport.deviceInfo(device)).filter(Boolean);
  }

  _sessionEvent(session, generation, event) {
    if (this._generation !== generation || this._sessionId !== session) return;
    if (event.event === 'native-call') {
      this.notifyDiagnostic({ type: 'martin-native-call', bridgeSessionId: session, operation: event.operation || event.command || null, detail: event });
    } else if (event.event === 'lost') {
      const wasConnected = this.connected;
      this.connected = false;
      this.lastError = event.error || 'Связь с Martin прервана';
      this.notifyDiagnostic({ type: 'martin-lost', bridgeSessionId: session, error: transferError({ ...event, fatal: true }), detail: event.lastNativeCall || null });
      if (wasConnected) this.notifyDisconnect(this.lastError);
    }
  }

  open() {
    if (this.connected) return Promise.resolve(true);
    if (this._opening && this._opening.generation === this._generation) return this._opening.promise;
    const generation = ++this._generation;
    const session = randomUUID();
    this._sessionId = session;
    this._disconnectNotified = false;
    this._unsubscribe?.();
    this._unsubscribe = this.bridge.subscribe(session, event => this._sessionEvent(session, generation, event));
    const promise = (async () => {
      try {
        const result = await this.bridge.open(this.deviceInfo.pnpInstanceId || this.deviceInfo.path, session);
        if (this._generation !== generation || this._sessionId !== session) { await this.bridge.close(session); return false; }
        if (!result || !result.ok || result.session !== session || result.universes !== 2
            || (this.bridge.isSessionActive && !this.bridge.isSessionActive(session))) {
          this.lastError = 'Martin: ' + (result?.error || 'Не удалось открыть две DMX-линии');
          this.notifyDiagnostic({
            type: 'transport-open-failed', bridgeSessionId: session,
            error: { kind: 'MARTIN_OPEN_FAILED', name: 'MartinBridge', message: this.lastError, code: result?.code || null, errno: null },
            backend: result?.backend || null, native: result?.native || null,
          });
          await this.bridge.close(session);
          if (this._generation === generation && this._sessionId === session) {
            this._unsubscribe?.();
            this._unsubscribe = null;
            this._sessionId = null;
            this.connected = false;
          }
          console.log('❌ Martin ошибка:', this.lastError);
          return false;
        }
        this.universeCount = result.universes;
        this.deviceInfo.universeCount = result.universes;
        this.connected = true;
        this.lastError = null;
        this.notifyDiagnostic({
          type: 'martin-open', bridgeSessionId: session, universes: this.universeCount,
          backend: result.backend, native: result.native || null,
          firmware: result.firmware ?? null, nativeName: result.nativeName ?? '',
          fullName: this.deviceInfo.fullName || this.deviceInfo.name,
        });
        console.log(`💡 ${this.deviceInfo.name} подключён: backend=${result.backend}, вселенных=${this.universeCount}`);
        return true;
      } catch (error) {
        if (this._generation !== generation || this._sessionId !== session) return false;
        this.lastError = 'Martin: ' + error.message;
        this.connected = false;
        this.notifyDiagnostic({ type: 'transport-open-failed', bridgeSessionId: session, error: transferError({ code: 'OPEN_ERROR', error: this.lastError }) });
        try { await this.bridge.close(session); } catch { /* own helper may already be dead */ }
        if (this._generation === generation && this._sessionId === session) {
          this._unsubscribe?.();
          this._unsubscribe = null;
          this._sessionId = null;
        }
        return false;
      } finally {
        if (this._opening?.generation === generation) this._opening = null;
      }
    })();
    this._opening = { generation, promise };
    return promise;
  }

  async close() {
    ++this._generation;
    this.connected = false;
    const session = this._sessionId;
    this._sessionId = null;
    this._unsubscribe?.();
    this._unsubscribe = null;
    if (session) {
      try { await this.bridge.close(session); } catch { /* the addressed helper may already be dead */ }
    }
  }

  send(dmxData, universe = 1) {
    if (!this.connected || !this._sessionId || !Number.isInteger(universe) || universe < 1 || universe > 2) return false;
    if (!dmxData || !Number.isInteger(dmxData.length) || dmxData.length > 512) return false;
    const frame = Buffer.alloc(512);
    for (let index = 0; index < dmxData.length; index++) {
      if (!Number.isInteger(dmxData[index]) || dmxData[index] < 0 || dmxData[index] > 255) return false;
      frame[index] = dmxData[index];
    }
    const session = this._sessionId;
    const generation = this._generation;
    return this.bridge.send(session, universe, frame, outcome => {
      if (this._generation !== generation || this._sessionId !== session || (outcome.session && outcome.session !== session)) return;
      if (outcome.cancelled && outcome.expected) return;
      const success = outcome.ok === true && outcome.confirmation === 'sdk-buffer';
      const error = success ? null : transferError(outcome);
      this.noteTransfer({ success, error, durationMs: outcome.durationMs ?? null, universe,
        phase: outcome.phase || 'callback', thresholdReached: !success && !!outcome.fatal });
      if (!success && outcome.fatal) {
        this.connected = false;
        this.lastError = error.message;
        this.notifyDisconnect(error.message);
      }
    });
  }
}

module.exports = MartinTransport;
module.exports.hasMartinDevice = hasMartinDevice;
