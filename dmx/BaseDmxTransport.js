const { serializeUsbError } = require('./DmxDiagnostics');

// A frame error in the SAME kind vocabulary uDMX already uses (NO_DEVICE /
// TIMED_OUT / PIPE / IO / BUSY / OTHER) — the report groups them in one
// `errorsByKind` table, and a second vocabulary would make that table
// meaningless. An object that already carries `kind` passes through untouched,
// so synthetic causes (a write watchdog, a closed sidecar pipe) land in the same
// table as real driver errors.
function normalizeTransferError(error) {
  if (!error) return null;
  if (typeof error === 'object' && error.kind) return error;
  return serializeUsbError(error);
}

class BaseDmxTransport {
  constructor(deviceInfo) {
    this.deviceInfo = deviceInfo;
    this.connected = false;
    this.lastError = null;
    // Self-clocked transports run their own steady wire loop (own timer) and
    // treat send() as a cheap memory update rather than an immediate wire write.
    // DmxManager bypasses its throttle for them (single frame clock — BUG-006).
    // Only Open DMX sets this true; all other transports stay wire-on-send.
    this.selfClocked = false;
    // UDMX-002: minimum wire interval the DmxManager throttle must honour for this
    // transport (null → the manager's shared default). A transport whose physical
    // frame time is longer than the default clock (uDMX: ~35 ms for 512 bytes on
    // low-speed USB) sets its own, otherwise the throttle asks for frames faster
    // than the hardware can ever deliver and the bus stays permanently saturated.
    this.minFrameIntervalMs = null;
    // Some transports can distinguish an opened handle from a frame that was
    // actually accepted by the device. DmxManager uses that capability after a
    // drop so the UI never treats open() alone as a confirmed recovery.
    this.requiresDmxTransferConfirmation = false;
    // Сетевые транспорты (2026-08-22): открытый UDP-сокет не доказывает, что на том
    // конце кто-то есть — он открывается и при неверном IP, и в пустой сети. Такие
    // транспорты просят подтверждения у самого узла (см. probeNode). У USB это не
    // нужно: устройство физически открыто драйвером, иначе open() бы не удался.
    this.requiresNodeConfirmation = false;
    // Auto-reconnect (DMX-004): DmxManager sets onDisconnect; a transport calls
    // notifyDisconnect() ONCE when it detects the device physically vanished
    // (cable/USB pulled) — distinct from an intentional close().
    this.onDisconnect = null;
    this._disconnectNotified = false;
    // Optional passive diagnostics sink. DmxManager injects it for the active
    // transport; transports never depend on the report implementation directly.
    this.onDiagnostic = null;
    // Учёт кадров на проводе (2026-09-11). Что именно означает УСПЕХ у этого
    // транспорта — уровень подтверждения. У каждого он свой, и отчёт не вправе
    // выдавать «кадр отдан драйверу» за «прибор принял кадр» (справочник
    // DMX_CONTROLLER_TROUBLESHOOTING §3: «виден в USB» и «успешно открыт» не
    // означают «передаёт DMX»). Словарь уровней — в DmxDiagnostics.
    // DmxManager читает это поле один раз при подключении и штампует им каждое
    // событие передачи, поэтому горячий путь отправки о нём ничего не знает.
    this.transferConfirmation = null;
    // Один кадр = одна попытка. uDMX ведёт СВОЙ, подробный учёт (план посылки,
    // лестница восстановления) и заново заводит этот же счётчик у себя; остальным
    // транспортам хватает общего — отчёту нужно отличить «поток идёт» от «молчит».
    this._transferSequence = 0;
    this._consecTransferErrors = 0;
  }

  // Fire the unexpected-disconnect hook exactly once per transport instance.
  // Transports are recreated per connect(), so the latch never needs resetting.
  notifyDisconnect(reason) {
    if (this._disconnectNotified) return;
    this._disconnectNotified = true;
    if (typeof this.onDisconnect === 'function') {
      try { this.onDisconnect(reason); } catch (e) { /* never let a listener throw break I/O */ }
    }
  }

  notifyDiagnostic(event) {
    if (typeof this.onDiagnostic !== 'function') return;
    try { this.onDiagnostic(event); } catch { /* diagnostics must never affect DMX I/O */ }
  }

  /**
   * Один кадр, отданный на провод, — в диагностику отчёта. Общая дверь для всех
   * транспортов, КРОМЕ uDMX: тот эмитит `transfer-result` сам, потому что знает про
   * кадр несравнимо больше (диапазон каналов, вид посылки, ступень восстановления).
   *
   * Вызывать в точке, где известен ИСХОД передачи (колбэк записи, колбэк сокета,
   * сторож), а не там, где кадр только поставлен в очередь: иначе счётчик покажет
   * «поток идёт» на мёртвом порту.
   */
  noteTransfer({
    success = false,
    durationMs = null,
    error = null,
    phase = null,
    thresholdReached = false,
    universe = null,
  } = {}) {
    const ok = !!success;
    // Счётчики ведём ВСЕГДА, даже когда слушателя нет: транспорт может остаться без
    // стока (teardown по таймауту оставляет «осиротевший» транспорт дописывать кадры),
    // а потом получить его снова — застывший счётчик выдал бы «восстановление после N
    // ошибок» из прошлой жизни.
    const recoveredAfterErrors = ok ? this._consecTransferErrors : 0;
    this._consecTransferErrors = ok ? 0 : this._consecTransferErrors + 1;
    this._transferSequence++;
    // Горячий путь (~40 кадров в секунду): без слушателя дальше не тратим ничего.
    if (typeof this.onDiagnostic !== 'function') return;
    this.notifyDiagnostic({
      type: 'transfer-result',
      success: ok,
      transferSequence: this._transferSequence,
      durationMs,
      phase,
      universe,
      error: ok ? null : normalizeTransferError(error),
      consecutiveErrors: this._consecTransferErrors,
      recoveredAfterErrors,
      thresholdReached: !!thresholdReached,
    });
  }

  async open() {
    throw new Error('Not implemented');
  }

  async close() {
    throw new Error('Not implemented');
  }

  send(dmxData) {
    throw new Error('Not implemented');
  }

  isConnected() {
    return this.connected;
  }

  /**
   * Спросить у железа/узла подтверждение, что связь настоящая.
   * По умолчанию средства подтверждения нет (`supported: false`) — так у sACN:
   * протокол E1.31 ответа приёмника не предусматривает вообще. Вызывающий обязан
   * трактовать это как «не знаем», а не как поломку: свет при этом идёт.
   */
  async probeNode() {
    return { supported: false, confirmed: false, reason: 'unsupported', nodes: [] };
  }

  getDisplayName() {
    return this.deviceInfo.name || 'Unknown';
  }
}

module.exports = BaseDmxTransport;
// test-only: приведение ошибки кадра к общему словарю видов.
module.exports._normalizeTransferError = normalizeTransferError;
