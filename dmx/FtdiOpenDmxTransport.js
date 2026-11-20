const { SerialPort } = require('serialport');
const BaseDmxTransport = require('./BaseDmxTransport');
const { canRunFrame } = require('./frameUtils');

// Frame loop timings (preserved from the working 2026-05-09 break/MAB build).
const BREAK_MS = 2;   // break (line low) duration
const MAB_MS = 1;     // mark-after-break before data
const FRAME_GAP_MS = 22; // gap before next frame (~40 Hz with processing overhead)
// Watchdog: if a serial callback never fires (driver TIMED_OUT without returning),
// force the loop forward so the show never freezes (OPEN-DMX-003). Generous enough
// that a healthy frame (break+MAB+write) always finishes well before it.
const FRAME_WATCHDOG_MS = 60;

// VIDs USB-serial chips often used in DMX cables / dongles.
// FTDI: оригинал Enttec Open DMX USB и большинство брендовых свистков (DMXking, Eurolite).
// CH340: дешёвые китайские "USB to DMX 512" свистки. Часть из них прошита под Enttec Pro,
// часть — bare USB-serial и требует ручного break/MAB (этот транспорт).
// Мы предлагаем оба протокола для каждого порта; пользователь выбирает в UI,
// autoConnect выбирает по умолчанию по чипу (см. DmxManager.autoConnect).
const KNOWN_SERIAL_VIDS = [
  '0403',  // FTDI
  '1a86',  // CH340 (Aliexpress / WCH)
];

// Models known to speak Open DMX on an FTDI chip — shown under the list entry so
// an owner recognises their box (same list as the site's supported-interfaces
// page). JMS USB2DMX PRO is Open DMX despite «PRO» in its name
// (DMX_CONTROLLER_TROUBLESHOOTING §11).
// The UI appends a localized «other Open DMX» item after these brands.
const OPEN_DMX_FTDI_MODELS = ['ENTTEC Open DMX USB', 'JMS USB2DMX PRO'];

function vidToChipLabel(vid) {
  if (vid === '1a86') return 'CH340';
  if (vid === '0403') return 'FTDI';
  return 'USB';
}

class FtdiOpenDmxTransport extends BaseDmxTransport {
  constructor(deviceInfo) {
    super(deviceInfo);
    this.port = null;
    this.currentDmxData = new Array(512).fill(0); // Память последнего кадра
    this.isLoopRunning = false;
    this.loopTimer = null;     // gap timer between frames (scheduleNext)
    this.frameTimer = null;    // intra-frame timer (break/MAB waits) — tracked so
                               // stopLoop() can cancel an in-flight frame (BUG-004)
    this.watchdogTimer = null; // per-frame stall watchdog (OPEN-DMX-003)
    this.watchdogRun = 0;      // watchdog skips in a row; gates the console warning
    this.stopping = false;     // set on stopLoop/close; checked in every callback
                               // so in-flight callbacks never touch a closed port
                               // (OPEN-DMX-002)
    // Open DMX is self-clocked: this transport owns the wire timing via its own
    // loop, so DmxManager must NOT also throttle it (single frame clock — BUG-006).
    this.selfClocked = true;
    // Успех = драйвер ОС завершил break/MAB и запись кадра. Голый FT232 ничего не
    // подтверждает: ритм DMX задаёт компьютер, ответа с линии нет вовсе.
    this.transferConfirmation = 'driver';
  }

  static async scan() {
    const results = [];
    try {
      const ports = await SerialPort.list();
      for (const port of ports) {
        const vid = (port.vendorId || '').toLowerCase();
        if (KNOWN_SERIAL_VIDS.includes(vid)) {
          const chip = vidToChipLabel(vid);
          // Shared device "passport" (DMXMGR-002): serialNumber survives a COM-port
          // reassignment, so reconnect can re-find the SAME physical stick among
          // identical ones. Reused by every list entry for this port.
          const base = {
            type: 'open-dmx',
            path: port.path,
            vendorId: vid,
            productId: (port.productId || '').toLowerCase(),
            serialNumber: (port.serialNumber || '').toLowerCase()
          };
          // ONE entry per port and protocol. Branded models that speak this exact
          // Open DMX protocol are listed as a hint under the entry instead of as
          // extra rows: VID:PID 0403:6001 is shared by every FTDI stick, so a model
          // cannot be detected, and per-brand duplicate rows only differed by name
          // (and autoConnect picked the alphabetically first one — «JMS» — for any
          // generic stick). Brands are FTDI-only. (CHANGES_TOUR 2026-10-31)
          results.push({
            ...base,
            id: `open-dmx-${port.path}`,
            name: `Open DMX (${chip}, ${port.path})`,
            ...(vid === '0403' ? { models: OPEN_DMX_FTDI_MODELS } : {})
          });
        }
      }
    } catch (err) {
      console.log('⚠️ Serial scan error:', err.message);
      throw err;
    }
    return results;
  }

  async open() {
    try {
      this.port = new SerialPort({
        path: this.deviceInfo.path,
        baudRate: 250000,
        dataBits: 8,
        stopBits: 2,
        parity: 'none',
        autoOpen: false
      });

      return new Promise((resolve) => {
        this.port.open((err) => {
          if (err) {
            this.lastError = err.message;
            this.connected = false;
            console.log('❌ Open DMX open error:', err.message);
            resolve(false);
          } else {
            this.connected = true;
            this.lastError = null;
            console.log(`✅ Open DMX подключен: ${this.deviceInfo.path}`);
            // Unplug detection (DMX-004): serialport fires 'close'/'error' when the
            // USB serial device vanishes. Ignore events caused by our own close()
            // (stopping=true) — those are intentional, not a cable pull.
            this.port.on('close', () => {
              if (!this.stopping) { this.connected = false; this.notifyDisconnect('serial-close'); }
            });
            this.port.on('error', (err) => {
              if (!this.stopping) {
                this.lastError = err && err.message ? err.message : String(err);
                this.connected = false;
                this.notifyDisconnect('serial-error');
              }
            });
            this.startLoop(); // Запускаем фоновую отправку!
            resolve(true);
          }
        });
      });
    } catch (err) {
      this.lastError = err.message;
      this.connected = false;
      return false;
    }
  }

  async close() {
    this.stopLoop(); // Останавливаем цикл при отключении
    if (this.port && this.port.isOpen) {
      return new Promise((resolve) => {
        this.port.close(() => {
          this.connected = false;
          this.port = null;
          resolve();
        });
      });
    }
    this.connected = false;
    this.port = null;
  }

  // Фронтенд теперь просто обновляет данные в памяти
  send(dmxData) {
    if (!dmxData) return;
    for (let i = 0; i < 512; i++) {
      this.currentDmxData[i] = dmxData[i] || 0;
    }
  }

  // --- Логика фоновой отправки (Keep-Alive) ---

  startLoop() {
    if (this.isLoopRunning) return;
    this.stopping = false; // clear in case open() is ever called after a close()
    this.watchdogRun = 0;
    this.isLoopRunning = true;
    this.sendNextFrame();
  }

  stopLoop() {
    this.isLoopRunning = false;
    this.stopping = true; // in-flight callbacks see this and bail out
    if (this.loopTimer) { clearTimeout(this.loopTimer); this.loopTimer = null; }
    if (this.frameTimer) { clearTimeout(this.frameTimer); this.frameTimer = null; }
    if (this.watchdogTimer) { clearTimeout(this.watchdogTimer); this.watchdogTimer = null; }
  }

  // Whether the loop may still touch the port at this instant. Re-checked in
  // every async callback because close() can run between scheduling and firing.
  canRun() {
    return canRunFrame({
      isLoopRunning: this.isLoopRunning,
      stopping: this.stopping,
      portOpen: !!(this.port && this.port.isOpen),
      connected: this.connected,
    });
  }

  sendNextFrame() {
    if (!this.canRun()) return;

    const buffer = Buffer.alloc(513);
    buffer[0] = 0x00; // DMX start code
    for (let i = 0; i < 512; i++) {
      buffer[1 + i] = this.currentDmxData[i];
    }

    // Exactly one scheduleNext per frame: whichever of {success, error, watchdog}
    // fires first wins; the others no-op. Prevents two parallel loops if a stalled
    // callback fires late after the watchdog already advanced (OPEN-DMX-003).
    let frameDone = false;
    // Счётчик кадров для отчёта (2026-09-11). Исход кадра известен ровно там же,
    // где решается его судьба, поэтому он приезжает аргументом в finish(); без
    // исхода (закрытие порта на полпути) кадр не учитывается вовсе — это не провал.
    const startedMs = Date.now();
    const finish = (outcome = null) => {
      if (frameDone) return;
      frameDone = true;
      this.watchdogRun = 0; // the driver answered — any run of skips is over
      if (this.watchdogTimer) { clearTimeout(this.watchdogTimer); this.watchdogTimer = null; }
      // Сначала заводим следующий кадр, потом считаем предыдущий: учёт может дойти до
      // синхронной записи в app.log, а цикл здесь САМОТАКТИРУЕМЫЙ — задержка перед
      // scheduleNext() стала бы дрожанием на проводе. Инвариант OPEN-DMX-003 не
      // меняется: защёлка frameDone уже взведена, второго scheduleNext быть не может.
      this.scheduleNext();
      if (outcome) this.noteTransfer({ ...outcome, durationMs: Date.now() - startedMs });
    };

    this.watchdogTimer = setTimeout(() => {
      if (frameDone || this.stopping) return;
      // Serial driver never returned (e.g. TIMED_OUT) — skip the stalled frame.
      // A lone skip healed by the next frame is background noise (a busy main
      // process at startup, timer jitter: ~1 per 3000 frames, 2026-11-02), so the
      // console only hears about skips IN A ROW, and a long hang once per 100.
      this.watchdogRun++;
      if (this.watchdogRun === 2 || this.watchdogRun % 100 === 0) {
        console.log(`⚠️ Open DMX: frame watchdog — кадры зависают подряд (${this.watchdogRun})`);
      }
      frameDone = true;
      this.watchdogTimer = null;
      // Следующий кадр — раньше учёта, по той же причине, что и в finish().
      this.scheduleNext();
      // Зависший кадр на провод не вышел — в отчёте он провал, а не пропуск.
      this.noteTransfer({
        success: false,
        durationMs: Date.now() - startedMs,
        phase: 'watchdog',
        error: {
          kind: 'TIMED_OUT',
          name: 'FrameWatchdog',
          message: `кадр не завершился за ${FRAME_WATCHDOG_MS} мс`,
          code: null,
          errno: null,
        },
      });
    }, FRAME_WATCHDOG_MS);

    // Every callback/timer below re-checks both `frameDone` and `canRun()`:
    //   • frameDone — a late callback from a frame the watchdog already advanced
    //     past must NOT continue its stale break/MAB/write chain (it would race
    //     the next frame and clobber its frameTimer) — OPEN-DMX-003 invariant.
    //   • canRun()  — close() may have run mid-flight (OPEN-DMX-002 / BUG-004).
    // 1. Break
    this.port.set({ brk: true }, (err) => {
      if (frameDone || !this.canRun()) return;
      if (err) { finish({ success: false, phase: 'break', error: err }); return; }

      // 2. Wait BREAK_MS
      this.frameTimer = setTimeout(() => {
        if (frameDone || !this.canRun()) return;
        // 3. MAB
        this.port.set({ brk: false }, (err) => {
          if (frameDone || !this.canRun()) return;
          if (err) { finish({ success: false, phase: 'mab', error: err }); return; }

          // 4. Wait MAB_MS, then send data
          this.frameTimer = setTimeout(() => {
            if (frameDone || !this.canRun()) return;
            this.port.write(buffer, (err) => {
              if (frameDone || this.stopping) return;
              if (err) {
                this.lastError = err.message;
                console.log('⚠️ Open DMX write error:', err.message);
                finish({ success: false, phase: 'write', error: err });
                return;
              }
              finish({ success: true });
            });
          }, MAB_MS);
        });
      }, BREAK_MS);
    });
  }

  scheduleNext() {
    if (this.stopping || !this.isLoopRunning) return;
    // Gap before the next frame (~40 Hz with break/MAB/write overhead)
    this.loopTimer = setTimeout(() => {
      this.sendNextFrame();
    }, FRAME_GAP_MS);
  }
}

module.exports = FtdiOpenDmxTransport;
