const { SerialPort } = require('serialport');
const BaseDmxTransport = require('./BaseDmxTransport');
const { isDeviceGoneError } = require('./reconnectUtils');

const KNOWN_SERIAL_VIDS = [
  '0403',  // FTDI (Enttec Pro, DMXKing, Eurolite, etc.)
  '1a86',  // CH340 (Aliexpress свистки с Enttec-прошивкой)
];

// Per-write completion watchdog (ENTTEC-001). A serial write callback fires when
// the frame is handed to the OS. On a hung chip that holds the line without
// raising 'close'/'error', the callback may NEVER fire — coalescing alone would
// then sit _inFlight forever and never reconnect. The watchdog forces the frame
// forward so the queue never wedges. Generous: a 518-byte frame at 57600 baud is
// ~90 ms on the wire, so a single slow frame under legitimate backpressure must
// finish well before this and never trip it.
const WRITE_WATCHDOG_MS = 250;
// Unplug/hang detection: consecutive watchdog stalls (no completed write in
// between) mean the device stopped accepting data. ~8 × 250 ms ≈ 2 s of total
// silence before we declare it gone — long enough that sustained backpressure
// (real frames still completing, which resets the counter) never trips it.
const MAX_CONSEC_STALLS = 8;

// Models known to speak the ENTTEC DMX USB PRO protocol (0x7E…0xE7) on an FTDI
// chip — shown under the list entry so an owner recognises their box (same list
// as the site's supported-interfaces page).
// The UI appends a localized «other DMX PRO» item after these brands.
const ENTTEC_PRO_FTDI_MODELS = ['ENTTEC DMX USB Pro', 'DMXKING ultraDMX Micro'];

function vidToChipLabel(vid) {
  if (vid === '1a86') return 'CH340';
  if (vid === '0403') return 'FTDI';
  return 'USB';
}

class EnttecProTransport extends BaseDmxTransport {
  constructor(deviceInfo) {
    super(deviceInfo);
    this.port = null;
    this._inFlight = false;   // ENTTEC-001: one wire write at a time
    this._pending = null;     // ENTTEC-001: latest undelivered frame (Buffer | null)
    this._consecStalls = 0;   // ENTTEC-001: consecutive watchdog stalls (DMX-004)
    this._watchdog = null;    // ENTTEC-001: per-write completion watchdog timer
    // ENTTEC-001/DMX-004: set on close() — lets port 'close'/'error' handlers tell
    // an intentional close from a cable pull (same pattern as Open DMX).
    this.stopping = false;
    // Успех = драйвер ОС завершил запись кадра в порт. Сама коробка Enttec Pro
    // ответа на кадр не шлёт, поэтому обещать «прибор принял» мы не вправе.
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
            type: 'enttec-pro',
            path: port.path,
            vendorId: vid,
            productId: (port.productId || '').toLowerCase(),
            manufacturer: port.manufacturer || '',
            serialNumber: (port.serialNumber || '').toLowerCase()
          };
          // ONE entry per port and protocol; Enttec-Pro-compatible brands are a
          // hint under it, not duplicate rows (same reasoning as Open DMX scan).
          // Brands are FTDI-only. (CHANGES_TOUR 2026-10-31)
          results.push({
            ...base,
            id: `enttec-pro-${port.path}`,
            name: `Enttec Pro (${chip}, ${port.path})`,
            ...(vid === '0403' ? { models: ENTTEC_PRO_FTDI_MODELS } : {})
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
    // Reset coalescing/watchdog state on each (re)open — drop any stale frame.
    this._inFlight = false;
    this._pending = null;
    this._consecStalls = 0;
    this.stopping = false;

    try {
      this.port = new SerialPort({
        path: this.deviceInfo.path,
        baudRate: 57600,
        dataBits: 8,
        stopBits: 1,
        parity: 'none',
        autoOpen: false
      });

      return new Promise((resolve) => {
        this.port.open((err) => {
          if (err) {
            this.lastError = err.message;
            this.connected = false;
            console.log('❌ Enttec Pro open error:', err.message);
            resolve(false);
          } else {
            this.connected = true;
            this.lastError = null;
            console.log(`✅ Enttec Pro подключен: ${this.deviceInfo.path}`);
            // Unplug detection (DMX-004): serialport fires 'close'/'error' when the
            // USB serial device vanishes. Ignore events caused by our own close()
            // (stopping=true) — those are intentional, not a cable pull. Same proven
            // pattern as FtdiOpenDmxTransport.
            this.port.on('close', () => {
              if (!this.stopping) { this.connected = false; this.notifyDisconnect('serial-close'); }
            });
            this.port.on('error', (e) => {
              if (!this.stopping) {
                this.lastError = e && e.message ? e.message : String(e);
                this.connected = false;
                this.notifyDisconnect('serial-error');
              }
            });
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
    // Mark intentional close FIRST so the 'close' handler below doesn't treat it
    // as a cable pull, then drop any in-flight coalescing/watchdog state.
    this.stopping = true;
    this._inFlight = false;
    this._pending = null;
    if (this._watchdog) { clearTimeout(this._watchdog); this._watchdog = null; }

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

  send(dmxData) {
    if (!this.port || !this.port.isOpen || !this.connected) return;

    // Snapshot the frame to a wire-ready packet immediately. This protects against
    // the caller mutating dmxData after returning from send().
    const buffer = this._buildPacket(dmxData);

    // Coalescing (ENTTEC-001): never stack serial writes. At 57600 baud a 518-byte
    // frame is ~90 ms on the wire, yet DmxManager throttles at 25 ms — sends arrive
    // ~4× faster than the wire can carry. While one write is in-flight, keep only
    // the latest frame and return; the callback flushes it. Intermediate (stale)
    // DMX states are intentionally dropped — only the current state matters.
    if (this._inFlight) {
      this._pending = buffer;
      return;
    }
    this._transmit(buffer);
  }

  // Build the Enttec Pro DMX-send packet (0x7E / label 0x06 / len / start code /
  // 512 channels / 0xE7). Format unchanged from the working build.
  _buildPacket(dmxData) {
    const START_BYTE = 0x7E;
    const END_BYTE = 0xE7;
    const LABEL_DMX_SEND = 0x06;
    const dmxLength = 513; // 1 startcode + 512 channels

    const buffer = Buffer.alloc(5 + dmxLength);
    buffer[0] = START_BYTE;
    buffer[1] = LABEL_DMX_SEND;
    buffer[2] = dmxLength & 0xFF;
    buffer[3] = (dmxLength >> 8) & 0xFF;
    buffer[4] = 0x00; // DMX start code

    for (let i = 0; i < 512; i++) {
      buffer[5 + i] = (dmxData[i] !== undefined) ? dmxData[i] : 0;
    }

    buffer[5 + 512] = END_BYTE;
    return buffer;
  }

  _transmit(buffer) {
    this._inFlight = true;
    // Счётчик кадров для отчёта (2026-09-11): исход известен только в колбэке
    // записи или у сторожа, поэтому время берём здесь, а учитываем там.
    const startedMs = Date.now();

    // Exactly one outcome per write: whichever of {callback, watchdog} fires first
    // wins; the other no-ops. Prevents a late callback (from a write the watchdog
    // already advanced past) from double-flushing the queue or racing the next
    // write — same frameDone invariant as Open DMX (OPEN-DMX-003).
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      if (this._watchdog) { clearTimeout(this._watchdog); this._watchdog = null; }
      this._inFlight = false;

      if (err) {
        // Clean device-gone error → reconnect immediately (DMX-004).
        if (isDeviceGoneError(err.message)) {
          this._pending = null;
          this.connected = false;
          this.noteTransfer({
            success: false,
            durationMs: Date.now() - startedMs,
            error: err,
            // Порог достигнут: этот кадр — последний перед объявлением потери связи,
            // и в журнале провалов он обязан стоять как приговор, а не как помеха.
            thresholdReached: true,
          });
          this.notifyDisconnect('serial-write-error');
          return;
        }
        // Transient write error — log and keep going (do NOT drop the connection).
        this.lastError = err.message;
        console.log('⚠️ Enttec Pro send error:', err.message);
      } else {
        this._consecStalls = 0; // a completed write proves the device is alive
      }

      // Учёт ДО флэша очереди — намеренно, в отличие от Open DMX. Там цикл кадров
      // самотактируемый, и любая задержка перед scheduleNext() становится дрожанием на
      // проводе; здесь такт задаёт троттл DmxManager (25 мс), а сама запись кадра на
      // 57600 бод занимает ~90 мс — на этом фоне учёт не измеряется. Зато порядок
      // остаётся хронологическим: _flushPending() может синхронно начать (и на
      // мгновенной ошибке — завершить) следующий кадр, и тот получил бы номер раньше
      // уже завершившегося.
      this.noteTransfer({ success: !err, durationMs: Date.now() - startedMs, error: err || null });
      this._flushPending();
    };

    // Watchdog: the OS never completed the write (hung chip, no 'close'/'error').
    // Force the frame forward so the queue never wedges; a sustained run of stalls
    // with no completed write means the device is gone (DMX-004).
    this._watchdog = setTimeout(() => {
      if (done || this.stopping) return;
      done = true;
      this._watchdog = null;
      this._inFlight = false;
      this._consecStalls++;
      // Зависшая запись — это не «кадр ушёл»: драйвер её не завершил. В отчёте она
      // обязана быть видна как провал, иначе «поток идёт» покажет мёртвый порт.
      this.noteTransfer({
        success: false,
        durationMs: Date.now() - startedMs,
        phase: 'watchdog',
        error: {
          kind: 'TIMED_OUT',
          name: 'WriteWatchdog',
          message: `запись в порт не завершилась за ${WRITE_WATCHDOG_MS} мс`,
          code: null,
          errno: null,
        },
        thresholdReached: this._consecStalls >= MAX_CONSEC_STALLS,
      });
      if (this._consecStalls >= MAX_CONSEC_STALLS) {
        this._pending = null;
        this.connected = false;
        this.notifyDisconnect('serial-no-response');
        return;
      }
      // A lone stall healed by the next write is noise; only a run is worth a line.
      if (this._consecStalls >= 2) {
        console.log(`⚠️ Enttec Pro: write watchdog — записи зависают подряд (${this._consecStalls})`);
      }
      this._flushPending();
    }, WRITE_WATCHDOG_MS);

    try {
      this.port.write(buffer, (err) => finish(err || null));
    } catch (err) {
      // write() can also throw SYNCHRONOUSLY when the port vanished mid-call.
      if (this._watchdog) { clearTimeout(this._watchdog); this._watchdog = null; }
      done = true;
      this._inFlight = false;
      this._pending = null; // drop pending — device is gone / port broken
      const gone = isDeviceGoneError(err && err.message);
      this.noteTransfer({
        success: false,
        durationMs: Date.now() - startedMs,
        phase: 'synchronous-throw',
        error: err,
        thresholdReached: gone,
      });
      if (gone) {
        this.connected = false;
        this.notifyDisconnect('serial-write-throw');
      } else {
        this.lastError = err && err.message ? err.message : String(err);
        console.log('⚠️ Enttec Pro write throw:', this.lastError);
      }
    }
  }

  // Flush the coalesced latest frame that arrived while a write was in flight.
  _flushPending() {
    if (this._pending && this.connected && this.port && this.port.isOpen) {
      const next = this._pending;
      this._pending = null;
      this._transmit(next);
    }
  }
}

module.exports = EnttecProTransport;
