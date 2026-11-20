const dgram = require('dgram');
const BaseDmxTransport = require('./BaseDmxTransport');

// sACN (E1.31) — ANSI E1.31-2018 Streaming ACN protocol
// Uses UDP multicast on 239.255.x.x, port 5568

const SACN_PORT = 5568;
const SACN_MULTICAST_BASE = '239.255.';
const ACN_PACKET_IDENTIFIER = Buffer.from([
  0x41, 0x53, 0x43, 0x2D, 0x45, 0x31, 0x2E, 0x31,
  0x37, 0x00, 0x00, 0x00
]); // "ASC-E1.17\0\0\0"

class SacnTransport extends BaseDmxTransport {
  constructor(deviceInfo) {
    super(deviceInfo);
    this.socket = null;
    this.sequenceNumber = 0;
    // MULTI-UNIVERSE: `universe` is the BASE wire universe for logical universe 1.
    // Logical universe N maps to wire universe (base + N − 1). sACN carries the
    // universe in every packet, so one socket serves all universes.
    this.universe = deviceInfo.universe || 1;
    this.supportsMultiUniverse = true;
    this.sequenceByUniverse = new Map(); // wire universe → its own E1.31 sequence counter
    this.priority = deviceInfo.priority || 100;
    this.cid = this.generateCID();
    this.sourceName = 'SvetoMaster';
    this.multicastAddress = this.getMulticastAddress(this.universe);
    // Сетевой транспорт: открытый сокет не доказывает, что кадры кто-то принимает.
    // В отличие от Art-Net (ArtPoll/ArtPollReply) подтвердить это у sACN НЕЧЕМ:
    // E1.31 не предусматривает ответа приёмника. Поэтому probeNode() остаётся
    // базовым (`supported: false`), и исход честно называется «не подтверждено».
    this.requiresNodeConfirmation = true;
    // По той же причине успех передачи здесь — ровно «ядро приняло пакет к
    // отправке». Кадры считаются, чтобы отчёт отличал «поток идёт» от «молчит»,
    // но выдавать это за приём приборами нельзя (2026-09-11).
    this.transferConfirmation = 'socket';
  }

  // Logical universe (1-based, from the engine) → wire universe stamped in the packet.
  wireUniverse(logicalUniverse = 1) {
    return this.universe + (Math.max(1, Math.floor(logicalUniverse) || 1) - 1);
  }

  static scan() {
    return [{
      id: 'sacn',
      type: 'sacn',
      name: 'sACN / E1.31 (UDP)',
      universe: 1,
      priority: 100
    }];
  }

  generateCID() {
    // Generate a pseudo-random 16-byte CID (UUID-like)
    const cid = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      cid[i] = Math.floor(Math.random() * 256);
    }
    // Set UUID v4 variant bits
    cid[6] = (cid[6] & 0x0F) | 0x40;
    cid[8] = (cid[8] & 0x3F) | 0x80;
    return cid;
  }

  getMulticastAddress(universe) {
    // sACN multicast: 239.255.<high byte>.<low byte>
    const highByte = (universe >> 8) & 0xFF;
    const lowByte = universe & 0xFF;
    return SACN_MULTICAST_BASE + highByte + '.' + lowByte;
  }

  // DMX-001: extracted for test injection (override in tests to supply a fake socket).
  _createSocket() {
    return dgram.createSocket({ type: 'udp4', reuseAddr: true });
  }

  async open() {
    // DMX-001: idempotent — close any existing socket before opening a new one.
    if (this.socket) await this.close();

    try {
      this.universe = this.deviceInfo.universe || 1;
      this.priority = this.deviceInfo.priority || 100;
      this.multicastAddress = this.getMulticastAddress(this.universe);
      this.sequenceNumber = 0;

      this.socket = this._createSocket();

      await new Promise((resolve, reject) => {
        this.socket.bind(0, () => {
          try {
            this.socket.setBroadcast(true);
            this.socket.setMulticastTTL(20);
          } catch (e) {
            // Non-fatal: some systems don't support multicast TTL
          }
          resolve();
        });
        // DMX-001: once (not on) — auto-removed after first fire so no permanent
        // listener survives on the live socket after a successful bind.
        this.socket.once('error', reject);
      });

      this.connected = true;
      this.lastError = null;
      console.log(`✅ sACN подключен: universe ${this.universe}, ${this.multicastAddress}:${SACN_PORT}`);
      return true;
    } catch (err) {
      // DMX-001: close the socket if createSocket() succeeded but bind() rejected —
      // without this the UDP file descriptor leaks on every failed open() attempt.
      if (this.socket) {
        try { this.socket.close(); } catch (e) { /* ignore */ }
        this.socket = null;
      }
      this.lastError = err.message;
      this.connected = false;
      console.log('❌ sACN ошибка:', err.message);
      return false;
    }
  }

  async close() {
    if (this.socket) {
      try {
        this.socket.close();
      } catch (e) { /* ignore */ }
    }
    this.socket = null;
    this.connected = false;
  }

  send(dmxData, logicalUniverse = 1) {
    if (!this.socket || !this.connected) return;

    // Счётчик кадров для отчёта (2026-09-11). Время замеряем до сборки пакета:
    // исход приходит в колбэке сокета, а до него кадр ещё ничей.
    const startedMs = Date.now();
    try {
      const wire = this.wireUniverse(logicalUniverse);
      const packet = this.buildDataPacket(dmxData, wire);
      this.socket.send(packet, 0, packet.length, SACN_PORT, this.getMulticastAddress(wire), (err) => {
        // Ошибка отправки НЕ рвёт подключение (так было и раньше): UDP доставку не
        // гарантирует, а разовый EADDRNOTAVAIL — не потеря связи. Но в счётчиках она
        // обязана быть видна, иначе «поток идёт» покажет сеть, куда ничего не уходит.
        this.noteTransfer({
          success: !err,
          durationMs: Date.now() - startedMs,
          universe: logicalUniverse,
          error: err || null,
        });
      });
      // Per-universe sequence counter (E1.31 receivers track sequence per universe).
      const seq = ((this.sequenceByUniverse.get(wire) || 0) + 1) & 0xFF;
      this.sequenceByUniverse.set(wire, seq);
      this.sequenceNumber = seq; // keep last for back-compat/inspection
    } catch (err) {
      // ignore send errors
      this.noteTransfer({
        success: false,
        durationMs: Date.now() - startedMs,
        phase: 'synchronous-throw',
        universe: logicalUniverse,
        error: err,
      });
    }
  }

  buildDataPacket(dmxData, wireUniverse = this.universe) {
    // E1.31 Data Packet structure (638 bytes for 512 channels)
    // Root Layer (38 bytes) + Framing Layer (77 bytes) + DMP Layer (523 bytes)
    const slotCount = 512;
    const dmpLength = 11 + slotCount + 1; // DMP header + start code + slots
    const framingLength = 77 + dmpLength - 10;
    const rootLength = 22 + framingLength + 16 - 10;
    const totalLength = rootLength + 16 + 6;
    const packet = Buffer.alloc(totalLength, 0);

    let offset = 0;

    // === Root Layer ===
    // Preamble Size (2 bytes)
    packet.writeUInt16BE(0x0010, offset); offset += 2;
    // Post-amble Size (2 bytes)
    packet.writeUInt16BE(0x0000, offset); offset += 2;
    // ACN Packet Identifier (12 bytes)
    ACN_PACKET_IDENTIFIER.copy(packet, offset); offset += 12;
    // Flags & Length (2 bytes) - 0x7000 | length
    const rootFlagsLength = 0x7000 | (totalLength - 16);
    packet.writeUInt16BE(rootFlagsLength, offset); offset += 2;
    // Vector (4 bytes) - VECTOR_ROOT_E131_DATA = 0x00000004
    packet.writeUInt32BE(0x00000004, offset); offset += 4;
    // CID (16 bytes)
    this.cid.copy(packet, offset); offset += 16;

    // === Framing Layer ===
    // Flags & Length (2 bytes)
    const framingFlagsLength = 0x7000 | (totalLength - 38);
    packet.writeUInt16BE(framingFlagsLength, offset); offset += 2;
    // Vector (4 bytes) - VECTOR_E131_DATA_PACKET = 0x00000002
    packet.writeUInt32BE(0x00000002, offset); offset += 4;
    // Source Name (64 bytes, null-terminated UTF-8)
    const nameBuffer = Buffer.from(this.sourceName, 'utf8');
    nameBuffer.copy(packet, offset);
    offset += 64;
    // Priority (1 byte)
    packet.writeUInt8(this.priority, offset); offset += 1;
    // Synchronization Address (2 bytes)
    packet.writeUInt16BE(0, offset); offset += 2;
    // Sequence Number (1 byte) — per wire universe (E1.31 tracks it per universe).
    packet.writeUInt8(this.sequenceByUniverse.get(wireUniverse) || 0, offset); offset += 1;
    // Options Flags (1 byte)
    packet.writeUInt8(0, offset); offset += 1;
    // Universe (2 bytes)
    packet.writeUInt16BE(wireUniverse, offset); offset += 2;

    // === DMP Layer ===
    // Flags & Length (2 bytes)
    const dmpFlagsLength = 0x7000 | (slotCount + 1 + 11);
    packet.writeUInt16BE(dmpFlagsLength, offset); offset += 2;
    // Vector (1 byte) - VECTOR_DMP_SET_PROPERTY = 0x02
    packet.writeUInt8(0x02, offset); offset += 1;
    // Address Type & Data Type (1 byte) - 0xA1
    packet.writeUInt8(0xA1, offset); offset += 1;
    // First Property Address (2 bytes)
    packet.writeUInt16BE(0x0000, offset); offset += 2;
    // Address Increment (2 bytes)
    packet.writeUInt16BE(0x0001, offset); offset += 2;
    // Property Value Count (2 bytes) - slots + 1 (start code)
    packet.writeUInt16BE(slotCount + 1, offset); offset += 2;
    // DMX Start Code (1 byte)
    packet.writeUInt8(0x00, offset); offset += 1;
    // DMX Data (512 bytes)
    for (let i = 0; i < slotCount; i++) {
      packet.writeUInt8((dmxData[i] !== undefined) ? dmxData[i] : 0, offset + i);
    }

    return packet;
  }
}

module.exports = SacnTransport;
