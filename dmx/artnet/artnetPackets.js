// ═══════════════════════════════════════════════════════════════════════════
// Art-Net — сборка и разбор пакетов. Чистый протокольный слой.
// ═══════════════════════════════════════════════════════════════════════════
//
// Зачем отдельным модулем (2026-08-22, блок A мастера настройки). Раньше разбор
// жил внутри `ArtNetTransport` — класса, который держит сокеты и вывод света.
// Мастеру настройки те же функции нужны ДО и БЕЗ подключения: он ищет узлы, когда
// транспорт ещё не открыт, и не имеет права трогать вывод света. Здесь нет ни
// сокетов, ни состояния — только байты, поэтому всё тестируется без сети.
//
// Совместимость: `ArtNetTransport` реэкспортирует прежние имена, существующие
// тесты и вызовы работают без правок.
//
// Порядок байтов в Art-Net неоднороден, и это источник трудноуловимых ошибок:
// OpCode — little-endian, версия протокола и длина данных — big-endian.
const os = require('os');

const ART_NET_ID = 'Art-Net\0';
const ART_NET_PORT = 6454;
const ART_NET_PROTOCOL_VERSION = 14;

const OP_POLL = 0x2000;
const OP_POLL_REPLY = 0x2100;
const OP_DMX = 0x5000;
const OP_IP_PROG = 0xF800;
const OP_IP_PROG_REPLY = 0xF900;

// Полный Port-Address: net (7 бит) : subnet (4) : universe (4) = 15 бит.
const MAX_PORT_ADDRESS = 0x7FFF;

// Биты команды ArtIpProg. Программирование включается ТОЛЬКО вместе с ENABLE.
const IP_PROG_ENABLE = 0x80;
const IP_PROG_DHCP = 0x40;
const IP_PROG_DEFAULT = 0x08; // сброс к заводским — намеренно не используем
const IP_PROG_SET_IP = 0x04;
const IP_PROG_SET_MASK = 0x02;
const IP_PROG_SET_PORT = 0x01;

/** Общий заголовок: ID + OpCode (LE) + версия протокола (BE). */
function buildHeader(opcode, length) {
  const packet = Buffer.alloc(length);
  packet.write('Art-Net', 0, 'latin1');
  packet.writeUInt8(0, 7);                          // NUL-терминатор ID
  packet.writeUInt16LE(opcode, 8);                  // OpCode — little-endian
  packet.writeUInt8(0, 10);                         // ProtVerHi
  packet.writeUInt8(ART_NET_PROTOCOL_VERSION, 11);  // ProtVerLo = 14
  return packet;
}

/** ArtPoll: 14 байт, TalkToMe = 0 (ответ только на наш запрос, без диагностики). */
function buildArtPollPacket() {
  const packet = buildHeader(OP_POLL, 14);
  packet.writeUInt8(0, 12); // TalkToMe
  packet.writeUInt8(0, 13); // Priority
  return packet;
}

function writeIpv4(packet, offset, value) {
  const parts = String(value || '').split('.');
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    packet.writeUInt8(Number.isFinite(n) ? Math.max(0, Math.min(255, n)) : 0, offset + i);
  }
}

const readIpv4 = (msg, offset) => `${msg[offset]}.${msg[offset + 1]}.${msg[offset + 2]}.${msg[offset + 3]}`;

/**
 * ArtIpProg — смена сетевых настроек узла ПО СЕТИ.
 *
 * ⚠️ В пакете НЕТ поля адресата. Узел в чужой подсети недостижим адресно, поэтому
 * команда уходит широковещательно — и её выполнит КАЖДЫЙ узел сегмента, который её
 * услышит. Решение о безопасности принимается уровнем выше (мастер обязан убедиться,
 * что в сети ровно один узел, либо дать пользователю выбор). Здесь — только байты.
 *
 * Биты «сброс к заводским» и «сменить порт» не выставляются никогда: первый стирает
 * настройки пользователя, второй уводит узел с порта 6454, где его больше никто не найдёт.
 */
function buildArtIpProgPacket({ ip, mask, dhcp = false } = {}) {
  const packet = buildHeader(OP_IP_PROG, 34);
  let command = IP_PROG_ENABLE;
  if (dhcp) {
    command |= IP_PROG_DHCP;
  } else {
    if (ip) command |= IP_PROG_SET_IP;
    if (mask) command |= IP_PROG_SET_MASK;
  }
  packet.writeUInt8(command, 14);
  if (!dhcp) {
    if (ip) writeIpv4(packet, 16, ip);
    if (mask) writeIpv4(packet, 20, mask);
  }
  return packet;
}

/** Ответ узла на ArtIpProg — фактические настройки ПОСЛЕ применения команды. */
function parseArtIpProgReply(msg, rinfo = {}) {
  if (!isArtNetPacket(msg, 26) || msg.readUInt16LE(8) !== OP_IP_PROG_REPLY) return null;
  return {
    ip: readIpv4(msg, 16),
    mask: readIpv4(msg, 20),
    from: rinfo.address ? String(rinfo.address) : null,
    // Бит 6 статуса: адрес получен по DHCP.
    dhcp: msg.length >= 27 ? !!(msg.readUInt8(26) & 0x40) : false,
  };
}

/**
 * ArtDmx — кадр DMX. `portAddress` — полный 15-битный адрес; раскладывается в
 * SubUni (subnet:universe) и Net, как того требует спецификация.
 * Длина данных — big-endian, в отличие от OpCode.
 */
function buildArtDmxPacket(portAddress, values, sequence = 0) {
  const packet = buildHeader(OP_DMX, 18 + 512);
  const address = clampInt(portAddress, 0, MAX_PORT_ADDRESS);
  packet.writeUInt8(clampInt(sequence, 0, 255), 12); // Sequence, 0 = не используется
  packet.writeUInt8(0, 13);                          // Physical
  packet.writeUInt8(address & 0xFF, 14);             // SubUni
  packet.writeUInt8((address >> 8) & 0x7F, 15);      // Net
  packet.writeUInt16BE(512, 16);                     // Length — big-endian
  if (values) {
    for (let i = 0; i < 512; i++) {
      const v = values[i];
      packet.writeUInt8(typeof v === 'number' && v > 0 ? Math.min(255, v | 0) : 0, 18 + i);
    }
  }
  return packet;
}

function clampInt(value, min, max) {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

/** Порядковый номер кадра: 1..255, 0 зарезервирован под «нумерация не ведётся». */
function nextSequence(previous) {
  const n = clampInt(previous, 0, 255);
  return n >= 255 ? 1 : n + 1;
}

function isArtNetPacket(msg, minLength) {
  return Buffer.isBuffer(msg)
    && msg.length >= minLength
    && msg.toString('latin1', 0, 8) === ART_NET_ID;
}

function readString(msg, from, to) {
  if (msg.length < to) return '';
  return msg.toString('latin1', from, to).replace(/\0[\s\S]*$/, '').trim();
}

/**
 * ArtPollReply — паспорт узла. Возвращает null для всего остального (чужой протокол,
 * наш собственный ArtPoll, ArtDmx и т.п.).
 *
 * Поля `ip` / `from` / `shortName` сохранены ради обратной совместимости с probeNode.
 *
 * ⚠️ `outputs[].isOutput` доверять НЕЛЬЗЯ как единственному признаку: живой PKNIGHT
 * CR021R объявляет свои физические ВЫХОДЫ как входы (PortType = 0x80), хотя свет
 * через них идёт. Направление определяется корпусом устройства, а не этим битом.
 */
function parseArtPollReply(msg, rinfo = {}) {
  if (!isArtNetPacket(msg, 26) || msg.readUInt16LE(8) !== OP_POLL_REPLY) return null;

  const ip = readIpv4(msg, 10);
  // ShortName — 18 байт, строка с NUL-терминатором и мусором после него.
  // Резать надо ИМЕННО по NUL: в прежней версии этот символ стоял в исходнике
  // литералом-невидимкой, и при переносе кода легко подменяется пробелом —
  // тогда имя узла тащит хвост \0 и в интерфейсе выглядит поломанным.
  const shortName = readString(msg, 26, 44);

  const reply = {
    ip: ip === '0.0.0.0' && rinfo.address ? String(rinfo.address) : ip,
    from: rinfo.address ? String(rinfo.address) : null,
    shortName,
  };
  // Короткий ответ (нестандартный узел) — отдаём то, что удалось прочитать.
  if (msg.length < 200) return reply;

  const net = msg.readUInt8(18) & 0x7F;
  const subNet = msg.readUInt8(19) & 0x0F;
  const status1 = msg.readUInt8(23);
  const status2 = msg.length >= 213 ? msg.readUInt8(212) : 0;
  const portCount = Math.min(4, msg.readUInt8(173));

  const outputs = [];
  for (let i = 0; i < portCount; i++) {
    const portType = msg.readUInt8(174 + i);
    const goodOutput = msg.readUInt8(182 + i);
    const swOut = msg.readUInt8(190 + i) & 0x0F;
    outputs.push({
      port: i + 1,
      swOut,
      portAddress: (net << 8) | (subNet << 4) | swOut,
      isOutput: !!(portType & 0x40),
      transmitting: !!(goodOutput & 0x80),
      shortCircuit: !!(goodOutput & 0x04),
      merging: !!(goodOutput & 0x08),
      outputsSacn: !!(goodOutput & 0x01),
    });
  }

  return Object.assign(reply, {
    longName: readString(msg, 44, 108),
    nodeReport: readString(msg, 108, 172),
    firmware: `${msg.readUInt8(16)}.${msg.readUInt8(17)}`,
    oem: msg.readUInt16BE(20),
    esta: msg.readUInt16LE(24),
    mac: msg.length >= 207
      ? Array.from(msg.slice(201, 207)).map((b) => b.toString(16).padStart(2, '0')).join(':')
      : null,
    style: msg.length >= 201 ? msg.readUInt8(200) : null,
    net,
    subNet,
    portCount,
    outputs,
    // Кто вправе назначать адреса портов: 2 = по сети (ArtAddress), 1 = только кнопками.
    portAddressByNetwork: ((status1 >> 4) & 0x03) === 2,
    supportsDhcp: !!(status2 & 0x04),
    usingDhcp: !!(status2 & 0x02),
    supportsWebConfig: !!(status2 & 0x01),
    supports15BitAddress: !!(status2 & 0x08),
    supportsRdm: !!(status1 & 0x02),
    status1,
    status2,
  });
}

/** Наши собственные IPv4 — чтобы не принять свой же ответ за «узел нашёлся». */
/**
 * ArtDmx (OpCode 0x5000) — кадр света. Возвращает null для всего остального.
 *
 * Зачем разбирать ЧУЖОЙ кадр: Art-Net-узлы штатно сливают два источника по HTP
 * (побеждает большее значение), поэтому вторая программа или пульт в той же сети
 * молча «подмешивает» свой свет в наш. Со стороны это выглядит как «прибор живёт
 * своей жизнью»: часть каналов слушается, часть намертво держится чужим кадром
 * (разбор 2026-08-23, `ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md` §7). Доказать это
 * можно только увидев чужие кадры на проводе — этим и занят разбор.
 *
 * Данные каналов сознательно НЕ копируются: наблюдателю нужны отправитель и адрес
 * юниверса, а 512 байт на каждый чужой кадр 40 раз в секунду — мусор для GC.
 */
function parseArtDmx(msg, rinfo = {}) {
  if (!isArtNetPacket(msg, 18)) return null;
  if (msg.readUInt16LE(8) !== OP_DMX) return null;
  // Заявленная длина ОБЯЗАНА укладываться в то, что реально пришло (аудит 2026-09-05).
  // Раньше проверялся только 18-байтный заголовок, поэтому обрезанный или битый кадр
  // с совпадающим Port-Address поднимал тревогу «в сети второй источник света» и
  // попадал в отчёт поддержки. Тело кадра идёт сразу за заголовком, значит длина
  // буфера проверяема точно.
  //
  // Чётность длины (её требует спецификация) СОЗНАТЕЛЬНО не проверяем: дешёвые
  // отправители правило нарушают, а пропустить настоящий конфликтующий источник
  // хуже, чем принять кадр с нечётной длиной — тревога всё равно поднимается только
  // при совпадении Port-Address с нашим.
  const length = msg.readUInt16BE(16);
  if (length < 1 || length > 512) return null;
  if (msg.length < 18 + length) return null;
  const subUni = msg.readUInt8(14);
  const net = msg.readUInt8(15) & 0x7F;
  return {
    ip: rinfo.address || null,
    portAddress: (net << 8) | subUni,
    sequence: msg.readUInt8(12),
    physical: msg.readUInt8(13),
    length,
  };
}

function localIpv4Addresses(interfaces) {
  const list = interfaces || os.networkInterfaces();
  const out = new Set();
  for (const entries of Object.values(list || {})) {
    for (const entry of entries || []) {
      // Node 18+ отдаёт family числом (4), более старые — строкой ('IPv4').
      if (entry && (entry.family === 'IPv4' || entry.family === 4) && entry.address) {
        out.add(String(entry.address));
      }
    }
  }
  return out;
}

/**
 * Свой ли это ответ. dmxnet представляется узлом и отвечает на ArtPoll, а
 * широковещательный запрос возвращается на свою же машину — без этого фильтра
 * программа «находила» саму себя. Отсекаем и по IP, и по имени: имя ловит наш
 * второй экземпляр на другом ПК.
 */
function isOwnArtPollReply(reply, localAddresses) {
  if (!reply) return true;
  const locals = localAddresses || localIpv4Addresses();
  if (reply.ip && locals.has(reply.ip)) return true;
  if (reply.from && locals.has(reply.from)) return true;
  return /^SvetoMaster/i.test(reply.shortName || '');
}

module.exports = {
  ART_NET_ID,
  ART_NET_PORT,
  ART_NET_PROTOCOL_VERSION,
  MAX_PORT_ADDRESS,
  OP_POLL,
  OP_POLL_REPLY,
  OP_DMX,
  OP_IP_PROG,
  OP_IP_PROG_REPLY,
  buildArtPollPacket,
  buildArtIpProgPacket,
  buildArtDmxPacket,
  parseArtDmx,
  parseArtPollReply,
  parseArtIpProgReply,
  isOwnArtPollReply,
  localIpv4Addresses,
  nextSequence,
};
