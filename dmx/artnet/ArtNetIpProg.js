// ═══════════════════════════════════════════════════════════════════════════
// Переселение Art-Net устройства в сеть компьютера (2026-08-22, блок C)
// ═══════════════════════════════════════════════════════════════════════════
//
// Задача. У конвертеров заводской адрес часто не совпадает с домашней сетью: у живого
// PKNIGHT CR021R это 10.201.6.100 с маской 255.0.0.0 против компьютера в 192.168.0.x.
// Устройство при этом ИСПРАВНО и наш запрос получает — широковещательный пакет
// доставляется всем в сегменте независимо от их адресов. Но ответить оно не может:
// маршрута к чужой сети у него нет, поэтому поиск видит тишину и человек упирается в
// «устройство не найдено» при полностью рабочем железе.
//
// Лечение — команда ArtIpProg, которая назначает устройству адрес по сети. Проверено
// на живом CR021R: переехал без единого нажатия кнопки.
//
// ⚠️ ГЛАВНАЯ ОПАСНОСТЬ. В пакете ArtIpProg НЕТ поля адресата. К устройству в чужой
// подсети адресно не достучаться, поэтому команда уходит широковещательно — и её
// выполнит КАЖДОЕ устройство сегмента, которое её услышит. На площадке с четырьмя
// конвертерами это разъедет адреса всем сразу, посреди монтажа.
//
// Отсюда правила, зашитые здесь и в интерфейсе:
//   • операция предлагается ТОЛЬКО когда обычный поиск ничего не нашёл;
//   • пользователь обязан подтвердить её явно, прочитав предупреждение про несколько
//     устройств (решение владельца 2026-08-22: не запрещать, а дать выбор — «оставьте
//     подключённым только тот, который настраиваете» либо «настрою вручную»);
//   • новый адрес выбирается свободный и в подсети выбранной карты;
//   • биты «сброс к заводским» и «смена порта» не выставляются никогда (см.
//     artnetPackets.buildArtIpProgPacket);
//   • после отправки результат ПРОВЕРЯЕТСЯ повторным опросом — молчание означает
//     «эта модель по сети адрес не меняет», а не «готово».
const dgram = require('dgram');
const { execFile } = require('child_process');

const {
  ART_NET_PORT,
  buildArtIpProgPacket,
  buildArtPollPacket,
  parseArtIpProgReply,
  parseArtPollReply,
  isOwnArtPollReply,
  localIpv4Addresses,
} = require('./artnetPackets');
const { ipToInt, isSameSubnet } = require('../../main/remote/remoteNet');

const BROADCAST_ALL = '255.255.255.255';
// Верхняя часть подсети: DHCP-пулы домашних роутеров почти всегда заканчиваются
// раньше, поэтому там меньше шансов столкнуться с чужим устройством.
const PREFERRED_HOSTS = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250];

/**
 * Кандидаты на новый адрес устройства: подсеть выбранной карты, верхний диапазон.
 * Исключаем свой адрес, адрес сети, широковещательный и типичный адрес шлюза (.1).
 * Чистая функция — вся арифметика проверяется тестами.
 */
function candidateAddresses(nic, taken = []) {
  if (!nic || !nic.address || !nic.netmask) return [];
  const base = nic.address.split('.').slice(0, 3).join('.');
  const busy = new Set([nic.address, `${base}.1`, `${base}.0`, `${base}.255`, ...taken]);
  const out = [];
  for (const host of PREFERRED_HOSTS) {
    const ip = `${base}.${host}`;
    if (busy.has(ip)) continue;
    // Держимся внутри подсети карты: при нестандартной маске (/26 и подобных)
    // верхние адреса могут оказаться уже за её пределами.
    if (!isSameSubnet(nic.address, ip, nic.netmask)) continue;
    out.push(ip);
  }
  return out;
}

/** Занят ли адрес: спрашиваем ARP-таблицу ОС после короткой пробы. */
function isAddressTaken(ip, { arpReader } = {}) {
  const read = arpReader || defaultArpReader;
  return new Promise((resolve) => {
    // Проба заставляет Windows разослать ARP-запрос; ответ осядет в таблице.
    let probe;
    try {
      probe = dgram.createSocket('udp4');
      probe.send(Buffer.from([0]), 9, ip, () => {
        setTimeout(() => {
          try { probe.close(); } catch (e) { /* закрыт */ }
          read(ip).then(resolve).catch(() => resolve(false));
        }, 900);
      });
    } catch (e) {
      try { if (probe) probe.close(); } catch (e2) { /* закрыт */ }
      read(ip).then(resolve).catch(() => resolve(false));
    }
  });
}

function defaultArpReader(ip) {
  return new Promise((resolve) => {
    execFile('arp', ['-a'], { timeout: 4000, windowsHide: true }, (err, stdout) => {
      if (err || !stdout) return resolve(false);
      resolve(hasRealMac(String(stdout), ip));
    });
  });
}

/**
 * Есть ли в выводе `arp -a` РЕАЛЬНЫЙ MAC для адреса. Строка без MAC — это наш же
 * неотвеченный запрос, то есть адрес свободен; принять её за занятость значило бы
 * никогда не находить свободных адресов.
 */
function hasRealMac(arpOutput, ip) {
  const needle = ip.replace(/\./g, '\\.');
  const re = new RegExp(`(^|\\s)${needle}\\s+([0-9a-f]{2}[-:]){5}[0-9a-f]{2}`, 'im');
  const match = re.exec(arpOutput);
  if (!match) return false;
  return !/(00[-:]){5}00/i.test(match[0]);
}

/**
 * Переселить устройство. Никогда не бросает.
 *
 * @returns {Promise<{ok: boolean, reason: string, ip: string|null, nodes: Array}>}
 *   reason: 'moved' — устройство отозвалось с нового адреса (единственный успех);
 *           'silent' — команда ушла, но никто не отозвался: скорее всего модель не
 *                      поддерживает настройку по сети;
 *           'no-free-address' | 'no-interface' | 'error'.
 */
async function reassignAddress({
  nic,
  newIp = null,
  mask = '255.255.255.0',
  timeoutMs = 6000,
  createSocket = null,
  arpReader = null,
  takenAddresses = [],
} = {}) {
  if (!nic || !nic.address) return { ok: false, reason: 'no-interface', ip: null, nodes: [] };

  let target = newIp;
  if (!target) {
    const candidates = candidateAddresses(nic, takenAddresses);
    for (const candidate of candidates) {
      // eslint-disable-next-line no-await-in-loop
      const taken = await isAddressTaken(candidate, { arpReader });
      if (!taken) { target = candidate; break; }
    }
  }
  if (!target) return { ok: false, reason: 'no-free-address', ip: null, nodes: [] };

  const mk = createSocket || ((o) => dgram.createSocket(o));
  let rx = null;
  let tx = null;
  const replies = [];
  const nodes = new Map();
  const locals = localIpv4Addresses();

  const onMessage = (msg, rinfo) => {
    try {
      const prog = parseArtIpProgReply(msg, rinfo);
      if (prog) { replies.push(prog); return; }
      const poll = parseArtPollReply(msg, rinfo);
      if (poll && !isOwnArtPollReply(poll, locals)) nodes.set(poll.ip, poll);
    } catch (e) { /* чужой мусор не должен ломать операцию */ }
  };

  try {
    rx = mk({ type: 'udp4', reuseAddr: true });
    rx.on('error', () => { /* приёмник не обязателен: ответ придёт и на tx */ });
    rx.on('message', onMessage);
    await new Promise((resolve) => {
      try {
        rx.bind({ port: ART_NET_PORT, address: '0.0.0.0' }, () => {
          try { rx.setBroadcast(true); } catch (e) { /* не критично */ }
          resolve();
        });
      } catch (e) { resolve(); }
    });

    tx = mk({ type: 'udp4', reuseAddr: true });
    tx.on('error', () => { /* ошибка отправки обернётся таймаутом */ });
    tx.on('message', onMessage);
    await new Promise((resolve) => {
      try {
        tx.bind({ port: 0, address: nic.address }, () => {
          try { tx.setBroadcast(true); } catch (e) { /* не критично */ }
          resolve();
        });
      } catch (e) { resolve(); }
    });

    const packet = buildArtIpProgPacket({ ip: target, mask });
    const send = (buf, to) => new Promise((resolve) => {
      try { tx.send(buf, ART_NET_PORT, to, () => resolve()); } catch (e) { resolve(); }
    });

    // Три посылки: UDP теряет пакеты, а второго шанса у пользователя не будет.
    for (let i = 0; i < 3; i++) {
      // eslint-disable-next-line no-await-in-loop
      await send(packet, BROADCAST_ALL);
      // eslint-disable-next-line no-await-in-loop
      await wait(400);
    }

    // Проверяем результат: спрашиваем сеть и новый адрес отдельно.
    //
    // Ждём ИМЕННО НОВЫЙ АДРЕС, а не «хоть какой-нибудь ответ». Разница принципиальна,
    // когда переселяют НАЙДЕННЫЙ узел (он в чужой подсети, но на вещание отвечает —
    // живой случай 07.09.2026, узел 2.0.0.200 при ПК в 192.168.0.x). Его ответ со
    // СТАРОГО адреса приходит первым же опросом, а смена адреса занимает секунду и
    // больше: условие «пока список пуст» обрывало ожидание сразу и выдавало вердикт
    // «модель не умеет настраиваться по сети» на модели, которая умеет.
    const arrived = () => nodes.has(target) || replies.some((r) => r.ip === target);
    const deadline = Date.now() + Math.max(1000, timeoutMs);
    while (Date.now() < deadline && !arrived()) {
      // eslint-disable-next-line no-await-in-loop
      await send(buildArtPollPacket(), BROADCAST_ALL);
      // eslint-disable-next-line no-await-in-loop
      await send(buildArtPollPacket(), target);
      // eslint-disable-next-line no-await-in-loop
      await wait(700);
    }

    const found = Array.from(nodes.values());
    const moved = found.some((n) => n.ip === target) || replies.some((r) => r.ip === target);
    return {
      ok: moved,
      reason: moved ? 'moved' : 'silent',
      ip: moved ? target : null,
      nodes: found,
      replies,
    };
  } catch (e) {
    return { ok: false, reason: 'error', ip: null, nodes: [] };
  } finally {
    for (const sock of [rx, tx]) {
      try { if (sock) sock.close(); } catch (e) { /* закрыт */ }
    }
  }
}

function wait(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

module.exports = {
  reassignAddress,
  candidateAddresses,
  isAddressTaken,
  hasRealMac,
  PREFERRED_HOSTS,
};
module.exports._ipToInt = ipToInt;
