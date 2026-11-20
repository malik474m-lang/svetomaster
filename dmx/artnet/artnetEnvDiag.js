// ═══════════════════════════════════════════════════════════════════════════
// Диагностика среды для Art-Net (2026-08-22, шаг 6 блока B мастера настройки)
// ═══════════════════════════════════════════════════════════════════════════
//
// Отвечает на вопрос, который пользователь задать не умеет: «почему у меня не идёт
// свет, хотя программа пишет "подключено"». Открытие UDP-сокета удаётся всегда — и
// при неверном адресе, и когда узла в сети нет вовсе, — поэтому «подключено» само по
// себе не значит ничего.
//
// Главный приём — СПРОСИТЬ У САМОЙ ОС, через какой адаптер уйдёт пакет. У сокета
// после `connect()` появляется адрес источника, который система выбрала по своей
// таблице маршрутов. Это факт, а не догадка по названию адаптера: при активном VPN
// (метрика туннеля ниже, чем у Ethernet) там окажется адрес туннеля, и свет уйдёт
// именно туда. Проверено живьём — ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md §6 п.7.
//
// Модуль ничего не чинит и ничего не отправляет в провод: только смотрит и называет
// проблему словами, которые можно показать человеку.
const dgram = require('dgram');
const { listCandidates, isSameSubnet } = require('../../main/remote/remoteNet');
const { ART_NET_PORT } = require('./artnetPackets');

const BROADCAST_ALL = '255.255.255.255';

/**
 * Через какой адрес ОС отправит пакет на указанную цель.
 *
 * `connect()` у UDP не создаёт соединения — он лишь фиксирует получателя, заставляя
 * ядро выбрать маршрут и локальный адрес. Никаких пакетов не уходит.
 * Возвращает null, если определить не удалось (сети нет вовсе).
 */
function probeRouteSource(target, { createSocket } = {}) {
  return new Promise((resolve) => {
    let sock;
    try {
      sock = (createSocket || ((o) => dgram.createSocket(o)))({ type: 'udp4', reuseAddr: true });
    } catch (e) {
      return resolve(null);
    }
    const finish = (value) => {
      try { sock.close(); } catch (e) { /* уже закрыт */ }
      resolve(value);
    };
    try {
      sock.on('error', () => finish(null));
      // Широковещательная цель требует явного разрешения, иначе connect отвергается.
      sock.bind(0, () => {
        try { sock.setBroadcast(true); } catch (e) { /* не критично */ }
        try {
          sock.connect(ART_NET_PORT, target, () => {
            let address = null;
            try { address = sock.address().address; } catch (e) { address = null; }
            finish(address && address !== '0.0.0.0' ? address : null);
          });
        } catch (e) { finish(null); }
      });
    } catch (e) { finish(null); }
  });
}

/** Свободен ли порт 6454. Занят — значит рядом работает другая световая программа. */
function probePortBusy({ createSocket } = {}) {
  return new Promise((resolve) => {
    let sock;
    try {
      // БЕЗ reuseAddr: с ним bind удастся даже на занятом порту, и проверка
      // всегда отвечала бы «свободен».
      sock = (createSocket || ((o) => dgram.createSocket(o)))({ type: 'udp4' });
    } catch (e) {
      return resolve({ busy: false, reason: null });
    }
    const finish = (value) => {
      try { sock.close(); } catch (e) { /* уже закрыт */ }
      resolve(value);
    };
    sock.on('error', (err) => finish({ busy: true, reason: err && err.code ? err.code : 'error' }));
    try {
      sock.bind({ port: ART_NET_PORT, address: '0.0.0.0' }, () => finish({ busy: false, reason: null }));
    } catch (e) {
      finish({ busy: true, reason: 'bind-throw' });
    }
  });
}

/**
 * Вердикты по снимку среды. Чистая функция — тестируется без сети.
 * Каждый вердикт: код (для интерфейса), уровень и данные для подстановки в текст.
 *
 * Порядок важен: сначала то, что делает вывод НЕВОЗМОЖНЫМ, потом мелочи.
 */
function buildVerdicts({ interfaces = [], routeSource = null, targetIp = null, portBusy = null, nodeFound = false, nodeInArp = false, ownTransportConnected = false } = {}) {
  const verdicts = [];
  const usable = interfaces.filter((n) => !n.tunnel);

  if (!interfaces.length) {
    verdicts.push({ code: 'no-network', level: 'error' });
    return verdicts;
  }
  if (!usable.length) {
    verdicts.push({ code: 'only-tunnels', level: 'error', data: { list: interfaces.map((n) => n.name) } });
    return verdicts;
  }

  // Свет уйдёт не туда — самая частая и самая незаметная причина «нет света».
  if (routeSource) {
    const owner = interfaces.find((n) => n.address === routeSource);
    if (owner && owner.tunnel) {
      verdicts.push({ code: 'route-via-tunnel', level: 'error', data: { name: owner.name, address: owner.address } });
    } else if (!owner) {
      verdicts.push({ code: 'route-via-unknown', level: 'warn', data: { address: routeSource } });
    }
  } else {
    verdicts.push({ code: 'route-unknown', level: 'warn' });
  }

  // Узел есть на проводе (виден по ARP), но не отвечает — режет брандмауэр либо
  // ответу некуда прийти. Различить это по одному признаку нельзя, поэтому вердикт
  // называет ОБА варианта, а не выдумывает один.
  if (!nodeFound && nodeInArp) {
    verdicts.push({ code: 'seen-but-silent', level: 'warn' });
  }

  // Узел в чужой подсети: он исправен, но доставить ответ физически не может.
  if (targetIp) {
    const sameNet = usable.some((n) => isSameSubnet(n.address, targetIp, n.netmask));
    if (!sameNet) {
      verdicts.push({ code: 'foreign-subnet', level: 'warn', data: { target: targetIp, list: usable.map((n) => n.address) } });
    }
  }

  // Порт 6454 держим МЫ САМИ, когда Art-Net уже подключён. Пугать этим пользователя
  // нельзя: он увидел бы «порт занят другой программой» ровно в тот момент, когда всё
  // работает. Тревога только если порт занял кто-то посторонний.
  if (portBusy && portBusy.busy && !ownTransportConnected) {
    verdicts.push({ code: 'port-busy', level: 'warn', data: { reason: portBusy.reason } });
  }

  const apipa = usable.filter((n) => /^169\.254\./.test(n.address));
  if (apipa.length === usable.length) {
    verdicts.push({ code: 'apipa', level: 'error', data: { list: apipa.map((n) => n.name) } });
  }

  const wireless = usable.filter((n) => n.wireless);
  if (wireless.length === usable.length) {
    verdicts.push({ code: 'wifi-only', level: 'warn', data: { list: wireless.map((n) => n.name) } });
  }

  if (!verdicts.length) verdicts.push({ code: 'ok', level: 'info' });
  return verdicts;
}

/**
 * Полный снимок среды. Никогда не бросает.
 * @param {object} options — targetIp: адрес узла (если известен), nodeFound/nodeInArp
 *   передаёт вызывающий по результатам поиска.
 */
async function inspectEnvironment({ targetIp = null, nodeFound = false, nodeInArp = false, ownTransportConnected = false, interfaces = null, createSocket = null } = {}) {
  let candidates = [];
  try {
    candidates = listCandidates(interfaces || require('os').networkInterfaces());
  } catch (e) { candidates = []; }

  const list = candidates.map((c) => ({
    name: c.name,
    address: c.address,
    netmask: c.netmask,
    tunnel: c.tunnel,
    virtual: c.virtual,
    wireless: c.wireless,
  }));

  const deps = createSocket ? { createSocket } : {};
  // Маршрут проверяем и для адреса узла, и для вещания: они могут разойтись.
  const routeSource = await probeRouteSource(targetIp || BROADCAST_ALL, deps);
  const broadcastSource = targetIp ? await probeRouteSource(BROADCAST_ALL, deps) : routeSource;
  const portBusy = await probePortBusy(deps);

  return {
    interfaces: list,
    routeSource,
    broadcastSource,
    portBusy,
    verdicts: buildVerdicts({ interfaces: list, routeSource, targetIp, portBusy, nodeFound, nodeInArp, ownTransportConnected }),
  };
}

module.exports = {
  inspectEnvironment,
  buildVerdicts,
  probeRouteSource,
  probePortBusy,
  BROADCAST_ALL,
};
