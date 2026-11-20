// ═══════════════════════════════════════════════════════════════════════════
// Поиск Art-Net узлов в сети (2026-08-22, блок A мастера настройки)
// ═══════════════════════════════════════════════════════════════════════════
//
// Задача: ответить на вопрос «какие узлы вообще есть в сети», ДО того как
// пользователь что-то настроил. Сейчас человек обязан откуда-то знать IP своего
// конвертера и вписать его руками — для новичка это тупик.
//
// Почему нельзя просто открыть сокет и разослать опрос:
//
// 1. ОС САМА ВЫБИРАЕТ, ЧЕРЕЗ КАКУЮ КАРТУ СЛАТЬ. При активном VPN метрика туннеля
//    ниже, чем у Ethernet, и широковещательный пакет уходит в туннель — свет и опрос
//    просто не доходят до сети (подтверждено живьём: ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md
//    §6 п.7). Поэтому на КАЖДУЮ карту создаётся свой сокет, привязанный к её адресу:
//    привязка источника — единственный способ заставить пакет уйти именно оттуда.
//
// 2. УЗЕЛ МОЖЕТ БЫТЬ В ЧУЖОЙ ПОДСЕТИ. Заводской адрес конвертера часто не совпадает с
//    домашней сетью (у живого CR021R это 10.201.6.100/8 против 192.168.0.6/24).
//    Адресный пакет туда не дойдёт, а вот «общее» вещание 255.255.255.255 доставляется
//    на канальном уровне ВСЕМ в сегменте, независимо от их IP. Поэтому шлём и его, и
//    вещание своей подсети: часть узлов отвечает только на второе.
//
// 3. ОТВЕТ МОЖЕТ НЕ ДОЙТИ ОБРАТНО. Узел из чужой подсети физически не может доставить
//    нам ответ. Это НЕ поломка узла, и мастер обязан отличать «узлов нет» от
//    «узел есть, но ответить не может» — второй случай лечится сменой адреса.
//
// Модуль ничего не решает за пользователя и никогда не бросает: худший исход —
// пустой список с описанием того, что мешало.
const dgram = require('dgram');
const os = require('os');

const {
  ART_NET_PORT,
  buildArtPollPacket,
  parseArtPollReply,
  isOwnArtPollReply,
  localIpv4Addresses,
} = require('./artnetPackets');
const { listCandidates, directedBroadcast, isSameSubnet } = require('../../main/remote/remoteNet');

const BROADCAST_ALL = '255.255.255.255';
// Узел отвечает за единицы миллисекунд, но UDP теряет пакеты, а дешёвая прошивка
// может задуматься. Три посылки за 3 с — запас, не заметный человеку.
const DEFAULT_TIMEOUT_MS = 3000;
const DEFAULT_ATTEMPTS = 3;

/**
 * Карты, через которые есть смысл искать. Туннельные (/31, /32 — VPN) отсеиваются:
 * за ними нет локального сегмента, вещать некуда. Но они ВОЗВРАЩАЮТСЯ отдельным
 * списком — пользователь должен видеть, почему его VPN-адаптер не участвует.
 */
function selectInterfaces(ifaces) {
  const candidates = listCandidates(ifaces || os.networkInterfaces());
  const usable = [];
  const skipped = [];
  for (const c of candidates) {
    // Виртуальные адаптеры (VirtualBox, Docker) для Смарт-пульта бесполезны, но
    // Art-Net узел вполне может висеть на мосту виртуалки, поэтому здесь отсекаем
    // ТОЛЬКО туннели: у них вещание физически невозможно.
    (c.tunnel ? skipped : usable).push({
      name: c.name,
      address: c.address,
      netmask: c.netmask,
      broadcast: directedBroadcast(c.address, c.netmask),
      tunnel: c.tunnel,
      virtual: c.virtual,
    });
  }
  return { usable, skipped };
}

// Служебная метка сокета-приёмника: он не привязан к карте, слушает все сразу.
// Нулевой символ взят намеренно: имя сетевой карты его содержать не может, поэтому
// метка гарантированно не столкнётся с настоящим ключом. Пишем ЭКРАНИРОВАННО —
// живой байт в исходнике делает файл «бинарным» для git и убивает по нему diff.
const RECEIVER_TAG = '\u0000receiver';

/**
 * Через какую карту виден узел. Ответ на общий приёмник не несёт имени карты, поэтому
 * определяем её по подсети: узел в 192.168.0.x виден через карту 192.168.0.6.
 *
 * Узел из ЧУЖОЙ подсети не совпадёт ни с одной — тогда возвращаем первую карту, через
 * которую вообще шёл опрос: это честнее, чем показать пользователю пустоту. **Но
 * сначала настоящую, а не виртуальную** (2026-09-07): порядок карт задаёт ОС, и на
 * машине с Hyper-V/VirtualBox первым идёт мост вроде `vEthernet 172.x`. Раньше это
 * было косметикой (подпись «виден через…»), а теперь по этой карте уходит команда
 * смены адреса: привязка к мосту увела бы её в чужой сегмент, узел ничего бы не
 * получил, и человек прочитал бы ложное «модель не меняет адрес по сети».
 */
function resolveNic(usable, nodeIp) {
  const list = Array.isArray(usable) ? usable : [];
  const match = list.find((n) => isSameSubnet(n.address, nodeIp, n.netmask));
  if (match) return match;
  return list.find((n) => !n.virtual) || list[0] || { address: null };
}

/** Куда слать опрос с этой карты: общее вещание + вещание своей подсети. */
function pollTargets(nic) {
  const targets = [BROADCAST_ALL];
  if (nic.broadcast && nic.broadcast !== nic.address && nic.broadcast !== BROADCAST_ALL) {
    targets.push(nic.broadcast);
  }
  return targets;
}

/**
 * Слияние ответов. Один узел отвечает несколько раз и приходит сразу на несколько
 * карт — без слияния список выглядел бы как «пять конвертеров» там, где он один.
 * Ключ — MAC (уникален и не меняется при смене адреса), IP только запасной вариант:
 * дешёвые прошивки MAC не отдают.
 *
 * ⚠️ ВЫХОДЫ НАКАПЛИВАЮТСЯ, А НЕ ЗАМЕЩАЮТСЯ (07.09.2026, живой узел iceray). Часть
 * прошивок описывает КАЖДЫЙ выход ОТДЕЛЬНЫМ пакетом ArtPollReply:
 *
 *   #1 short="Port 1"  SwOut 1 → Port-Address 1
 *   #2 short="Port 2"  SwOut 2 → Port-Address 2
 *
 * Прежняя строка `node.outputs = reply.outputs` оставляла список ПОСЛЕДНЕГО пакета,
 * поэтому двухвыходной конвертер выглядел как «1 вых. (2)», а базовым адресом
 * становился 2 вместо 1: юниверс 1 уходил на ВТОРОЙ выход, юниверс 2 — на несуществующий
 * адрес 3. Со стороны это «мастер настроил, а свет не идёт», и лечилось только ручной
 * правкой поля. Накопление даёт честные «2 вых. (1, 2)» и базу 1 — то есть юниверс 1 на
 * первый выход, юниверс 2 на второй, без единого действия человека.
 */
function mergeNode(map, reply, nic) {
  const key = reply.mac && reply.mac !== '00:00:00:00:00:00' ? `mac:${reply.mac}` : `ip:${reply.ip}`;
  const existing = map.get(key);
  const node = existing || {
    ip: reply.ip,
    mac: reply.mac || null,
    name: reply.shortName || reply.longName || '',
    longName: reply.longName || '',
    firmware: reply.firmware || null,
    portCount: reply.portCount || 0,
    outputs: reply.outputs || [],
    supportsDhcp: !!reply.supportsDhcp,
    portAddressByNetwork: !!reply.portAddressByNetwork,
    seenVia: [],
  };
  // Свежий ответ точнее: адрес мог смениться между опросами.
  node.ip = reply.ip;
  node.outputs = mergeOutputs(existing ? node.outputs : [], reply.outputs);
  // Число выходов считаем по НАКОПЛЕННОМУ списку, а не по полю пакета: у прошивок с
  // ответом-на-выход в каждом пакете стоит «1», и человек читал бы «1 вых.» у
  // двухголового конвертера.
  node.portCount = node.outputs.length || reply.portCount || 0;
  if (!node.seenVia.includes(nic.address)) node.seenVia.push(nic.address);
  map.set(key, node);
  return node;
}

/**
 * Объединить описания выходов из разных ответов одного узла.
 *
 * Ключ — Port-Address: номер порта внутри пакета (`port`) у прошивок «ответ на выход»
 * всегда 1, и по нему разные выходы схлопнулись бы в один. Одинаковый адрес на двух
 * физических выходах встречается (узел так дублирует юниверс) — для настройки это одна
 * и та же цель, поэтому схлопывание здесь верно. Порядок — по адресу: список читает
 * человек, и «1, 2» понятнее, чем очерёдность прихода пакетов по сети.
 */
function mergeOutputs(current, incoming) {
  const byAddress = new Map();
  for (const list of [current || [], incoming || []]) {
    for (const out of list) {
      if (!out || typeof out.portAddress !== 'number') continue;
      byAddress.set(out.portAddress, out);
    }
  }
  return Array.from(byAddress.values()).sort((a, b) => a.portAddress - b.portAddress);
}

/**
 * Дойдёт ли до узла АДРЕСНЫЙ кадр. Поиск слышен и через чужую подсеть: опрос уходит
 * вещанием, которое доставляется всем в сегменте. А свет и подтверждение связи идут
 * по адресу узла — и вот они требуют нашей карты в ЕГО подсети, иначе пакет уйдёт на
 * шлюз (при активном VPN — в туннель) и до конвертера не доберётся.
 *
 * Признак нужен интерфейсу: «нашли, но подключаться нельзя» — единственный случай,
 * когда зелёный статус врал бы человеку в лицо (живой разбор 07.09.2026, узел на
 * заводском 2.0.0.200 при ПК в 192.168.0.x).
 */
function isNodeAddressable(usable, nodeIp) {
  if (!nodeIp) return false;
  return (usable || []).some((n) => n && n.address && isSameSubnet(n.address, nodeIp, n.netmask));
}

/** Базовые адреса выходов — то, что пользователь вписывает как «Юниверс №1». */
function primaryPortAddress(node) {
  if (!node || !node.outputs || !node.outputs.length) return 0;
  return node.outputs.reduce((min, o) => Math.min(min, o.portAddress), node.outputs[0].portAddress);
}

class ArtNetDiscovery {
  /**
   * @param {object} deps — подмена для тестов: фабрика сокетов и снимок интерфейсов.
   */
  constructor(deps = {}) {
    this.createSocket = deps.createSocket || ((opts) => dgram.createSocket(opts));
    this.interfaces = deps.interfaces || null;
    this.localAddresses = deps.localAddresses || null;
    // Уже открытый приёмник 6454 рабочего транспорта. Когда он есть, своего НЕ заводим:
    // две привязки к одному порту на Windows растаскивают ответы (аудит 2026-09-05).
    // Сокет чужой — закрывать его нельзя, только отписаться.
    this.attachReceiver = deps.attachReceiver || null;
    this._cancelled = false;
    this._sockets = [];
    this._sharedReceiver = null;
    this._sharedHandler = null;
  }

  cancel() {
    this._cancelled = true;
    this._closeAll();
  }

  _closeAll() {
    for (const sock of this._sockets) {
      try { sock.close(); } catch (e) { /* уже закрыт */ }
    }
    this._sockets = [];
    // Общий приёмник транспорта закрывать НЕЛЬЗЯ — он продолжает подтверждать узел и
    // наблюдать за чужими источниками. Снимаем только свою подписку.
    if (this._sharedReceiver && this._sharedHandler) {
      try { this._sharedReceiver.removeListener('message', this._sharedHandler); } catch (e) { /* сокет закрыт */ }
    }
    this._sharedReceiver = null;
    this._sharedHandler = null;
  }

  /**
   * Подписаться на приёмник рабочего транспорта вместо своего сокета на 6454.
   *
   * Обработчик ДОБАВЛЯЕТСЯ: на том же сокете уже висят подтверждение узла и наблюдение
   * за чужими источниками, и они обязаны продолжать работать во время поиска.
   */
  _useSharedReceiver(onMessage, errors) {
    const sock = this.attachReceiver;
    if (!sock || typeof sock.on !== 'function') {
      errors.push({ reason: 'receiver-shared: сокет транспорта недоступен' });
      return null;
    }
    this._sharedReceiver = sock;
    this._sharedHandler = (msg, rinfo) => onMessage(msg, rinfo, { address: RECEIVER_TAG });
    sock.on('message', this._sharedHandler);
    return sock;
  }

  /**
   * Опросить сеть. Никогда не бросает.
   * @returns {Promise<{nodes: Array, interfaces: Array, skipped: Array, errors: Array, cancelled: boolean, outcome: 'found'|'empty-success'|'failed'|'cancelled'}>}
   */
  async discover({ timeoutMs = DEFAULT_TIMEOUT_MS, attempts = DEFAULT_ATTEMPTS } = {}) {
    const { usable, skipped } = selectInterfaces(this.interfaces);
    const locals = this.localAddresses || localIpv4Addresses(this.interfaces);
    const found = new Map();
    const errors = [];
    this._cancelled = false;

    if (!usable.length) {
      return {
        nodes: [], interfaces: [], skipped,
        errors: [{ reason: 'no-usable-interface' }],
        cancelled: false,
        outcome: 'failed',
      };
    }

    const onMessage = (msg, rinfo, nic) => {
      try {
        const reply = parseArtPollReply(msg, rinfo);
        if (!reply || isOwnArtPollReply(reply, locals)) return;
        // Ответ чаще приходит на общий приёмник, а не на сокет конкретной карты.
        // Подставляем карту по подсети отправителя: пользователю нужно понятное
        // «узел виден через Ethernet», а не служебное имя сокета.
        mergeNode(found, reply, nic.address === RECEIVER_TAG ? resolveNic(usable, reply.ip) : nic);
      } catch (e) { /* чужой мусор на 6454 не должен ломать поиск */ }
    };

    // Приёмник на штатном порту: узлы отвечают на 6454 независимо от того, с какого
    // порта пришёл запрос. reuseAddr обязателен — порт может держать чужая световая
    // программа.
    //
    // НО если 6454 держит НАШ ЖЕ рабочий транспорт, второй сокет на тот же порт
    // открывать нельзя (аудит 2026-09-05): на Windows при дублирующей привязке с
    // SO_REUSEADDR адресные пакеты достаются сокету, привязанному ПОСЛЕДНИМ, — то есть
    // на все три секунды поиска рабочий приёмник слеп. Цена: `probeNode()` отвечает
    // «узел не подтверждён» и человек получает подсказку про IP ровно в тот момент,
    // когда всё исправно, а наблюдение за чужими источниками в это время ничего не
    // видит. Поэтому транспорт отдаёт свой УЖЕ ОТКРЫТЫЙ сокет (DmxManager передаёт его
    // в `attachReceiver`), и мы просто подписываемся на него, не закрывая по окончании.
    const receiver = this.attachReceiver
      ? this._useSharedReceiver(onMessage, errors)
      : await this._bindReceiver(onMessage, errors);
    // Отправители: по одному на карту, каждый привязан к её адресу.
    const senders = [];
    for (const nic of usable) {
      const sock = await this._bindSender(nic, onMessage, errors);
      if (sock) senders.push({ nic, sock });
    }

    if (!senders.length) {
      this._closeAll();
      return {
        nodes: [], interfaces: usable, skipped, errors,
        cancelled: this._cancelled,
        outcome: this._cancelled ? 'cancelled' : 'failed',
      };
    }

    const gap = Math.max(200, Math.floor(timeoutMs / Math.max(1, attempts)));
    let successfulPolls = 0;
    for (let i = 0; i < attempts && !this._cancelled; i++) {
      const sends = [];
      for (const { nic, sock } of senders) {
        for (const target of pollTargets(nic)) {
          // Пустой список можно считать фактом о сети только если ОС действительно
          // приняла хотя бы один ArtPoll. `send()` не бросает большинство UDP-ошибок:
          // они приходят в callback, поэтому одного факта вызова здесь недостаточно.
          sends.push(this._sendPoll(sock, nic, target, errors, gap));
        }
      }
      const sent = await Promise.all(sends);
      successfulPolls += sent.filter(Boolean).length;
      await this._sleep(gap);
    }

    this._closeAll();
    if (receiver) { /* свой закрыт вместе со всеми; общий — только отписан */ }

    const nodes = Array.from(found.values()).map((n) => ({
      ...n,
      portAddress: primaryPortAddress(n),
      // Узел ответил — но это ещё не значит, что до него дойдёт свет (см. isNodeAddressable).
      addressable: isNodeAddressable(usable, n.ip),
    }));
    nodes.sort((a, b) => String(a.ip).localeCompare(String(b.ip), 'en', { numeric: true }));
    // ВАЖНО: `errors.length > 0` само по себе не означает полный отказ — одна
    // виртуальная карта может ошибиться, а настоящая успешно опросить сегмент. Для
    // честной пустоты нужны (1) рабочий приёмник 6454 и (2) хотя бы одна успешная
    // отправка. Без любого из них «0 узлов» ничего не доказывает и не даёт мастеру
    // права переписывать рабочий вывод на слепое вещание.
    const outcome = this._cancelled
      ? 'cancelled'
      : nodes.length
        ? 'found'
        : receiver && successfulPolls > 0
          ? 'empty-success'
          : 'failed';
    return { nodes, interfaces: usable, skipped, errors, cancelled: this._cancelled, outcome };
  }

  /**
   * Отправить один ArtPoll и дождаться подтверждения от ОС.
   *
   * Таймаут здесь fail-closed: если callback сокета потерялся, мастер не получает
   * права считать пустой результат обследованием сети. В норме callback приходит за
   * миллисекунды; предел равен интервалу между попытками и не удлиняет обычный поиск.
   */
  _sendPoll(sock, nic, target, errors, timeoutMs) {
    return new Promise((resolve) => {
      let settled = false;
      const done = (ok) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(ok);
      };
      const timer = setTimeout(() => {
        errors.push({ nic: nic.address, target, reason: 'send-timeout' });
        done(false);
      }, Math.max(200, timeoutMs));
      if (typeof timer.unref === 'function') timer.unref();
      try {
        sock.send(buildArtPollPacket(), ART_NET_PORT, target, (err) => {
          // Колбэк обязателен: без него dgram эмитит ошибку событием на сокете.
          if (err) {
            errors.push({ nic: nic.address, target, reason: err.message });
            done(false);
            return;
          }
          done(true);
        });
      } catch (e) {
        errors.push({ nic: nic.address, target, reason: e.message });
        done(false);
      }
    });
  }

  _sleep(ms) {
    return new Promise((resolve) => {
      const t = setTimeout(resolve, ms);
      if (typeof t.unref === 'function') t.unref();
    });
  }

  _bindReceiver(onMessage, errors) {
    return new Promise((resolve) => {
      let sock;
      try {
        sock = this.createSocket({ type: 'udp4', reuseAddr: true });
      } catch (e) {
        errors.push({ reason: `receiver-create: ${e.message}` });
        return resolve(null);
      }
      let settled = false;
      const done = (value) => { if (!settled) { settled = true; resolve(value); } };
      sock.on('error', (err) => {
        errors.push({ reason: `receiver: ${err.message}` });
        try { sock.close(); } catch (e) { /* уже закрыт */ }
        done(null);
      });
      sock.on('message', (msg, rinfo) => onMessage(msg, rinfo, { address: RECEIVER_TAG }));
      try {
        sock.bind({ port: ART_NET_PORT, address: '0.0.0.0' }, () => {
          try { sock.setBroadcast(true); } catch (e) { /* не критично */ }
          this._sockets.push(sock);
          done(sock);
        });
      } catch (e) {
        errors.push({ reason: `receiver-bind: ${e.message}` });
        done(null);
      }
    });
  }

  _bindSender(nic, onMessage, errors) {
    return new Promise((resolve) => {
      let sock;
      try {
        sock = this.createSocket({ type: 'udp4', reuseAddr: true });
      } catch (e) {
        errors.push({ nic: nic.address, reason: `sender-create: ${e.message}` });
        return resolve(null);
      }
      let settled = false;
      const done = (value) => { if (!settled) { settled = true; resolve(value); } };
      sock.on('error', (err) => {
        errors.push({ nic: nic.address, reason: `sender: ${err.message}` });
        try { sock.close(); } catch (e) { /* уже закрыт */ }
        done(null);
      });
      // Часть узлов отвечает на порт-источник, а не на 6454 — слушаем и здесь.
      sock.on('message', (msg, rinfo) => onMessage(msg, rinfo, nic));
      try {
        // Порт 0 = любой свободный; адрес карты — то, ради чего всё затевалось.
        sock.bind({ port: 0, address: nic.address }, () => {
          try { sock.setBroadcast(true); } catch (e) { /* не критично */ }
          this._sockets.push(sock);
          done(sock);
        });
      } catch (e) {
        errors.push({ nic: nic.address, reason: `sender-bind: ${e.message}` });
        done(null);
      }
    });
  }
}

module.exports = ArtNetDiscovery;
module.exports.selectInterfaces = selectInterfaces;
module.exports.pollTargets = pollTargets;
module.exports.mergeNode = mergeNode;
module.exports.primaryPortAddress = primaryPortAddress;
module.exports.isNodeAddressable = isNodeAddressable;
module.exports.mergeOutputs = mergeOutputs;
module.exports.resolveNic = resolveNic;
module.exports.DEFAULT_TIMEOUT_MS = DEFAULT_TIMEOUT_MS;
module.exports.BROADCAST_ALL = BROADCAST_ALL;
