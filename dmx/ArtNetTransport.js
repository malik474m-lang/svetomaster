const dgram = require('dgram');
const os = require('os');
const dmxnet = require('dmxnet');
const BaseDmxTransport = require('./BaseDmxTransport');
const ArtDmxSender = require('./artnet/ArtDmxSender');
const { listCandidates } = require('../main/remote/remoteNet');

/**
 * АВАРИЙНЫЙ ОТКАТ на прежний путь через dmxnet (2026-09-02, блок D).
 *
 * Собственный отправитель заменяет библиотеку в самом ответственном месте — выводе
 * света. Если в поле вскроется что-то, чего не поймали тесты, у пользователя должен
 * остаться способ вернуть прежнее поведение БЕЗ отката версии: переменная окружения
 * `SVETO_ARTNET_LEGACY=1`. Прецедент такого флага в проекте уже есть —
 * `SVETO_UDMX_PORT_RESET=1` (UDMX-006). Флаг живёт один релиз: как только полевая
 * проверка подтвердит новый путь, вместе с ним уходит и зависимость dmxnet.
 */
function legacyArtNetEnabled() {
  return process.env.SVETO_ARTNET_LEGACY === '1';
}

// ARTNET-002: steady 40 Hz refresh (DMX standard is ~44 Hz). dmxnet's default
// base_refresh_interval is 1000 ms (1 Hz) — so when the renderer RAF is throttled
// (OS throttles it to ~1 Hz while the window is minimized) Art-Net output dropped
// to 1 Hz, causing visible stepping / node timeouts. See constructor + send().
const ART_NET_REFRESH_MS = 25; // 1000 / 25 = 40 Hz

// Art-Net addressing is a single 15-bit Port-Address split across three fields:
// net (7 bits) : subnet (4 bits) : universe (4 bits). dmxnet validates each field
// separately and THROWS ("Invalid Universe, must be smaller than 16") on universe > 15.
//
// The settings field offers 0..32767 — i.e. the whole Port-Address — so every value
// above 15 used to crash the connection (seen in client-health as artnet /
// "Invalid Universe, must be smaller than 16"). Rather than shrinking the field to
// 0..15 (which would drop addressing the user was already promised), the entered
// number is treated as the full Port-Address and split into the three wire fields.
// This is ONE mechanism shared with the multi-universe offset below, so there is no
// separate special case for "large" values.
const ART_NET_MAX_PORT_ADDRESS = 32767; // 0x7FFF — net 7 bits | subnet 4 | universe 4

function clampInt(value, min, max) {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, n));
}

/**
 * Full Port-Address for the device's BASE address (logical universe 1). `universe`
 * carries the whole address; `net`/`subnet`, when present, stay meaningful as an
 * additional base offset, so existing device descriptors keep their exact wire address.
 */
function artNetPortAddress(deviceInfo = {}) {
  return Math.min(
    ART_NET_MAX_PORT_ADDRESS,
    (clampInt(deviceInfo.net, 0, 127) << 8)
      + (clampInt(deviceInfo.subnet, 0, 15) << 4)
      + clampInt(deviceInfo.universe, 0, ART_NET_MAX_PORT_ADDRESS),
  );
}

/** Port-Address → the three fields dmxnet accepts (each already inside its range). */
function splitPortAddress(portAddress) {
  const value = clampInt(portAddress, 0, ART_NET_MAX_PORT_ADDRESS);
  return {
    net: (value >> 8) & 0x7F,
    subnet: (value >> 4) & 0x0F,
    universe: value & 0x0F,
  };
}

// Pure builder for the dmxnet sender options (exported for unit tests). Keeps the
// 40 Hz refresh and address defaults in one testable place.
function buildArtNetSenderOptions(deviceInfo) {
  return {
    ip: deviceInfo.ip || '255.255.255.255',
    ...splitPortAddress(artNetPortAddress(deviceInfo)),
    base_refresh_interval: ART_NET_REFRESH_MS,
  };
}

// dmxnet's own UDP error handling is fatal by design: lib.js re-THROWS inside the
// receive socket's 'error' callback, and the send socket has no 'error' handler at
// all — so a busy port 6454 or missing UDP permission became an uncaughtException
// in the main process (seen in client-health as "Socket error:"). Replace/attach
// our handlers so a socket error degrades into a normal transport loss instead of
// a process-level crash. Exported for unit tests; dmxnet itself is not patched.
function attachDmxnetSocketGuards(target, onError) {
  // Works for the dmxnet instance (listener4 + shared socket) AND for a sender
  // (each newSender() creates its OWN dgram socket, lib.js:377, with no 'error'
  // handler either). onError receives (err, sock) so the caller can decide
  // per-socket cleanup.
  const sockets = [target && target.listener4, target && target.socket];
  for (const sock of sockets) {
    if (!sock || typeof sock.on !== 'function') continue;
    try { sock.removeAllListeners('error'); } catch (e) { /* keep attaching */ }
    sock.on('error', (err) => {
      try { onError(err, sock); } catch (e) { /* guard must never throw into dgram */ }
    });
    swallowDmxnetSendErrors(sock);
  }
}

// ARTNET-003 (2026-08-22): the 'error' guard above is NOT enough, because dmxnet also
// throws from INSIDE the dgram.send() callback — `if (err) throw err` in transmit()
// (lib.js:424) and twice in ArtPollReply() (lib.js:215, 260). A throw there is not a
// socket 'error' event, so no listener can intercept it: it surfaces as a main-process
// uncaughtException. The only interception point is send() itself — we replace it with
// a wrapper that installs OUR callback, so dmxnet's throwing callback never runs.
//
// A failed SEND deliberately does NOT tear the transport down. Art-Net is UDP: delivery
// was never guaranteed, and a one-off EADDRNOTAVAIL (interface disappeared, loopback with
// no usable broadcast) is not a lost transport — a genuinely unplugged cable is invisible
// over UDP anyway (see ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md §6). Reporting is throttled
// to the first failure per socket: transmit runs at 40 Hz and would otherwise flood the log.
function swallowDmxnetSendErrors(sock) {
  if (!sock || typeof sock.send !== 'function' || sock.__svmSendGuarded) return;
  const originalSend = sock.send.bind(sock);
  let reported = 0;
  sock.send = function guardedSend(...args) {
    // dgram.send accepts an optional trailing callback in every overload; dropping
    // dmxnet's callback costs only its own debug logging.
    if (args.length && typeof args[args.length - 1] === 'function') args.pop();
    return originalSend(...args, (err) => {
      if (!err) return;
      reported += 1;
      if (reported === 1) {
        console.log('⚠️ Art-Net: ошибка отправки UDP (подключение сохранено):', err.message);
      }
    });
  };
  sock.__svmSendGuarded = true;
}

/**
 * ARTNET-003: dmxnet answers EVERY incoming ArtPoll — including the one our own
 * probeNode() broadcasts — by sending an ArtPollReply to the broadcast address of
 * EVERY OS interface (lib.js:163). For loopback that address is 127.255.255.255, and
 * for a /32 adapter (the usual VPN shape) the netmask library yields no broadcast at
 * all; both sends fail with EADDRNOTAVAIL. Dropping those entries removes the cause
 * rather than only muffling the symptom.
 *
 * Safe by inspection: `ip4` is read nowhere else in dmxnet (lib.js:57, 65, 75, 163),
 * so this affects the ArtPollReply fan-out and nothing else — never the DMX output.
 * Returns how many entries were dropped (for logging/tests).
 */
function sanitizeArtPollReplyTargets(instance) {
  if (!instance || !Array.isArray(instance.ip4)) return 0;
  const before = instance.ip4.length;
  instance.ip4 = instance.ip4.filter((entry) => {
    if (!entry) return false;
    const broadcast = typeof entry.broadcast === 'string' ? entry.broadcast : '';
    if (!broadcast) return false;                  // /32 adapter — nowhere to send
    if (/^127\./.test(broadcast)) return false;    // loopback
    if (/^127\./.test(String(entry.ip || ''))) return false;
    return true;
  });
  return before - instance.ip4.length;
}

// MULTI-UNIVERSE: sender options for a given logical universe (1-based). Logical 1 =
// the base address from deviceInfo; logical N shifts the Art-Net Port-Address by
// (N − 1) and is split back into net/subnet/universe, so the carry crosses all three
// fields correctly instead of only subnet.
function senderOptionsForUniverse(deviceInfo, logicalUniverse) {
  const base = buildArtNetSenderOptions(deviceInfo);
  const offset = Math.max(1, Math.floor(logicalUniverse) || 1) - 1;
  if (offset === 0) return base;
  return {
    ...base,
    ...splitPortAddress(portAddressForUniverse(deviceInfo, logicalUniverse)),
  };
}

/**
 * Полный Port-Address логического юниверса (1-based) — ТО ЖЕ САМОЕ число, которое
 * выше раскладывается на net/subnet/universe для dmxnet. Свой отправитель пишет адрес
 * в пакет целиком, поэтому ему нужно число, а не три поля. Механизм один на оба
 * пути: разойдись они — мультиюниверс поехал бы на разные адреса в зависимости от флага.
 */
function portAddressForUniverse(deviceInfo, logicalUniverse) {
  const offset = Math.max(1, Math.floor(logicalUniverse) || 1) - 1;
  return clampInt(artNetPortAddress(deviceInfo) + offset, 0, ART_NET_MAX_PORT_ADDRESS);
}

/**
 * Влезает ли логический юниверс в 15-битное адресное пространство Art-Net.
 *
 * Адреса больше 0x7FFF не существует, поэтому клэмп выше СХЛОПЫВАЕТ верхние юниверсы в
 * один адрес: при базе 32760 логические 8, 9 и 10 получают один и тот же 32767 и
 * начинают затирать кадры друг друга 40 раз в секунду — на приборах это выглядит как
 * «юниверс живёт своей жизнью» (аудит 2026-09-05). Молчание в несуществующий юниверс
 * честнее тихой порчи соседнего, поэтому вывод такого юниверса блокируется.
 */
function universeFitsPortAddress(deviceInfo, logicalUniverse) {
  const offset = Math.max(1, Math.floor(logicalUniverse) || 1) - 1;
  return artNetPortAddress(deviceInfo) + offset <= ART_NET_MAX_PORT_ADDRESS;
}

/**
 * Создать экземпляр dmxnet, ЗАПОМНИВ таймеры, которые он завёл (аудит 2026-09-05).
 *
 * Конструктор библиотеки вешает `setInterval(…, 30000)` («проверить, живы ли
 * контроллеры») и НЕ сохраняет его идентификатор (lib.js:116), а метода закрытия у
 * экземпляра нет вовсе — снять таймер снаружи было физически нечем, и после каждого
 * переподключения в главном процессе оставался лишний таймер, вечно держащий брошенный
 * экземпляр. Конструктор синхронный, поэтому подмена глобального `setInterval` ровно на
 * время вызова безопасна: между подменой и восстановлением чужой код не исполняется.
 * Саму библиотеку по-прежнему не патчим — фиксируем её побочный эффект.
 */
function createDmxnetInstance(options) {
  const timers = [];
  const original = global.setInterval;
  global.setInterval = function capturingSetInterval(...args) {
    const id = original.apply(this, args);
    timers.push(id);
    return id;
  };
  try {
    return { instance: new dmxnet.dmxnet(options), timers };
  } catch (err) {
    clearDmxnetTimers(timers);
    throw err;
  } finally {
    global.setInterval = original;
  }
}

function clearDmxnetTimers(timers) {
  for (const id of timers || []) {
    try { clearInterval(id); } catch (e) { /* уже снят */ }
  }
}

/**
 * Разрешить широковещание на сокете, который может быть ещё не привязан.
 *
 * `setBroadcast()` требует привязанного сокета, а dmxnet при нешироковещательной (по
 * ЕГО мнению) цели не привязывает свой сокет вовсе — первая `send()` делает это неявно
 * и асинхронно. Поэтому: привязан — ставим сразу, иначе ждём 'listening'.
 */
function enableBroadcastWhenBound(sock) {
  if (!sock || typeof sock.setBroadcast !== 'function') return;
  const apply = () => { try { sock.setBroadcast(true); } catch (e) { /* ещё не привязан / уже закрыт */ } };
  // Три случая, и путать их нельзя: привязан (ставим сразу), НЕ привязан (ждём
  // 'listening' — до него вызов только бросил бы), состояние узнать нечем (пробуем
  // сразу И подписываемся: лишний вызов безвреден, а пропущенное разрешение означает
  // отсутствие света).
  const knowable = typeof sock.address === 'function';
  let bound = false;
  if (knowable) { try { bound = !!sock.address(); } catch (e) { bound = false; } }
  if (bound || !knowable) apply();
  if (!bound && typeof sock.once === 'function') sock.once('listening', apply);
}

// ─────────────────────────────────────────────────────────────────────────────
// ArtPoll / ArtPollReply — единственный способ узнать, что на том конце кто-то ЕСТЬ
// ─────────────────────────────────────────────────────────────────────────────
//
// Зачем (2026-08-22). Открытие сетевого транспорта — это всего лишь UDP-сокет у ОС:
// оно удаётся и при неверном IP, и когда узла в сети нет вовсе. Поэтому «подключился»
// само по себе ничего не доказывало ни пользователю, ни отчёту «Интерфейсы».
// Art-Net (в отличие от sACN) предусматривает опрос: контроллер шлёт ArtPoll, а КАЖДЫЙ
// узел обязан ответить ArtPollReply. Ответ — единственное объективное подтверждение,
// что кадры уходят не в пустоту.
//
// Опрос НИЧЕГО не решает за пользователя: свет отправляется в любом случае. Часть
// дешёвых узлов ArtPoll игнорирует, брандмауэр может резать входящий UDP 6454 — это
// повод сказать «не подтверждено», но не повод рвать рабочее подключение.
// Сборка и разбор пакетов вынесены в общий протокольный модуль (2026-08-22): те же
// функции нужны мастеру настройки ДО подключения, когда транспорта ещё нет. Здесь
// остаются только тайминги опроса — они относятся к поведению транспорта, не к байтам.
const {
  ART_NET_PORT,
  buildArtPollPacket,
  parseArtDmx,
  parseArtPollReply,
  isOwnArtPollReply,
  localIpv4Addresses,
} = require('./artnet/artnetPackets');
const { createForeignSourceWatch } = require('./artnet/foreignSourceWatch');

// Дефолты опроса: один ответ приходит за единицы миллисекунд, но пакет может пропасть
// (UDP), а узел — тормозить. Два запроса за 2,5 с покрывают это и не задерживают ничего:
// опрос идёт в стороне от вывода света.
const ART_POLL_TIMEOUT_MS = 2500;
const ART_POLL_RETRY_MS = 800;

/**
 * Ответил ли ИМЕННО тот узел, которому адресован опрос (2026-09-05).
 *
 * Слушаем ОБЩИЙ сокет 6454, поэтому сюда попадает и ответ на ЧУЖОЙ опрос — от соседнего
 * узла, к нашему свету отношения не имеющего. Засчитывать его значило бы подтверждать
 * связь с устройством, которого мы даже не спрашивали.
 * При вещании адресата нет — сверять не с чем: отвечать вправе любой узел сегмента, и
 * это штатный режим (заводской адрес узла часто лежит в чужой подсети, §6 справочника).
 */
function artPollReplyFromTarget(reply, target, broadcast) {
  if (broadcast) return true;
  return !!reply && (reply.ip === target || reply.from === target);
}

/**
 * Слушает ли узел ТОТ Port-Address, в который мы шлём кадры.
 *
 * Судим только когда узел сам перечислил порты: короткий ответ (нестандартная прошивка)
 * и узел без портов не наказываем — «не сообщил» не равно «не слушает». Зато когда порты
 * названы, а нашего адреса среди них нет, это ровно тот случай «конвертер подключён,
 * индикаторы горят, а света нет», который иначе ищут весь вечер.
 *
 * НАПРАВЛЕНИЕ ПОРТА НЕ УЧИТЫВАЕТСЯ, и это принципиально. Живой PKNIGHT CR021R объявляет
 * свои физические ВЫХОДЫ как входы (`PortType = 0x80`, см. предупреждение в
 * artnet/artnetPackets.js и фикстуру `buildCr021rReply` в тестах), поэтому фильтр по
 * `isOutput` выбрасывал у него ВСЕ порты — и проверка адреса молча отключалась ровно на
 * том узле, ради которого затевалась. Port-Address и так отвечает на нужный вопрос:
 * какие пакеты узел вообще принимает. Совпал хоть с одним объявленным портом — свет
 * дойдёт; не совпал ни с одним — не дойдёт, как бы узел ни маркировал направление.
 */
function artPollReplyServesPortAddress(reply, portAddress) {
  const ports = Array.isArray(reply && reply.outputs) ? reply.outputs : [];
  if (ports.length === 0) return true;
  return ports.some((port) => port && port.portAddress === portAddress);
}

class ArtNetTransport extends BaseDmxTransport {
  /**
   * @param {object} deviceInfo дескриптор устройства (адрес узла, юниверс, bindAddress)
   * @param {object} deps подмена для тестов — фабрика сокетов и снимок сетевых карт.
   *   Тот же приём, что у `ArtNetDiscovery` и `artnetEnvDiag`: весь путь вывода
   *   проверяется без единого настоящего сокета. В бою deps всегда пуст.
   */
  constructor(deviceInfo, deps = {}) {
    super(deviceInfo);
    this._deps = deps || {};
    this.dmxnetInstance = null;
    // Таймеры, которые завёл конструктор dmxnet: снять их иначе нечем (см.
    // createDmxnetInstance), а close() обязан не оставлять фоновой активности.
    this._dmxnetTimers = null;
    // Юниверсы, не влезшие в 15-битный адрес: предупреждаем по одному разу на юниверс,
    // а не 40 раз в секунду.
    this._overflowWarned = new Set();
    this.sender = null;
    // Свой отправитель (блок D). Пока он есть — вывод идёт через него; `dmxnetInstance`
    // остаётся только у аварийного отката SVETO_ARTNET_LEGACY=1. Ветвление идёт по
    // ФАКТУ существования объекта, а не по флагу: так каждый путь проверяем отдельно.
    this.artDmx = null;
    // Приёмник на 6454: подтверждение узла (ArtPollReply) и наблюдение за чужими
    // источниками. У прежнего пути эту роль играл dmxnetInstance.listener4.
    this.receiver = null;
    this._pendingSocketError = null;
    this._onSocketError = null; // set per open(); shared by base and extra senders
    // MULTI-UNIVERSE: Art-Net binds one sender per universe. `sender` is logical
    // universe 1 (the base address); extra universes get their own sender lazily on
    // first frame, each with its own dmxnet 40 Hz timer. sACN/Art-Net advertise this.
    this.supportsMultiUniverse = true;
    this.extraSenders = new Map(); // logical universe (>1) → dmxnet sender
    // ARTNET-002: Art-Net is self-clocked — dmxnet's internal sender timer
    // (base_refresh_interval) re-transmits the current buffer at a steady 40 Hz
    // from the MAIN process, independent of the renderer RAF. So send() only
    // updates the buffer (prepChannel) and never transmits; that timer is the
    // single wire clock. DmxManager bypasses its own throttle for selfClocked
    // transports (like Open DMX) — otherwise a second ~40 Hz beat would double
    // the wire rate (~80 Hz, above the Art-Net 44 Hz maximum).
    this.selfClocked = true;
    // Сетевой транспорт: открытый сокет ничего не доказывает — «работает» вправе
    // утверждать только ответ узла на ArtPoll (см. probeNode ниже).
    this.requiresNodeConfirmation = true;
    // Чем подтверждается кадр в счётчиках отчёта (2026-09-11). Свой отправитель
    // знает, принял ли ядро пакет к отправке; у аварийного отката на dmxnet провод
    // тактует чужая библиотека, и доказать мы можем лишь «кадр положен в её буфер».
    this.transferConfirmation = legacyArtNetEnabled() ? 'buffer' : 'socket';
    // Чужие источники света в сети (HTP-мерж на узле). Наблюдение включается в open()
    // и живёт на том же сокете, что и опрос узлов, — второй сокет на 6454 не открываем.
    this.foreignWatch = null;
    this._onForeignMessage = null;
    // DmxManager вешает сюда обработчик, как на onDisconnect: транспорт сообщает о
    // ПЕРВОМ конфликтном источнике, а не о каждом кадре 40 раз в секунду.
    this.onForeignSource = null;
  }

  static scan() {
    return [{
      id: 'artnet',
      type: 'artnet',
      name: 'Art-Net (UDP)',
      ip: '255.255.255.255',
      subnet: 0,
      universe: 0,
      port: 6454
    }];
  }

  async open() {
    // DMX-001: idempotent — close any existing sender before opening a new one.
    // DmxManager always creates a fresh instance per connect(), so this guard is
    // defensive; it prevents a double-open from leaking the UDP socket if the call
    // pattern ever changes.
    if (this.sender || this.artDmx) await this.close();
    return legacyArtNetEnabled() ? this._openViaDmxnet() : this._openNative();
  }

  /**
   * Открытие своим отправителем (2026-09-02, блок D) — путь по умолчанию.
   *
   * Отличия от прежнего пути ровно два, оба намеренные:
   *  • сокеты отправки привязаны к адресу сетевой карты, поэтому свет не уходит в
   *    VPN-туннель (ради этого блок и делался);
   *  • мы больше НЕ представляемся Art-Net узлом и не отвечаем на чужой ArtPoll —
   *    dmxnet делал это, и его же ответ приходилось отфильтровывать как «свой».
   *    На вывод света не влияет: отвечать положено узлам, а мы контроллер.
   */
  async _openNative() {
    try {
      this._pendingSocketError = null;
      this._onSocketError = (err, sock) => {
        const text = err && err.message ? err.message : String(err);

        // ПРИЁМНИК СВЕТ НЕ ОТПРАВЛЯЕТ (решение владельца 2026-09-02). Порт 6454 нужен
        // только для подтверждения узла и наблюдения за чужими источниками — это
        // наблюдаемость, а не вывод. Прежде его ошибка (порт занял другой пульт)
        // объявлялась потерей связи, и площадка видела «подключился — отвалился —
        // подключился» по кругу, хотя кадры уходили исправно. Теперь честно теряем
        // ровно то, что сломалось: подтверждение и наблюдение. Свет идёт дальше.
        if (sock && sock === this.receiver) {
          console.log(`⚠️ Art-Net: порт ${ART_NET_PORT} недоступен (${text}). Свет идёт, но узел не подтверждается и чужие источники в сети не видны.`);
          this._stopForeignWatch();   // слушатель на мёртвом сокете держал бы ссылки
          try { sock.close(); } catch (e) { /* already closed */ }
          this.receiver = null;
          return;
        }

        // Сокет ОТПРАВКИ — настоящая потеря связи (DMX-004). Сюда доходит только отказ
        // ПОСЛЕДНЕГО живого сокета: при вещании с двух карт отправитель сначала
        // выбрасывает сбойный и продолжает работать с оставшихся.
        this.lastError = text;
        console.log('❌ Art-Net socket error:', text);
        if (this.connected) {
          this.connected = false;
          this.notifyDisconnect('artnet-socket-error');
        } else {
          // Ошибка пришла, пока мы ещё привязывали сокеты: сообщим о ней сразу после
          // открытия, чтобы порядок событий совпал с прежним путём.
          this._pendingSocketError = text;
        }
      };

      this.receiver = this._createReceiver();

      const sender = new ArtDmxSender({
        ip: this.deviceInfo.ip || '255.255.255.255',
        // Единственная истина о частоте провода — ART_NET_REFRESH_MS, общая с прежним
        // путём: две константы такта неизбежно разъехались бы (BUG-006 про два клока).
        refreshMs: ART_NET_REFRESH_MS,
        createSocket: this._deps.createSocket || undefined,
        interfaces: this._deps.interfaces || null,
        // Выбор сетевой карты приходит из интерфейса (мастер Art-Net). Пусто —
        // отправитель решит сам: по подсети узла, иначе вещанием со всех карт.
        bindAddress: this.deviceInfo.bindAddress || null,
        onSocketError: (err, sock) => {
          if (this._onSocketError) this._onSocketError(err, sock);
        },
        // Счётчики передач для отчёта (2026-09-11): такт провода — единственное
        // место, где у Art-Net вообще есть исход кадра. До этого раздел
        // `transferTotals` у сетевых транспортов был нулевым даже при исправном
        // свете, и «поток идёт» от «молчит» отличить было нечем.
        onWireFrame: (result) => this.noteTransfer({
          success: !!result.success,
          durationMs: result.durationMs,
          error: result.error || null,
        }),
      });
      // Ссылку держим ДО await: привязка асинхронная, и close(), пришедший в это окно,
      // иначе не достал бы до отправителя — тот остался бы жив и продолжал гнать свет
      // 40 раз в секунду на закрытом подключении (класс дефектов BUG-005 / DMX-001).
      this.artDmx = sender;
      const opened = await sender.open();
      if (!opened) {
        this.artDmx = null;
        throw new Error('не удалось привязать UDP-сокет отправки');
      }
      // close() мог случиться, пока шла привязка: тогда открывать нечего.
      if (sender.closed) {
        this.artDmx = null;
        throw new Error('подключение закрыто во время открытия');
      }

      // Юниверс 1 начинает вещать сразу, ещё до первого кадра из окна: узел держит
      // последнее состояние и ждёт ровного потока. Прежний путь вёл себя так же —
      // dmxnet транслировал с момента создания sender'а (lib.js:389).
      sender.ensureUniverse(portAddressForUniverse(this.deviceInfo, 1));

      if (this.receiver) this._startForeignWatch(this.receiver);

      this.connected = true;
      this.lastError = null;
      const via = sender.boundAddresses().join(', ') || '0.0.0.0';
      console.log(`✅ Art-Net подключен: ${this.deviceInfo.ip || 'broadcast'} (карта ${via})`);

      if (this._pendingSocketError) {
        const text = this._pendingSocketError;
        this._pendingSocketError = null;
        // dmxnet сообщал о занятом порте уже ПОСЛЕ успешного open() (привязка
        // асинхронная). Сохраняем тот же порядок: сначала «подключились», потом
        // штатная потеря связи (DMX-004) — иначе DmxManager получил бы разрыв
        // раньше, чем узнал о подключении.
        setImmediate(() => {
          if (!this.connected) return;
          this.lastError = text;
          this.connected = false;
          this.notifyDisconnect('artnet-socket-error');
        });
      }
      return true;
    } catch (err) {
      this._stopForeignWatch();
      if (this.artDmx) { try { this.artDmx.close(); } catch (e) { /* ignore */ } }
      this.artDmx = null;
      if (this.receiver) { try { this.receiver.close(); } catch (e) { /* ignore */ } }
      this.receiver = null;
      this.lastError = err.message;
      this.connected = false;
      console.log('❌ Art-Net ошибка:', err.message);
      return false;
    }
  }

  /**
   * Приёмник на штатном порту 6454. К выводу света отношения не имеет, но без него
   * невозможны две вещи: подтверждение узла (ArtPollReply приходит на 6454 независимо
   * от порта запроса) и наблюдение за чужими источниками. `reuseAddr` — как у dmxnet:
   * порт может держать другая световая программа, и это не повод не работать.
   *
   * Привязка асинхронная СОЗНАТЕЛЬНО: занятый порт всплывает событием 'error' через
   * мгновение — ровно как у dmxnet (lib.js:107), поэтому путь потери связи не меняется.
   */
  _createReceiver() {
    let socket;
    try {
      const create = this._deps.createSocket || ((opts) => dgram.createSocket(opts));
      socket = create({ type: 'udp4', reuseAddr: true });
    } catch (e) {
      return null;
    }
    socket.on('error', (err) => {
      if (this._onSocketError) {
        try { this._onSocketError(err, socket); } catch (e) { /* guard must never throw into dgram */ }
      }
    });
    try {
      socket.bind({ port: ART_NET_PORT, address: '0.0.0.0' });
    } catch (e) {
      try { socket.close(); } catch (e2) { /* already closed */ }
      return null;
    }
    return socket;
  }

  /** Прежний путь через библиотеку dmxnet — только под SVETO_ARTNET_LEGACY=1. */
  async _openViaDmxnet() {
    try {
      // Таймеры конструктора запоминаем сразу: снять их иначе нечем, а close() обязан
      // погасить экземпляр целиком (см. _closeDmxnetInstance).
      const created = createDmxnetInstance({
        log: { level: 'error' },
        oem: 0,
        sName: 'SvetoMaster',
        lName: 'SvetoMaster AI DMX Controller'
      });
      this.dmxnetInstance = created.instance;
      this._dmxnetTimers = created.timers;

      // ARTNET-003: strip interfaces whose ArtPollReply fan-out can only fail, BEFORE
      // newSender() — that call triggers the first ArtPollReply (lib.js:140).
      const dropped = sanitizeArtPollReplyTargets(this.dmxnetInstance);
      if (dropped > 0) {
        console.log(`ℹ️ Art-Net: из рассылки ArtPollReply исключено интерфейсов: ${dropped}`);
      }

      // The listener binds port 6454 asynchronously AFTER the constructor returns,
      // so a busy port surfaces as a socket 'error' event moments later — route it
      // through the standard unexpected-disconnect flow (DMX-004), like serial-error
      // does for FTDI transports, instead of letting dmxnet crash the process.
      const listener = this.dmxnetInstance.listener4;
      this._onSocketError = (err, sock) => {
        const text = err && err.message ? err.message : String(err);
        this.lastError = text;
        console.log('❌ Art-Net socket error:', text);
        // A listener whose bind failed (busy 6454) is dead weight — close it so the
        // auto-reconnect loop does not accumulate half-open handles. Sender sockets
        // are deliberately NOT closed here: dmxnet's 40 Hz transmit timer would then
        // throw on a closed socket before DmxManager tears the transport down.
        if (sock === listener) { try { sock.close(); } catch (e) { /* already closed */ } }
        if (this.connected) {
          this.connected = false;
          this.notifyDisconnect('artnet-socket-error');
        }
      };
      attachDmxnetSocketGuards(this.dmxnetInstance, this._onSocketError);

      this.sender = this.dmxnetInstance.newSender(buildArtNetSenderOptions(this.deviceInfo));
      attachDmxnetSocketGuards(this.sender, this._onSocketError);

      // dmxnet включает широковещание на сокете отправителя ТОЛЬКО если последний октет
      // цели равен 255 (lib.js:519). Направленное вещание сети /25 — это `.127`, и такой
      // сокет разрешения не получал: ядро отвечало EACCES на КАЖДУЮ отправку, наш гвард
      // писал одну строку в лог и глушил остальные, а человек видел «подключено» без
      // света (аудит 2026-09-05). Свой отправитель считает broadcast правильно с
      // рождения — здесь дотягиваем до него аварийный путь.
      if (this._isBroadcastTarget(this.deviceInfo.ip || '255.255.255.255')) {
        enableBroadcastWhenBound(this.sender.socket);
      }

      this._startForeignWatch(listener);

      this.connected = true;
      this.lastError = null;
      console.log(`✅ Art-Net подключен: ${this.deviceInfo.ip || 'broadcast'}`);
      return true;
    } catch (err) {
      // DMX-001: экземпляр dmxnet гасим ПОЛНОСТЬЮ, а не просто обнуляем ссылку —
      // его сокеты и таймер уже созданы конструктором, и при падении newSender()
      // (исторически — тот самый `Invalid Universe`) каждая попытка автопереподключения
      // оставляла в процессе живой listener на 6454 (аудит 2026-09-05).
      // Наблюдение за чужими источниками снимаем тем же движением: обработчик на
      // мёртвом сокете держал бы ссылку на брошенный dmxnet.
      this._stopForeignWatch();
      this.sender = null;
      this._closeDmxnetInstance();
      this.lastError = err.message;
      this.connected = false;
      console.log('❌ Art-Net ошибка:', err.message);
      return false;
    }
  }

  /**
   * Погасить экземпляр dmxnet целиком (аудит 2026-09-05).
   *
   * Прежде `close()` только останавливал sender'ы, а сам экземпляр обнулялся ссылкой —
   * но его UDP-сокеты оставались открытыми. `listener4` продолжал держать порт 6454 и,
   * главное, ОТВЕЧАТЬ на чужой ArtPoll (lib.js:670): после N переподключений в сети
   * жило N фантомных узлов «SvetoMaster», а объём ответа на один чужой опрос рос
   * линейно (свой поиск их отфильтровывает по имени и IP, чужие контроллеры — нет).
   * Плюс оставались общий сокет отправки и 30-секундный таймер библиотеки.
   *
   * Обработчик 'message' снимаем ДО закрытия: `dataParser` отвечает на ArtPoll, и
   * пакет, пришедший между `close()` и сборкой мусора, ушёл бы от имени уже погашенного
   * подключения.
   */
  _closeDmxnetInstance() {
    const instance = this.dmxnetInstance;
    clearDmxnetTimers(this._dmxnetTimers);
    this._dmxnetTimers = null;
    this.dmxnetInstance = null;
    if (!instance) return;
    for (const sock of [instance.listener4, instance.socket]) {
      if (!sock || typeof sock.close !== 'function') continue;
      try { sock.removeAllListeners('message'); } catch (e) { /* не EventEmitter */ }
      try { sock.close(); } catch (e) { /* уже закрыт или ещё не привязан */ }
    }
    // `sender.stop()` у библиотеки НЕ удаляет отправителя из этого массива: колбэк
    // фильтра сравнивает `value === this`, а в strict-режиме `this` там `undefined`
    // (lib.js:503). Брошенный экземпляр иначе держал бы все sender'ы всех подключений.
    try { instance.senders = []; } catch (e) { /* объект заморожен */ }
  }

  /**
   * Широковещательная ли цель. Признак ТОТ ЖЕ, что у отправителя света: кроме
   * `255.255.255.255` это ещё и направленное вещание нашей подсети, у которого
   * последний октет НЕ обязан быть 255 — в сети /25 это `.127` (аудит 2026-09-05).
   * Прежняя проверка «оканчивается на .255» давала два разных промаха: опрос узла
   * никогда не подтверждался (ответа с адреса вещания не бывает), а в аварийном пути
   * сокет не получал разрешения на широковещание и свет не уходил вовсе.
   */
  _isBroadcastTarget(target) {
    const text = String(target || '');
    try {
      const ifaces = this._deps.interfaces || os.networkInterfaces();
      return ArtDmxSender.isBroadcastTarget(text, listCandidates(ifaces));
    } catch (e) {
      // Снимок карт недоступен — остаётся прежний, более узкий признак.
      return text === '255.255.255.255' || /\.255$/.test(text);
    }
  }

  /**
   * Спросить сеть «кто здесь» и дождаться ArtPollReply.
   *
   * Слушаем на сокете dmxnet, потому что узлы отвечают на порт 6454 независимо от
   * того, с какого порта пришёл запрос (спецификация Art-Net). Свой обработчик
   * ДОБАВЛЯЕТСЯ к обработчику dmxnet, а не заменяет его: разбор ArtDmx и ответы на
   * чужой ArtPoll должны продолжать работать.
   *
   * Никогда не бросает и ничего не меняет в выводе света: худший исход —
   * `confirmed: false`, то есть «подтвердить не удалось».
   */
  async probeNode({ timeoutMs = ART_POLL_TIMEOUT_MS, retryMs = ART_POLL_RETRY_MS } = {}) {
    const { listener, sendSocket } = this._probeSockets();
    if (!this.connected || !listener || !sendSocket) {
      return { supported: true, confirmed: false, reason: 'no-socket', nodes: [] };
    }

    const target = this.deviceInfo.ip || '255.255.255.255';
    const broadcast = this._isBroadcastTarget(target);
    // Сверяем с БАЗОВЫМ юниверсом: он вещает с момента подключения, а дополнительные
    // создаются лениво по первому кадру — их на момент опроса может ещё не быть.
    const portAddress = portAddressForUniverse(this.deviceInfo, 1);
    const locals = localIpv4Addresses();
    const nodes = new Map();      // ответы, которые действительно подтверждают наш вывод
    const strangers = new Map();  // ответили, но не нам или не в наш юниверс
    let onMessage = null;
    let timer = null;
    let retry = null;

    try {
      return await new Promise((resolve) => {
        const finish = (reason) => {
          if (timer) { clearTimeout(timer); timer = null; }
          if (retry) { clearTimeout(retry); retry = null; }
          if (onMessage) { try { listener.removeListener('message', onMessage); } catch (e) { /* сокет уже закрыт */ } }
          onMessage = null;
          const confirmed = nodes.size > 0;
          // Ответы были, но ни один не наш. «Не тот юниверс» — самая полезная из причин
          // (свет реально не дойдёт), поэтому при обеих сразу называем её.
          let why = reason;
          if (!confirmed && strangers.size > 0) {
            why = Array.from(strangers.values()).some((s) => s.why === 'universe-mismatch')
              ? 'universe-mismatch' : 'node-mismatch';
          }
          resolve({
            supported: true,
            confirmed,
            reason: confirmed ? 'reply' : why,
            portAddress,
            // Вещаем ли мы. Признак считает ТОЛЬКО транспорт (`_isBroadcastTarget`
            // учитывает и `x.x.x.255`, и снимок карт), и он же обязан доехать до
            // подсказки: интерфейс пробовал угадывать это по строке адреса и путал
            // направленное вещание `192.168.0.255` с обычным узлом (ревью 14.09.2026).
            broadcast,
            nodes: confirmed
              ? Array.from(nodes.values())
              : Array.from(strangers.values()).map((s) => s.reply),
          });
        };

        onMessage = (msg, rinfo) => {
          try {
            const reply = parseArtPollReply(msg, rinfo);
            if (!reply || isOwnArtPollReply(reply, locals)) return;
            if (!artPollReplyFromTarget(reply, target, broadcast)) {
              strangers.set(reply.ip, { reply, why: 'node-mismatch' });
              return;   // ждём своего: чужой ответ опрос не заканчивает
            }
            if (!artPollReplyServesPortAddress(reply, portAddress)) {
              strangers.set(reply.ip, { reply, why: 'universe-mismatch' });
              return;
            }
            nodes.set(reply.ip, reply);
            finish('reply');
          } catch (e) { /* чужой мусор на 6454 не должен ломать опрос */ }
        };
        listener.on('message', onMessage);

        const poll = () => {
          try {
            // Широковещательный опрос требует явного разрешения на сокете; у общего
            // сокета dmxnet оно уже стоит, у listener4 — нет. Признак широковещания
            // общий с выводом света: `.255` — не единственная его форма.
            if (broadcast && typeof sendSocket.setBroadcast === 'function') {
              try { sendSocket.setBroadcast(true); } catch (e) { /* уже включено или не поддержано */ }
            }
            // Колбэк обязателен: без него dgram эмитит ошибку отправки НА СОКЕТЕ, а на
            // listener4 висит наш гвард — неудачный опрос (например, EACCES на
            // широковещание) выглядел бы как обрыв связи и рвал рабочее подключение.
            sendSocket.send(buildArtPollPacket(), ART_NET_PORT, target, () => { /* ошибка опроса = таймаут */ });
          } catch (e) { /* сеть недоступна — ответом будет таймаут */ }
        };

        poll();
        retry = setTimeout(() => { retry = null; poll(); }, Math.max(100, retryMs));
        timer = setTimeout(() => finish('timeout'), Math.max(200, timeoutMs));
        if (typeof retry.unref === 'function') retry.unref();
        if (typeof timer.unref === 'function') timer.unref();
      });
    } catch (e) {
      return { supported: true, confirmed: false, reason: 'error', nodes: [] };
    }
  }

  async close() {
    this._stopForeignWatch();
    // Свой отправитель: гасит собственный такт 40 Гц и закрывает все сокеты. Вызов
    // идемпотентен, поэтому повторный close() безопасен (DMX-001).
    if (this.artDmx) {
      try { this.artDmx.close(); } catch (e) { /* ignore */ }
    }
    this.artDmx = null;
    if (this.receiver) {
      try { this.receiver.close(); } catch (e) { /* already closed */ }
    }
    this.receiver = null;
    this._pendingSocketError = null;
    if (this.sender) {
      try {
        this.sender.stop();
      } catch (e) { /* ignore */ }
    }
    // MULTI-UNIVERSE: stop every extra-universe sender too (each owns a dmxnet timer).
    for (const s of this.extraSenders.values()) {
      try { s.stop(); } catch (e) { /* ignore */ }
    }
    this.extraSenders.clear();
    this.sender = null;
    // Аварийный путь: экземпляр библиотеки гасим целиком — сокеты и таймер живут в нём,
    // а не в sender'ах, и обнуление ссылки их не закрывало (аудит 2026-09-05).
    this._closeDmxnetInstance();
    this.connected = false;
  }

  /**
   * Откуда слушать и чем спрашивать при опросе узла. Своим отправителем спрашиваем с
   * УЖЕ ПРИВЯЗАННОГО сокета: опрос обязан идти тем же маршрутом, что и свет, иначе
   * возможен абсурд — «узел подтверждён» через одну карту, а кадры уходят в другую.
   */
  _probeSockets() {
    if (this.artDmx) {
      const listener = this.receiver;
      return { listener, sendSocket: this.artDmx.primarySocket() || listener };
    }
    const listener = this.dmxnetInstance && this.dmxnetInstance.listener4;
    return { listener, sendSocket: (this.dmxnetInstance && this.dmxnetInstance.socket) || listener };
  }

  // Resolves the dmxnet sender for a logical universe, creating it lazily. Logical 1 =
  // the base sender opened in open(); others are created on first frame.
  /**
   * Наблюдение за чужими источниками света (см. artnet/foreignSourceWatch.js).
   *
   * Слушаем ТОТ ЖЕ сокет, что и опрос узлов: обработчик ДОБАВЛЯЕТСЯ к обработчику
   * dmxnet, поэтому его собственный разбор ArtDmx и ответы на чужой ArtPoll работают
   * как раньше. Второй сокет на 6454 открывать нельзя — порт уже занят нашим же
   * listener4, и попытка привязки уронила бы подключение (EADDRINUSE).
   *
   * Наблюдение никогда не трогает вывод света: худший исход — пустой список.
   */
  _startForeignWatch(listener) {
    this._stopForeignWatch();
    if (!listener || typeof listener.on !== 'function') return;

    this.foreignWatch = createForeignSourceWatch({ localAddresses: localIpv4Addresses() });
    this._syncForeignOwnAddresses();

    this._onForeignMessage = (msg, rinfo) => {
      try {
        const frame = parseArtDmx(msg, rinfo);
        if (!frame) return;   // ArtPoll/ArtPollReply/чужой протокол — не наше дело
        const verdict = this.foreignWatch.observe(frame, Date.now());
        if (verdict !== 'new-conflict') return;
        // Список своих адресов снят при open(). У сетевого вывода по Wi-Fi адрес живёт
        // недолго: переключение точки доступа или переезд в другую сеть дают НОВЫЙ IP,
        // и наш собственный broadcast, вернувшийся на свой же сокет, выглядел бы как
        // чужой источник. Перед тревогой пересматриваем адреса — это дёшево, потому
        // что случается один раз на источник, а не на каждом кадре.
        this.foreignWatch.setLocalAddresses(localIpv4Addresses());
        if (this.foreignWatch.isLocal(frame.ip)) {
          this.foreignWatch.forget(frame.ip);
          return;
        }
        // Сообщаем ОДИН раз на источник: кадры идут 40 раз в секунду.
        console.log(`⚠️ Art-Net: в сети есть ещё один источник света — ${frame.ip} вещает в наш юниверс (Port-Address ${frame.portAddress})`);
        if (typeof this.onForeignSource === 'function') {
          try {
            this.onForeignSource({ ip: frame.ip, portAddress: frame.portAddress, sources: this.foreignSources() });
          } catch (e) { /* слушатель не вправе ломать приём кадров */ }
        }
      } catch (e) { /* чужой мусор на 6454 не должен ломать приём */ }
    };
    listener.on('message', this._onForeignMessage);
    this._foreignListener = listener;
  }

  _stopForeignWatch() {
    if (this._foreignListener && this._onForeignMessage) {
      try { this._foreignListener.removeListener('message', this._onForeignMessage); } catch (e) { /* сокет уже закрыт */ }
    }
    this._foreignListener = null;
    this._onForeignMessage = null;
    this.foreignWatch = null;
  }

  /** Наши Port-Address: база плюс по одному на каждый дополнительный юниверс. */
  _syncForeignOwnAddresses() {
    if (!this.foreignWatch) return;
    const addresses = new Set([artNetPortAddress(this.deviceInfo)]);
    // Прежний путь держит юниверсы отдельными sender'ами dmxnet…
    for (const universe of this.extraSenders.keys()) {
      addresses.add(portAddressForUniverse(this.deviceInfo, universe));
    }
    // …свой отправитель — записями по Port-Address. Список «наших» адресов один и тот
    // же: по нему наблюдение отличает опасного соседа в НАШЕМ юниверсе от безобидного.
    if (this.artDmx) {
      for (const portAddress of this.artDmx.portAddresses()) addresses.add(portAddress);
    }
    this.foreignWatch.setOwnAddresses(Array.from(addresses));
  }

  /**
   * Сокет 6454, который транспорт уже держит.
   *
   * Поиск узлов подписывается на него вместо второй привязки к тому же порту: на Windows
   * дублирующая привязка с SO_REUSEADDR растаскивает ответы между сокетами, и на время
   * поиска рабочий приёмник слеп (аудит 2026-09-05).
   */
  sharedReceiverSocket() {
    if (this.receiver) return this.receiver;
    return (this.dmxnetInstance && this.dmxnetInstance.listener4) || null;
  }

  /** Кто ещё вещает в сети прямо сейчас (для статуса, диагностики и предупреждения). */
  foreignSources() {
    return this.foreignWatch ? this.foreignWatch.snapshot(Date.now()) : [];
  }

  _senderFor(logicalUniverse) {
    if (logicalUniverse <= 1) return this.sender;
    let s = this.extraSenders.get(logicalUniverse);
    if (!s && this.dmxnetInstance) {
      s = this.dmxnetInstance.newSender(senderOptionsForUniverse(this.deviceInfo, logicalUniverse));
      // Every sender owns its own UDP socket — guard it like the base one.
      if (this._onSocketError) attachDmxnetSocketGuards(s, this._onSocketError);
      // …и своё разрешение на широковещание: цель у всех юниверсов одна, а dmxnet узнаёт
      // её broadcast-природу только по последнему октету 255 (см. _openViaDmxnet).
      if (this._isBroadcastTarget(this.deviceInfo.ip || '255.255.255.255')) {
        enableBroadcastWhenBound(s && s.socket);
      }
      this.extraSenders.set(logicalUniverse, s);
      // Новый юниверс = новый наш Port-Address: без этого чужой кадр в него считался бы
      // безобидным соседом, хотя мержится он именно с нашим светом.
      this._syncForeignOwnAddresses();
    }
    return s;
  }

  // Self-clocked (ARTNET-002): only update dmxnet's channel buffer. The sender's
  // own base_refresh_interval timer (40 Hz, main process) transmits it — calling
  // transmit() here too would double the wire rate (~80 Hz, > Art-Net 44 Hz max).
  send(dmxData, logicalUniverse = 1) {
    if (!this.connected) return;
    // Юниверс, чей Port-Address не влезает в 15 бит, НЕ выводится: клэмп отправил бы его
    // кадры на адрес соседнего юниверса и затирал бы их 40 раз в секунду (аудит
    // 2026-09-05). Предупреждаем один раз — на такте это горячий путь.
    if (!universeFitsPortAddress(this.deviceInfo, logicalUniverse)) {
      this._warnUniverseOverflow(logicalUniverse);
      return;
    }

    // Свой отправитель (блок D): здесь только обновление кадра в памяти, на провод
    // его выносит собственный таймер 40 Гц — инвариант ARTNET-002 не изменился.
    if (this.artDmx) {
      const portAddress = portAddressForUniverse(this.deviceInfo, logicalUniverse);
      // Юниверс появляется лениво, при первом кадре в него; новый адрес сразу
      // становится «нашим» для наблюдения за чужими источниками.
      if (this.artDmx.setFrame(portAddress, dmxData)) this._syncForeignOwnAddresses();
      return;
    }

    const sender = this._senderFor(logicalUniverse);
    if (!sender) return;

    try {
      for (let i = 0; i < 512; i++) {
        sender.prepChannel(i, (dmxData[i] !== undefined) ? dmxData[i] : 0);
      }
      // Аварийный откат (SVETO_ARTNET_LEGACY=1): провод тактует сам dmxnet, и исхода
      // отправки нам не видно. Считаем то единственное, что здесь доказуемо, — кадр
      // положен в буфер библиотеки; уровень подтверждения так и назван (`buffer`).
      this.noteTransfer({ success: true, universe: logicalUniverse });
    } catch (err) {
      // ignore prep errors
      this.noteTransfer({ success: false, universe: logicalUniverse, error: err });
    }
  }

  /** Юниверс за границей адресного пространства — сказать один раз, а не на каждом кадре. */
  _warnUniverseOverflow(logicalUniverse) {
    if (this._overflowWarned.has(logicalUniverse)) return;
    this._overflowWarned.add(logicalUniverse);
    const base = artNetPortAddress(this.deviceInfo);
    console.log(`⚠️ Art-Net: юниверс ${logicalUniverse} не влезает в адресное пространство (база ${base} + ${logicalUniverse - 1} больше ${ART_NET_MAX_PORT_ADDRESS}) — кадры в него не отправляются, иначе они затирали бы соседний юниверс. Уменьшите базовый Port-Address.`);
  }
}

module.exports = ArtNetTransport;
module.exports.buildArtNetSenderOptions = buildArtNetSenderOptions;
module.exports.senderOptionsForUniverse = senderOptionsForUniverse;
// Блок D (2026-09-02): свой отправитель ArtDmx + аварийный откат на dmxnet.
module.exports.portAddressForUniverse = portAddressForUniverse;
// Аудит 2026-09-05: юниверс за 0x7FFF не выводится вовсе, а не затирает соседний.
module.exports.universeFitsPortAddress = universeFitsPortAddress;
module.exports.enableBroadcastWhenBound = enableBroadcastWhenBound;
module.exports.createDmxnetInstance = createDmxnetInstance;
module.exports.legacyArtNetEnabled = legacyArtNetEnabled;
module.exports.ArtDmxSender = ArtDmxSender;
module.exports.ART_NET_REFRESH_MS = ART_NET_REFRESH_MS;
module.exports.ART_NET_MAX_PORT_ADDRESS = ART_NET_MAX_PORT_ADDRESS;
module.exports.attachDmxnetSocketGuards = attachDmxnetSocketGuards;
// ARTNET-003 (2026-08-22): защита от throw ВНУТРИ колбэка dgram.send() у dmxnet.
module.exports.swallowDmxnetSendErrors = swallowDmxnetSendErrors;
module.exports.sanitizeArtPollReplyTargets = sanitizeArtPollReplyTargets;
// test-only: pure address helpers
module.exports._artNetPortAddress = artNetPortAddress;
module.exports._splitPortAddress = splitPortAddress;
// ArtPoll (2026-08-22): чистые функции опроса — тестируются без сети.
module.exports.buildArtPollPacket = buildArtPollPacket;
module.exports.parseArtPollReply = parseArtPollReply;
module.exports.isOwnArtPollReply = isOwnArtPollReply;
module.exports.localIpv4Addresses = localIpv4Addresses;
// Строгая сверка ответа (2026-09-05): чей ответ и в наш ли юниверс.
module.exports.artPollReplyFromTarget = artPollReplyFromTarget;
module.exports.artPollReplyServesPortAddress = artPollReplyServesPortAddress;
module.exports.ART_POLL_TIMEOUT_MS = ART_POLL_TIMEOUT_MS;
