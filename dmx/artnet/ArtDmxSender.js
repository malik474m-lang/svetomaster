// ═══════════════════════════════════════════════════════════════════════════
// Art-Net — СВОЙ отправитель кадров света (2026-09-02, блок D мастера настройки)
// ═══════════════════════════════════════════════════════════════════════════
//
// Зачем понадобилось своё вместо библиотеки dmxnet. У неё два врождённых дефекта,
// оба подтверждены на живом железе:
//
// 1. СОКЕТ НЕ ПРИВЯЗАН К СЕТЕВОЙ КАРТЕ (`node_modules/dmxnet/lib.js:377` — при
//    адресной отправке привязки нет вовсе). Маршрут поэтому выбирает операционная
//    система, а при включённом VPN метрика туннеля ниже, чем у кабеля, и ВЕСЬ свет
//    уходит в туннель. Со стороны это «программа подключилась, приборы не реагируют».
//    Лечилось только внесением программы в исключения VPN — то есть не лечилось.
//    (Разбор: `ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md` §6 п.7.)
// 2. БРОСАЕТ ИСКЛЮЧЕНИЯ ИЗ КОЛБЭКОВ ОТПРАВКИ (`if (err) throw err`, lib.js:219/268/
//    312/424). Это не событие 'error' сокета — перехватить его обработчиком нельзя,
//    оно всплывает как uncaughtException в главном процессе (дефект ARTNET-003).
//
// Здесь оба лечатся по существу: сокет привязан к адресу выбранной карты, а ошибка
// отправки — обычное значение в колбэке, а не исключение.
//
// ГЛАВНЫЙ ПРИНЦИП — СВЕТ НА ШОУ НЕ ГАСНЕТ. Ни одна ветка не бросает наружу: не нашли
// карту — работаем через маршрут ОС (как раньше), не привязались — берём следующего
// кандидата, не ушёл пакет — сообщаем один раз и продолжаем. Хуже, чем было, не
// становится ни в одном сценарии.
//
// ТАКТ 40 Гц ЖИВЁТ ЗДЕСЬ (инвариант ARTNET-002). Кадр уходит на провод по нашему
// таймеру в ГЛАВНОМ процессе, а не по вызову send() из окна: при свёрнутом окне ОС
// душит анимационный цикл рендерера до ~1 Гц, и свет пошёл бы ступенями.
const dgram = require('dgram');
const os = require('os');

const { ART_NET_PORT, buildArtDmxPacket, nextSequence } = require('./artnetPackets');
const { listCandidates, directedBroadcast, isSameSubnet, prefixLength } = require('../../main/remote/remoteNet');

const BROADCAST_ALL = '255.255.255.255';
// Привязка «куда угодно»: маршрут выбирает ОС. Это ровно прежнее поведение dmxnet —
// наш последний рубеж, а не рабочий режим.
const ANY_ADDRESS = '0.0.0.0';
const ART_DMX_REFRESH_MS = 25;   // 1000 / 25 = 40 Гц (потолок Art-Net ~44 Гц)
// Сколько карт максимум вещают одновременно (см. resolveBindPlan): узел Art-Net по
// спецификации сливает ДВА источника, третий уже вправе пометить merge-fail.
const MAX_BROADCAST_SOCKETS = 2;
// Сколько неудачных отправок подряд СО ВСЕХ сокетов означает «эта карта не доставляет».
// Считается в ПАКЕТАХ, а не в тактах: при одном юниверсе это ровно секунда, при
// четырёх — четверть. Разброс в безопасную сторону (быстрее вернуть свет), а разовый
// сбой сети не живёт и четверти секунды. См. _maybeFallbackToAny().
const SEND_ERRORS_BEFORE_FALLBACK = 40;
// Сколько раз пытаться уйти на маршрут ОС. Без потолка каждая неудачная отправка
// (40+ раз в секунду на юниверс) заводила бы новый сокет — горячий цикл системных
// вызовов там, где сеть и так не работает.
const MAX_FALLBACK_ATTEMPTS = 3;

/**
 * Широковещательная ли цель. Кроме явного 255.255.255.255 это ещё и вещание своей
 * подсети (192.168.0.255 при маске /24) — на такой адрес часть узлов отвечает
 * охотнее. Хвост «.255» проверяем и отдельно: адрес может принадлежать подсети,
 * которой у нас сейчас нет, а отправка на него всё равно требует разрешения
 * широковещания — без него ядро вернёт EACCES.
 */
function isBroadcastTarget(targetIp, candidates) {
  if (!targetIp || targetIp === BROADCAST_ALL) return true;
  if (/\.255$/.test(targetIp)) return true;
  return (candidates || []).some((c) => directedBroadcast(c.address, c.netmask) === targetIp);
}

/**
 * К каким адресам привязывать сокеты отправки. Чистая функция: снимок интерфейсов
 * передаётся аргументом, поэтому все ветки проверяются тестами без сети.
 *
 * Возвращает ПЛАН, а не просто список, потому что случаи принципиально разные:
 *
 *  • `chain` — кандидаты пробуются ПО ОЧЕРЕДИ до первой удачи. Так адресуется узел:
 *    правильная карта ровно одна (та, в чьей подсети он живёт), а две параллельные
 *    отправки выглядели бы для узла как ДВА источника света и включили бы HTP-слияние
 *    на пустом месте.
 *  • `parallel` — вещаем со ВСЕХ пригодных карт сразу. Так уходит широковещательный
 *    кадр: подсети для сравнения нет, а угадывать единственную карту нельзя — ошибка
 *    означает «света нет вовсе». Ровно этим приёмом уже пользуется поиск узлов
 *    (`ArtNetDiscovery`), и он проверен на живом железе.
 *
 * Почему в `parallel` не больше двух карт и без виртуальных мостов: узел по
 * спецификации сливает два источника, а третий вправе пометить merge-fail. Данные во
 * всех наших потоках одинаковые, поэтому слияние безвредно, но выходить за предел
 * спецификации ради VirtualBox-моста смысла нет. Явный выбор карты из мастера
 * (`bindAddress`) всегда даёт РОВНО ОДИН источник и снимает вопрос совсем.
 *
 * Туннели (/31, /32 — форма любого VPN) исключены всегда: за ними нет сегмента, и
 * именно они уводили свет в никуда.
 */
function resolveBindPlan({ targetIp, bindAddress, interfaces } = {}) {
  let candidates = [];
  try {
    candidates = listCandidates(interfaces || os.networkInterfaces());
  } catch (e) {
    candidates = [];
  }
  const physical = candidates.filter((c) => c && c.address && !c.tunnel);
  const broadcast = isBroadcastTarget(targetIp, candidates);

  // 1. Явный выбор пользователя (мастер Art-Net, выбор узла в шапке, автоподключение).
  //    Мало того, что карта должна существовать, — она должна быть СПОСОБНА доставить.
  //    Выбор запоминается между запусками, поэтому он легко устаревает: мастер
  //    отработал дома по Wi-Fi, на площадке узел другой — и слепое подчинение увело бы
  //    свет в пустоту. Для АДРЕСНОГО узла способность проверяется подсетью; при
  //    вещании доставить может любая карта, поэтому там выбор принимается как есть.
  //    Важно: у вещания ошибок отправки нет, и аварийный откат по ним не сработал бы.
  let staleChoice = null;
  if (bindAddress && bindAddress !== ANY_ADDRESS) {
    const exact = physical.find((c) => c.address === bindAddress);
    if (exact && (broadcast || isSameSubnet(exact.address, targetIp, exact.netmask))) {
      return {
        mode: 'chain',
        broadcast,
        candidates: [
          { address: exact.address, name: exact.name, reason: 'explicit' },
          { address: ANY_ADDRESS, name: null, reason: 'any' },
        ],
      };
    }
    // Карта есть, но узел не в её подсети. Не выбрасываем совсем — человек мог выбрать
    // её осознанно (маршрут через шлюз), — но пробуем ПОСЛЕ подсетевых.
    staleChoice = exact || null;
  }

  // 2. Адресная отправка: карта, в чьей подсети живёт узел. При нескольких
  //    совпадениях выигрывает самая узкая маска — она точнее описывает сегмент.
  if (!broadcast) {
    const same = physical
      .filter((c) => isSameSubnet(c.address, targetIp, c.netmask))
      .sort((a, b) => (prefixLength(b.netmask) || 0) - (prefixLength(a.netmask) || 0))
      .map((c) => ({ address: c.address, name: c.name, reason: 'subnet' }));
    const stale = staleChoice && !same.some((c) => c.address === staleChoice.address)
      ? [{ address: staleChoice.address, name: staleChoice.name, reason: 'explicit-foreign' }]
      : [];
    return {
      mode: 'chain',
      broadcast,
      candidates: [...same, ...stale, { address: ANY_ADDRESS, name: null, reason: 'any' }],
    };
  }

  // 3. Вещание: со всех настоящих карт. Виртуальные мосты берём только если других
  //    нет вовсе — на них узел висит редко, а источником света они станут исправно.
  const real = physical.filter((c) => !c.virtual);
  const pool = real.length ? real : physical;
  // Вещание СВОЕЙ подсети имеет ровно одного законного отправителя — карту, которой
  // этот адрес и принадлежит. Ищем её во ВСЁМ пуле и ДО обрезки по числу мест: адрес
  // вида 2.255.255.255 (классическая Art-Net сеть 2.x с маской 255.0.0.0) — не
  // экзотика, и при трёх картах обрезка выбрасывала бы единственную нужную.
  const owner = targetIp && targetIp !== BROADCAST_ALL
    ? pool.filter((c) => directedBroadcast(c.address, c.netmask) === targetIp)
    : [];
  // Общее вещание: карт может быть больше, чем мест (их всего два), поэтому порядок
  // ОС — плохой судья: «первые две» могли оказаться теми, где узла нет. Ранжируем по
  // тому, что известно о самих адресах, а не по именам: 169.254.x — это «адреса не
  // выдали» (сеть фактически не поднята), а для света кабель предпочтительнее Wi-Fi,
  // где задержка и потери кадров заметны на глаз. Сортировка устойчива, поэтому при
  // равном весе сохраняется исходный порядок системы.
  const broadcastRank = (c) => (/^169\.254\./.test(c.address) ? 2 : 0) + (c.wireless ? 1 : 0);
  const chosen = owner.length
    ? owner
    : pool.slice().sort((a, b) => broadcastRank(a) - broadcastRank(b));
  const list = chosen
    .slice(0, MAX_BROADCAST_SOCKETS)
    .map((c) => ({ address: c.address, name: c.name, reason: 'broadcast' }));
  // Карт нет вообще (сеть не поднята) — остаётся прежнее поведение через маршрут ОС.
  if (!list.length) {
    return { mode: 'chain', broadcast, candidates: [{ address: ANY_ADDRESS, name: null, reason: 'any' }] };
  }
  return { mode: 'parallel', broadcast, candidates: list };
}

/**
 * Отправитель ArtDmx. Один экземпляр обслуживает ВСЕ юниверсы одного подключения:
 * цель у них общая, различается только Port-Address внутри пакета. Поэтому таймер
 * ровно один — два конкурирующих таймера дали бы удвоенную частоту на проводе
 * (~80 Гц против потолка спецификации ~44 Гц).
 */
class ArtDmxSender {
  /**
   * @param {object} options
   * @param {string} options.ip           куда слать (адрес узла или вещание)
   * @param {string} options.bindAddress  адрес карты, выбранной пользователем (мастер)
   * @param {object} options.interfaces   снимок os.networkInterfaces() — для тестов
   * @param {Function} options.createSocket фабрика сокетов — для тестов
   * @param {Function} options.onSocketError ошибка УЖЕ работающего сокета (обрыв, DMX-004)
   * @param {Function} options.onSendError   первая неудачная отправка на сокете
   * @param {Function} options.onWireFrame   исход ОДНОГО такта провода (для счётчиков отчёта)
   */
  constructor({
    ip, bindAddress, port, refreshMs, interfaces, createSocket, onSocketError, onSendError,
    onWireFrame, log,
  } = {}) {
    this.targetIp = ip || BROADCAST_ALL;
    this.bindAddress = bindAddress || null;
    // Порт назначения всегда 6454: спецификация другого не предусматривает, а
    // dmxnet его тоже не менял. Параметр существует ради тестов без сети.
    this.port = Number.isInteger(port) ? port : ART_NET_PORT;
    this.refreshMs = Math.max(5, Math.floor(refreshMs) || ART_DMX_REFRESH_MS);
    this.interfaces = interfaces || null;
    this.createSocket = createSocket || ((opts) => dgram.createSocket(opts));
    this.onSocketError = typeof onSocketError === 'function' ? onSocketError : null;
    this.onSendError = typeof onSendError === 'function' ? onSendError : null;
    // Счётчики передач для отчёта (2026-09-11): один такт провода = одна передача,
    // сколько бы юниверсов и сетевых карт он ни обслуживал. Иначе у клиента с двумя
    // картами «частота кадров» удвоилась бы на ровном месте.
    this.onWireFrame = typeof onWireFrame === 'function' ? onWireFrame : null;
    this.log = typeof log === 'function' ? log : ((msg) => console.log(msg));

    this.sockets = [];          // привязанные сокеты отправки
    this.universes = new Map(); // Port-Address → { values, sequence }
    this.timer = null;
    this.closed = false;
    this.plan = null;
    this.ticks = 0;             // сделанных тактов — для диагностики и тестов
    this.fellBackToAny = false; // сработал ли аварийный переход на маршрут ОС
    this._fallbackPending = false;
    this._fallbackAttempts = 0;
  }

  /**
   * Привязать сокеты и запустить такт. Никогда не бросает.
   * @returns {Promise<boolean>} false — не удалось открыть ни одного сокета вообще.
   */
  async open() {
    if (this.closed) return false;
    const plan = resolveBindPlan({
      targetIp: this.targetIp,
      bindAddress: this.bindAddress,
      interfaces: this.interfaces,
    });
    this.plan = plan;

    for (const candidate of plan.candidates) {
      const entry = await this._bind(candidate, plan.broadcast);
      if (entry) {
        this.sockets.push(entry);
        // Цепочка кандидатов — это фолбэк, а не веер: первой удачи достаточно.
        if (plan.mode === 'chain') break;
      }
    }

    // ФОЛБЭК. Карту могли выдернуть между выбором и привязкой; в вещательном плане
    // 0.0.0.0 в кандидатах нет вовсе. Свет важнее точности маршрута — работаем как
    // раньше, через выбор операционной системы.
    if (!this.sockets.length && !plan.candidates.some((c) => c.address === ANY_ADDRESS)) {
      const entry = await this._bind({ address: ANY_ADDRESS, name: null, reason: 'any' }, plan.broadcast);
      if (entry) this.sockets.push(entry);
    }

    if (this.closed || !this.sockets.length) {
      this._closeSockets();
      return false;
    }

    this.timer = setInterval(() => this._tick(), this.refreshMs);
    if (typeof this.timer.unref === 'function') this.timer.unref();
    return true;
  }

  /** Привязка одного сокета. Неудача — это null, а не исключение. */
  _bind(candidate, broadcast) {
    return new Promise((resolve) => {
      let socket;
      try {
        socket = this.createSocket({ type: 'udp4', reuseAddr: true });
      } catch (e) {
        return resolve(null);
      }
      const entry = {
        socket,
        address: candidate.address,
        name: candidate.name || null,
        reason: candidate.reason,
        ready: false,
        sendErrors: 0,
        errorsInRow: 0,
      };
      let settled = false;
      const done = (value) => { if (!settled) { settled = true; resolve(value); } };

      socket.on('error', (err) => {
        if (!entry.ready) {
          // Ошибка ДО готовности — это неудачная привязка (карты уже нет, адрес чужой).
          // Не обрыв подключения: пробуем следующего кандидата, вплоть до 0.0.0.0.
          try { socket.close(); } catch (e) { /* уже закрыт */ }
          return done(null);
        }
        // Ошибка РАБОТАЮЩЕГО сокета. При вещании их несколько: пока жив хотя бы один,
        // свет идёт — сбойный выбрасываем и молчим. Потеря связи (DMX-004) объявляется
        // только когда отказал последний, иначе транспорт рвался бы из-за карты,
        // которая для доставки и не требовалась.
        const others = this.sockets.filter((e) => e !== entry && e.ready);
        this._dropSocket(entry);
        if (others.length) {
          this.log(`⚠️ Art-Net: карта ${entry.address} отказала, свет идёт с остальных: ${err && err.message ? err.message : err}`);
          return;
        }
        if (this.onSocketError) {
          try { this.onSocketError(err, socket); } catch (e) { /* слушатель не вправе ломать вывод */ }
        }
      });

      try {
        // Порт 0 = любой свободный. Адрес карты — то, ради чего всё затевалось.
        socket.bind({ port: 0, address: candidate.address }, () => {
          if (broadcast) {
            try { socket.setBroadcast(true); } catch (e) { /* не критично: адресная отправка работает и так */ }
          }
          entry.ready = true;
          if (this.closed) {
            try { socket.close(); } catch (e) { /* уже закрыт */ }
            return done(null);
          }
          done(entry);
        });
      } catch (e) {
        try { socket.close(); } catch (e2) { /* уже закрыт */ }
        done(null);
      }
    });
  }

  /**
   * Юниверс появляется при ПЕРВОМ кадре в него (и один — сразу при открытии, чтобы на
   * проводе с первой секунды был ровный поток: узлы держат последнее состояние и ждут
   * его обновления). Пока кадров нет — нет и пакетов: молчание в чужой юниверс.
   */
  ensureUniverse(portAddress) {
    const key = Math.max(0, Math.floor(Number(portAddress)) || 0);
    let universe = this.universes.get(key);
    if (!universe) {
      // Обычный массив, а не типизированный: клэмп значений живёт в одном месте —
      // в buildArtDmxPacket, — а Uint8Array молча переполнил бы 300 в 44.
      universe = { values: new Array(512).fill(0), sequence: 0 };
      this.universes.set(key, universe);
    }
    return universe;
  }

  /**
   * Обновить кадр юниверса. Провод не трогает: его гонит таймер (ARTNET-002).
   * @returns {boolean} true — юниверс появился только что (нужен вызывающему, чтобы
   *   учесть новый Port-Address как «наш» в наблюдении за чужими источниками).
   */
  setFrame(portAddress, values) {
    if (this.closed) return false;
    const key = Math.max(0, Math.floor(Number(portAddress)) || 0);
    const created = !this.universes.has(key);
    const universe = this.ensureUniverse(key);
    const target = universe.values;
    for (let i = 0; i < 512; i++) {
      const v = values ? values[i] : 0;
      target[i] = v === undefined ? 0 : v;   // клэмп — в buildArtDmxPacket
    }
    return created;
  }

  /** Такт провода: по одному кадру ArtDmx на каждый живой юниверс с каждого сокета. */
  _tick() {
    if (this.closed || !this.sockets.length) return;
    // Исход такта складывается из колбэков всех его пакетов и сообщается ОДИН раз,
    // когда вернулся последний. Отправка асинхронная, поэтому «отдали ядру» и «ядро
    // приняло» — разные моменты, и счётчик обязан считать второй.
    // Без слушателя объект не заводится вовсе: такт идёт 40 раз в секунду, и путь
    // остаётся ровно таким же, каким был до появления счётчиков.
    const frame = this.onWireFrame ? {
      startedMs: Date.now(),
      pending: 0, sent: 0, errors: 0, lastError: null,
      dispatched: false, reported: false,
    } : null;
    for (const [portAddress, universe] of this.universes) {
      // Порядковый номер — свой у каждого юниверса (так требует спецификация):
      // 1..255 по кругу, 0 означает «нумерация не ведётся».
      universe.sequence = nextSequence(universe.sequence);
      // Пакет собирается заново на каждый такт СОЗНАТЕЛЬНО: dgram.send() не копирует
      // буфер синхронно, и правка общего буфера между тактами могла бы отправить
      // «рваный» кадр (часть каналов старая, часть новая). 530 байт 40 раз в секунду
      // для сборщика мусора — ничто, а испорченный кадр виден на приборах.
      const packet = buildArtDmxPacket(portAddress, universe.values, universe.sequence);
      for (const entry of this.sockets) this._transmit(entry, packet, frame);
    }
    this.ticks += 1;
    if (frame) {
      frame.dispatched = true;   // пакетов в этом такте больше не появится
      this._settleFrame(frame);  // все колбэки могли успеть вернуться уже сейчас
    }
  }

  /**
   * Такт закончен во всех смыслах — сообщить его исход ровно один раз.
   * Такт без единого пакета (юниверсов ещё нет) не сообщается вовсе: «нечего было
   * слать» — это не провал передачи, и в счётчике ошибок ему не место.
   */
  _settleFrame(frame) {
    if (!frame || frame.reported || !frame.dispatched || frame.pending > 0) return;
    if (!frame.sent && !frame.errors) return;
    frame.reported = true;
    if (!this.onWireFrame) return;
    try {
      this.onWireFrame({
        // Кадр считается ушедшим, если его принял ХОТЯ БЫ один сокет: при вещании с
        // двух карт свет доходит и с одной, и это не провал такта.
        success: frame.sent > 0,
        durationMs: Date.now() - frame.startedMs,
        packets: frame.sent,
        errors: frame.errors,
        error: frame.sent > 0 ? null : frame.lastError,
      });
    } catch (e) { /* слушатель не вправе ломать вывод света */ }
  }

  /**
   * Отправка одного пакета. Ошибка НЕ рвёт подключение: Art-Net идёт по UDP, где
   * доставка не гарантирована и никогда не подтверждается, а разовый EADDRNOTAVAIL
   * (карта мигнула) — не потеря связи. Сообщаем один раз на сокет: такт идёт 40 раз
   * в секунду и залил бы лог за минуту.
   */
  _transmit(entry, packet, frame = null) {
    if (!entry.ready) return;
    if (frame) frame.pending += 1;
    try {
      entry.socket.send(packet, 0, packet.length, this.port, this.targetIp, (err) => {
        if (frame) {
          frame.pending -= 1;
          if (err) { frame.errors += 1; frame.lastError = err; } else frame.sent += 1;
          this._settleFrame(frame);
        }
        if (!err) {
          entry.errorsInRow = 0;
          return;
        }
        entry.sendErrors += 1;
        entry.errorsInRow += 1;
        if (entry.sendErrors === 1) {
          this.log(`⚠️ Art-Net: ошибка отправки UDP с ${entry.address} (подключение сохранено): ${err && err.message ? err.message : err}`);
          if (this.onSendError) {
            try { this.onSendError(err, entry); } catch (e) { /* слушатель не вправе ломать вывод */ }
          }
        }
        this._maybeFallbackToAny();
      });
    } catch (e) {
      // Сокет закрыли между тактами — следующий такт этого сокета уже не увидит.
      if (frame) {
        frame.pending -= 1;
        frame.errors += 1;
        frame.lastError = e;
        this._settleFrame(frame);
      }
    }
  }

  /**
   * Аварийный переход на маршрут операционной системы — вторая половина правила
   * «свет на шоу не гаснет».
   *
   * Привязка к карте лечит VPN, но заводит НОВЫЙ способ остаться без света, которого у
   * прежнего пути не было: карта существует и привязка удалась, а доставить кадр с неё
   * некуда — узел переехал в другую подсеть, сеть перенастроили, адрес сменил DHCP.
   * Ядро отвечает на это ошибкой на КАЖДОЙ отправке. Секунда сплошных ошибок со всех
   * сокетов — это не помеха, а неверный маршрут, и тогда мы возвращаемся ровно к
   * прежнему поведению (0.0.0.0, маршрут выбирает ОС). Один раз за подключение:
   * дальше решение принимает переподключение, а не мигание туда-сюда.
   */
  _maybeFallbackToAny() {
    if (this.closed || this.fellBackToAny || this._fallbackPending) return;
    if (this._fallbackAttempts >= MAX_FALLBACK_ATTEMPTS) return;
    if (!this.sockets.length) return;
    if (this.sockets.some((e) => e.address === ANY_ADDRESS)) return;
    if (!this.sockets.every((e) => e.errorsInRow >= SEND_ERRORS_BEFORE_FALLBACK)) return;

    this._fallbackPending = true;
    this._fallbackAttempts += 1;
    if (this._fallbackAttempts === 1) {
      this.log('⚠️ Art-Net: с выбранной сетевой картой кадры не уходят — возвращаюсь на маршрут по умолчанию');
    }
    const broadcast = this.plan ? this.plan.broadcast : true;
    this._bind({ address: ANY_ADDRESS, name: null, reason: 'any-fallback' }, broadcast)
      .then((entry) => {
        this._fallbackPending = false;
        if (!entry) return;
        // Пока шла привязка, подключение могли закрыть — тогда новый сокет ничей.
        if (this.closed) {
          try { entry.socket.close(); } catch (e) { /* уже закрыт */ }
          return;
        }
        this._closeSockets();       // старые сокеты; новый ещё не в списке
        this.sockets = [entry];
        this.fellBackToAny = true;
      })
      .catch(() => { this._fallbackPending = false; });
  }

  /** Убрать сокет из работы: сначала из списка (такт его больше не увидит), потом закрыть. */
  _dropSocket(entry) {
    this.sockets = this.sockets.filter((e) => e !== entry);
    try { entry.socket.close(); } catch (e) { /* уже закрыт */ }
  }

  /** Наши Port-Address — наблюдению за чужими источниками нужно знать, что «наше». */
  portAddresses() {
    return Array.from(this.universes.keys());
  }

  /** Адреса, к которым реально привязались — уходят в лог подключения и в диагностику. */
  boundAddresses() {
    return this.sockets.filter((e) => e.ready).map((e) => e.address);
  }

  /**
   * Сокет для опроса узлов (ArtPoll). Берём рабочий сокет отправки: он уже привязан
   * к нужной карте, поэтому опрос идёт тем же маршрутом, что и свет, — иначе ответ
   * мог бы прийти «через VPN», а свет уходить через кабель.
   */
  primarySocket() {
    const entry = this.sockets.find((e) => e.ready);
    return entry ? entry.socket : null;
  }

  _closeSockets() {
    for (const entry of this.sockets) {
      try { entry.socket.close(); } catch (e) { /* уже закрыт */ }
    }
    this.sockets = [];
  }

  /** Погасить такт и закрыть сокеты. Повторный вызов безопасен. */
  close() {
    this.closed = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this._closeSockets();
    this.universes.clear();
  }
}

module.exports = ArtDmxSender;
module.exports.ArtDmxSender = ArtDmxSender;
module.exports.resolveBindPlan = resolveBindPlan;
module.exports.isBroadcastTarget = isBroadcastTarget;
module.exports.ART_DMX_REFRESH_MS = ART_DMX_REFRESH_MS;
module.exports.ANY_ADDRESS = ANY_ADDRESS;
module.exports.BROADCAST_ALL = BROADCAST_ALL;
module.exports.MAX_BROADCAST_SOCKETS = MAX_BROADCAST_SOCKETS;
module.exports.SEND_ERRORS_BEFORE_FALLBACK = SEND_ERRORS_BEFORE_FALLBACK;
module.exports.MAX_FALLBACK_ATTEMPTS = MAX_FALLBACK_ATTEMPTS;
