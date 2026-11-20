// ═══════════════════════════════════════════════════════════════════════════
// Art-Net — учёт ЧУЖИХ источников света в сети. Чистое состояние, без сокетов.
// ═══════════════════════════════════════════════════════════════════════════
//
// ЗАЧЕМ (разбор 2026-08-23, `ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md` §7). Art-Net-узлы
// штатно сливают два источника по HTP — на выход идёт БОЛЬШЕЕ значение канала. Поэтому
// вторая программа, забытое приложение Wi-Fi-бокса на телефоне или чужой пульт в той же
// сети молча подмешивают свой свет в наш. Симптом со стороны пользователя дикий: часть
// каналов слушается, а часть намертво держится чужим кадром — «ставлю красный, а прибор
// фиолетовый». Доказать это со стороны программы можно ровно одним способом: увидеть
// чужие кадры на проводе. Здесь — их учёт.
//
// КОНФЛИКТ ≠ ПРОСТО ЧУЖОЙ. Мерж бьёт только при совпадении Port-Address. Чужой источник
// в другом юниверсе нашему свету не мешает — он попадёт в диагностику, но пугать им
// пользователя нельзя. Поэтому `conflict` считается по нашим адресам, а не по факту
// «кто-то ещё вещает».
//
// СВОИ КАДРЫ. Наш собственный broadcast может вернуться на наш же слушающий сокет,
// поэтому отправители с локальных адресов отбрасываются. Обратная сторона: вторую копию
// СветоМастера, запущенную на ЭТОМ ЖЕ компьютере, наблюдатель не увидит — цена за
// отсутствие ложных срабатываний на каждом кадре собственного вещания.
//
// Только учёт: ничего не чинит, вывод света не трогает и решений за пользователя не
// принимает — как health-beacon, это наблюдаемость.

// Кадры идут 40 раз в секунду, поэтому «источник пропал» — это отсутствие кадров
// несколько секунд, а не один потерянный пакет UDP.
const DEFAULT_TTL_MS = 10000;
// Потолок на случай сканера/шторма в чужой сети: список нужен для диагноза, а не для
// инвентаризации. Дальше первых источников он не растёт и память не съедает.
const MAX_SOURCES = 16;
const MAX_UNIVERSES_PER_SOURCE = 8;

/**
 * Список адресов → Set. Принимает и Set, и массив СОЗНАТЕЛЬНО: `localIpv4Addresses()`
 * из artnetPackets отдаёт Set, а тесты и вызывающий код естественнее пишут массив.
 * Первая версия ждала массив — и Set молча превращался в пустой список, то есть свои
 * адреса не отсеивались вовсе и наш собственный broadcast считался чужим источником.
 */
function toAddressSet(addresses) {
  if (addresses instanceof Set) return addresses;
  if (Array.isArray(addresses)) return new Set(addresses);
  if (addresses && typeof addresses[Symbol.iterator] === 'function') return new Set(addresses);
  return new Set();
}

/** Отправитель — не мы? Локальные адреса и пустой IP не считаются чужими. */
function isForeignSender(ip, localAddresses = []) {
  if (typeof ip !== 'string' || ip === '') return false;
  return !toAddressSet(localAddresses).has(ip);
}

/**
 * Наблюдатель чужих источников.
 *
 * @param {object} options
 * @param {string[]} options.localAddresses адреса этого компьютера (см. localIpv4Addresses)
 * @param {number}   options.ttlMs          сколько источник считается живым без кадров
 */
function createForeignSourceWatch({ localAddresses = [], ttlMs = DEFAULT_TTL_MS, maxSources = MAX_SOURCES } = {}) {
  const sources = new Map();      // ip → запись наблюдения
  let locals = toAddressSet(localAddresses);
  let ownAddresses = new Set();   // Port-Address, в которые вещаем МЫ

  /** Наши адреса юниверсов — от них зависит, конфликтует чужой кадр или нет. */
  function setOwnAddresses(addresses) {
    ownAddresses = new Set(
      (Array.isArray(addresses) ? addresses : [])
        .map((v) => Math.floor(Number(v)))
        .filter((v) => Number.isFinite(v) && v >= 0),
    );
  }

  function setLocalAddresses(addresses) {
    locals = toAddressSet(addresses);
  }

  /** Этот адрес — наш? Транспорт спрашивает перед тем, как поднять тревогу. */
  function isLocal(ip) {
    return locals.has(ip);
  }

  /**
   * Учесть разобранный чужой кадр.
   * @returns {'new'|'new-conflict'|'known'|null} null — кадр наш, битый или список полон.
   *          'new' / 'new-conflict' — повод сказать об этом ОДИН раз, а не на каждом кадре.
   */
  function observe(frame, nowMs) {
    if (!frame || typeof frame !== 'object') return null;
    const ip = frame.ip;
    if (typeof ip !== 'string' || ip === '' || locals.has(ip)) return null;
    const portAddress = Math.floor(Number(frame.portAddress));
    if (!Number.isFinite(portAddress) || portAddress < 0) return null;
    const now = Number.isFinite(nowMs) ? nowMs : 0;

    let record = sources.get(ip);
    if (!record) {
      // Потолок защищает от шторма/сканера в чужой сети, но считать в нём ПРОТУХШИЕ
      // записи нельзя (аудит 2026-09-05): 16 когда-либо замеченных адресов запирали
      // список навсегда, и настоящий новый конфликт — тот самый HTP-сосед, из-за
      // которого «прибор живёт своей жизнью», — молча не учитывался до
      // переподключения. Чистим ровно в тот момент, когда место понадобилось:
      // тревога по-прежнему идёт ОДИН раз на источник, а не заново после каждой
      // паузы дольше TTL.
      if (sources.size >= maxSources) prune(now);
      if (sources.size >= maxSources) return null;
      record = {
        ip,
        portAddresses: new Set(),
        conflictAddresses: new Set(),
        frames: 0,
        firstSeen: now,
        lastSeen: now,
      };
      sources.set(ip, record);
    }

    const isNewSource = record.frames === 0;
    const wasConflicting = record.conflictAddresses.size > 0;
    record.frames += 1;
    record.lastSeen = now;
    if (record.portAddresses.size < MAX_UNIVERSES_PER_SOURCE) record.portAddresses.add(portAddress);
    if (ownAddresses.has(portAddress)) record.conflictAddresses.add(portAddress);

    const nowConflicting = record.conflictAddresses.size > 0;
    // О новом конфликте сообщаем и тогда, когда источник давно известен: он мог начать
    // вещать в наш юниверс только сейчас — а это ровно момент, когда свет «сломался».
    if (nowConflicting && (!wasConflicting || isNewSource)) return 'new-conflict';
    return isNewSource ? 'new' : 'known';
  }

  /**
   * Забыть источники, от которых нет кадров дольше TTL.
   *
   * Вызывается только когда в списке кончилось место: чистить на каждом кадре нельзя —
   * тогда сосед с паузами дольше TTL становился бы «новым» и давал бы тост заново.
   */
  function prune(nowMs) {
    const now = Number.isFinite(nowMs) ? nowMs : 0;
    for (const [ip, record] of sources) {
      if (now - record.lastSeen > ttlMs) sources.delete(ip);
    }
  }

  /** Снимок для диагностики и UI. Протухшие источники не показываются. */
  function snapshot(nowMs) {
    const now = Number.isFinite(nowMs) ? nowMs : 0;
    const out = [];
    for (const record of sources.values()) {
      const ageMs = now - record.lastSeen;
      if (ageMs > ttlMs) continue;
      out.push({
        ip: record.ip,
        universes: Array.from(record.portAddresses).sort((a, b) => a - b),
        conflictUniverses: Array.from(record.conflictAddresses).sort((a, b) => a - b),
        conflict: record.conflictAddresses.size > 0,
        frames: record.frames,
        firstSeen: record.firstSeen,
        lastSeen: record.lastSeen,
        ageMs,
      });
    }
    return out.sort((a, b) => Number(b.conflict) - Number(a.conflict) || a.ip.localeCompare(b.ip));
  }

  /** Есть ли ПРЯМО СЕЙЧАС чужой источник в наших юниверсах. */
  function hasConflict(nowMs) {
    return snapshot(nowMs).some((s) => s.conflict);
  }

  function reset() {
    sources.clear();
  }

  /** Забыть источник: нужен, когда «чужой» IP оказался нашим же новым адресом. */
  function forget(ip) {
    sources.delete(ip);
  }

  return { observe, snapshot, hasConflict, reset, prune, forget, isLocal, setOwnAddresses, setLocalAddresses };
}

module.exports = {
  DEFAULT_TTL_MS,
  toAddressSet,
  MAX_SOURCES,
  MAX_UNIVERSES_PER_SOURCE,
  isForeignSender,
  createForeignSourceWatch,
};
