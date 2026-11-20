const { spawn } = require('child_process');
const { randomUUID } = require('crypto');
const { StringDecoder } = require('string_decoder');
const path = require('path');
const fs = require('fs');

const MAX_LINE_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 8192;

function failure(code, error, extra = {}) {
  return { ok: false, code, error, ...extra };
}

function complete(callback, outcome) {
  if (typeof callback !== 'function') return;
  try { callback(outcome); } catch { /* an observer cannot break native I/O */ }
}

// Owns a single x86 process and a single addressed SDK session. Successful writes
// to stdin are deliberately not frame confirmations: only the SDK SEND reply is.
class MartinBridge {
  constructor(opts = {}) {
    this.exePath = opts.exePath || MartinBridge.defaultExePath();
    this.spawnProcess = opts.spawn || spawn;
    this.existsSync = opts.existsSync || fs.existsSync;
    this.startTimeoutMs = opts.startTimeoutMs ?? 20000;
    this.scanTimeoutMs = opts.scanTimeoutMs ?? 10000;
    this.openTimeoutMs = opts.openTimeoutMs ?? 20000;
    this.closeTimeoutMs = opts.closeTimeoutMs ?? 1800;
    this.sendTimeoutMs = opts.sendTimeoutMs ?? 2000;
    this.spawnThrottleMs = opts.spawnThrottleMs ?? 5000;
    this.proc = null;
    this.ready = false;
    this.disposed = false;
    this.lastError = null;
    this.stderr = '';
    this._starting = null;
    this._startResolve = null;
    this._startTimer = null;
    this._lastSpawnAt = null;
    this._nextId = 1;
    this._requests = new Map();
    this._writeQueue = [];
    this._writeBlocked = false;
    this._drainTimer = null;
    this._session = null;
    this._listeners = new Map();
    this._scanPromise = null;
  }

  static defaultExePath(resourcesPath = process.resourcesPath, existsSync = fs.existsSync) {
    try {
      if (resourcesPath) {
        const packaged = path.join(resourcesPath, 'martin', 'MartinSidecar.exe');
        if (existsSync(packaged)) return packaged;
      }
    } catch { /* an Electron development runtime also has resourcesPath */ }
    return path.resolve(__dirname, '..', '..', 'build', 'martin', 'MartinSidecar.exe');
  }

  isAvailable() {
    try { return !this.disposed && this.existsSync(this.exePath); } catch { return false; }
  }

  subscribe(session, listener) {
    if (!this._listeners.has(session)) this._listeners.set(session, new Set());
    const listeners = this._listeners.get(session);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
      if (!listeners.size && this._listeners.get(session) === listeners) this._listeners.delete(session);
    };
  }

  _emit(session, event) {
    const listeners = this._listeners.get(session);
    if (!listeners) return;
    for (const listener of [...listeners]) complete(listener, event);
  }

  isSessionActive(session) {
    return !!(this.ready && this._session && this._session.id === session && this._session.state === 'open');
  }

  _settleStart(ok) {
    clearTimeout(this._startTimer);
    this._startTimer = null;
    const resolve = this._startResolve;
    this._startResolve = null;
    this._starting = null;
    if (resolve) resolve(ok);
  }

  _ensureReady() {
    if (this.disposed) return Promise.resolve(false);
    if (this.ready && this.proc) return Promise.resolve(true);
    if (this._starting) return this._starting;
    if (!this.isAvailable()) {
      this.lastError = failure('EXE_MISSING', 'Не найден MartinSidecar.exe');
      return Promise.resolve(false);
    }
    if (this._lastSpawnAt != null && Date.now() - this._lastSpawnAt < this.spawnThrottleMs) return Promise.resolve(false);
    this._lastSpawnAt = Date.now();
    this._starting = new Promise(resolve => { this._startResolve = resolve; });
    const starting = this._starting;
    let child;
    try {
      child = this.spawnProcess(this.exePath, [], {
        windowsHide: true,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: path.dirname(this.exePath),
      });
      this.proc = child;
      this.stderr = '';
      const decoder = new StringDecoder('utf8');
      let buffer = '';
      child.stdout.on('data', chunk => {
        if (this.proc !== child) return;
        buffer += decoder.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        let newline = buffer.indexOf('\n');
        while (newline !== -1 && this.proc === child) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (Buffer.byteLength(line) > MAX_LINE_BYTES) { this._endProcess(child, failure('PROTOCOL_ERROR', 'Слишком длинная строка MartinSidecar')); return; }
          if (line) {
            try { this._handleMessage(child, JSON.parse(line)); } catch { this._endProcess(child, failure('PROTOCOL_ERROR', 'Неверный JSON от MartinSidecar')); return; }
          }
          newline = buffer.indexOf('\n');
        }
        if (Buffer.byteLength(buffer) > MAX_LINE_BYTES) this._endProcess(child, failure('PROTOCOL_ERROR', 'Переполнен буфер строки MartinSidecar'));
      });
      child.stderr.on('data', chunk => {
        if (this.proc !== child) return;
        this.stderr = Buffer.from(this.stderr + String(chunk)).subarray(-MAX_STDERR_BYTES).toString('utf8');
      });
      const broken = error => this._endProcess(child, failure('PROCESS_ERROR', error.message || String(error)));
      child.on('error', broken);
      child.stdin.on('error', broken);
      child.stdout.on('error', broken);
      child.stderr.on('error', broken);
      child.stdin.on('drain', () => {
        if (this.proc !== child) return;
        this._writeBlocked = false;
        clearTimeout(this._drainTimer);
        this._drainTimer = null;
        this._flushWrites();
        this._pump();
      });
      child.on('exit', (code, signal) => this._endProcess(child,
        failure('PROCESS_EXIT', `MartinSidecar завершился (${code == null ? signal : code})`)));
      this._startTimer = setTimeout(() => this._endProcess(child,
        failure('START_TIMEOUT', 'MartinSidecar не запустился за отведённое время')), this.startTimeoutMs);
      this._startTimer.unref?.();
    } catch (error) {
      if (child && this.proc === child) this._endProcess(child, failure('SPAWN_ERROR', error.message));
      else { this.lastError = failure('SPAWN_ERROR', error.message); this._settleStart(false); }
    }
    return starting;
  }

  _handleMessage(child, message) {
    if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Invalid message');
    if (message.event === 'ready') {
      if (this.ready || message.version !== '1.0.0') { this._endProcess(child, failure('PROTOCOL_ERROR', 'Несовместимая версия MartinSidecar')); return; }
      this.ready = true;
      this.lastError = null;
      this._settleStart(true);
      return;
    }
    if (message.event === 'fatal') { this._endProcess(child, failure(message.code || 'NATIVE_FATAL', message.error || 'Ошибка MartinSidecar')); return; }
    if (message.event) {
      const session = this._session;
      if (!session || message.session !== session.id || session.state === 'closing') return;
      if (message.event === 'lost') {
        this._endProcess(child, failure(message.code || 'DEVICE_LOST', message.error || 'Контроллер Martin отключён'));
      } else if (message.event === 'native-call') {
        session.lastNativeCall = message;
        this._emit(session.id, message);
      }
      return;
    }
    const request = this._requests.get(message.id);
    if (!request || request.proc !== child) return;
    if (request.session && message.session !== request.session) return;
    if (typeof message.ok !== 'boolean') throw new Error('Missing outcome');
    if (request.command === 'SEND' && (!message.ok || message.confirmation !== 'sdk-buffer')) {
      const error = message.ok
        ? failure('BAD_CONFIRMATION', 'MartinSidecar не подтвердил запись в буфер SDK', { session: request.session })
        : message;
      if (this._session) this._session.state = 'failed';
      this._finishRequest(request, { ...error, fatal: true });
      this._endProcess(child, error);
      return;
    }
    this._finishRequest(request, message);
  }

  _request(command, fields, timeoutMs, onResult) {
    if (!this.proc || !this.ready) {
      const error = failure('NO_PROCESS', 'MartinSidecar не готов', { session: fields.session, fatal: true });
      complete(onResult, error);
      return Promise.resolve(error);
    }
    const child = this.proc;
    const id = this._nextId++;
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    const request = { id, command, session: fields.session, proc: child, resolve, onResult, startedAt: Date.now(), timer: null, message: { id, command, ...fields } };
    request.timer = setTimeout(() => {
      if (this._requests.get(id) !== request || this.proc !== child) return;
      this._endProcess(child, failure('TIMED_OUT', `Истекло время команды Martin ${command}`, { phase: 'watchdog' }));
    }, timeoutMs);
    request.timer.unref?.();
    this._requests.set(id, request);
    this._writeQueue.push(request);
    this._flushWrites();
    return promise;
  }

  _flushWrites() {
    const child = this.proc;
    if (!child || !this.ready || this._writeBlocked) return;
    while (this._writeQueue.length && this.proc === child && !this._writeBlocked) {
      const request = this._writeQueue.shift();
      if (this._requests.get(request.id) !== request) continue;
      try {
        const accepted = child.stdin.write(JSON.stringify(request.message) + '\n', error => {
          if (error) this._endProcess(child, failure('STDIN_ERROR', error.message || String(error)));
        });
        if (!accepted && this.proc === child) {
          this._writeBlocked = true;
          this._drainTimer = setTimeout(() => {
            if (this.proc === child && this._writeBlocked) this._endProcess(child,
              failure('TIMED_OUT', 'Канал записи MartinSidecar не освободился', { phase: 'watchdog' }));
          }, this.sendTimeoutMs);
          this._drainTimer.unref?.();
        }
      } catch (error) { this._endProcess(child, failure('STDIN_ERROR', error.message)); }
    }
  }

  _finishRequest(request, result) {
    if (this._requests.get(request.id) !== request) return;
    this._requests.delete(request.id);
    clearTimeout(request.timer);
    const outcome = { ...result, session: request.session || result.session, durationMs: Date.now() - request.startedAt };
    complete(request.onResult, outcome);
    request.resolve(outcome);
  }

  _cancelFrames(session) {
    for (const item of session.latest.values()) complete(item.callback, failure('CANCELLED', 'Кадр отменён', { session: session.id, cancelled: true, expected: true }));
    session.latest.clear();
  }

  _endProcess(child, error, expected = false) {
    if (this.proc !== child) return;
    this.proc = null;
    this.ready = false;
    this.lastError = { ...error, stderr: this.stderr };
    clearTimeout(this._drainTimer);
    this._drainTimer = null;
    this._writeBlocked = false;
    this._writeQueue = [];
    this._settleStart(false);
    const session = this._session;
    const intentional = expected || session?.state === 'closing';
    if (session) {
      session.state = 'dead';
      this._cancelFrames(session);
    }
    for (const request of [...this._requests.values()]) {
      if (request.proc === child) this._finishRequest(request, { ...error, fatal: !intentional, cancelled: intentional, expected: intentional });
    }
    if (this._session === session) this._session = null;
    try { child.kill(); } catch { /* only our child is ever terminated */ }
    if (session && !intentional) this._emit(session.id, {
      event: 'lost', session: session.id, ...error, stderr: this.stderr, lastNativeCall: session.lastNativeCall || null,
    });
    if (session) this._listeners.delete(session.id);
  }

  async scan() {
    // A user-triggered scan must return the inventory from this attempt: there
    // may be no later supervisor scan when another transport is already active.
    if (!await this._ensureReady()) {
      const error = new Error(this.lastError?.error || 'MartinSidecar не готов к поиску устройств');
      error.code = this.lastError?.code || 'NOT_READY';
      throw error;
    }
    if (!this._scanPromise) {
      this._scanPromise = this._request('SCAN', {}, this.scanTimeoutMs)
        .then(result => {
          if (!result.ok || !Array.isArray(result.devices)) {
            const error = new Error(result.error || 'Не удалось перечислить USB-контроллеры Martin');
            error.code = result.code || 'INVALID_SCAN_REPLY';
            throw error;
          }
          return result.devices;
        })
        .finally(() => { this._scanPromise = null; });
    }
    return this._scanPromise;
  }

  async open(instanceId, sessionId = randomUUID()) {
    if (typeof instanceId !== 'string' || !instanceId.trim()) return failure('INVALID_INSTANCE', 'Не задан USB InstanceId Martin', { session: sessionId });
    if (this._session) return failure('SESSION_BUSY', 'Другая сессия Martin ещё открыта или закрывается', { session: sessionId });
    const session = { id: sessionId, instanceId, state: 'opening', latest: new Map(), inFlight: null, lastUniverse: 2, closePromise: null };
    this._session = session;
    if (!await this._ensureReady()) {
      if (this._session === session) this._session = null;
      return { ...(this.lastError || failure('NOT_READY', 'MartinSidecar не готов')), session: sessionId };
    }
    if (this._session !== session || session.state !== 'opening') return failure('CANCELLED', 'Открытие Martin отменено', { session: sessionId, cancelled: true, expected: true });
    const result = await this._request('OPEN', { session: sessionId, instanceId }, this.openTimeoutMs);
    if (this._session !== session || session.state !== 'opening') return result.ok
      ? failure('CANCELLED', 'Открытие Martin отменено', { session: sessionId, cancelled: true, expected: true }) : result;
    if (!result.ok) { await this.close(sessionId); return result; }
    session.state = 'open';
    return result;
  }

  close(sessionId) {
    const session = this._session;
    if (!session || session.id !== sessionId) return Promise.resolve(failure('STALE_SESSION', 'Сессия Martin уже закрыта', { session: sessionId, cancelled: true, expected: true }));
    if (session.closePromise) return session.closePromise;
    session.state = 'closing';
    this._cancelFrames(session);
    for (const request of [...this._requests.values()]) {
      if (request.session === sessionId) this._finishRequest(request,
        failure('CANCELLED', 'Сессия Martin закрывается', { session: sessionId, cancelled: true, expected: true }));
    }
    session.closePromise = (async () => {
      const result = this.proc && this.ready
        ? await this._request('CLOSE', { session: sessionId }, this.closeTimeoutMs)
        : { ok: true, session: sessionId };
      if (!result.ok && result.code !== 'STALE_SESSION' && this.proc) this._endProcess(this.proc, result, true);
      if (this._session === session) this._session = null;
      this._listeners.delete(sessionId);
      return result;
    })();
    return session.closePromise;
  }

  send(sessionId, universe, data, callback) {
    const session = this._session;
    if (!this.isSessionActive(sessionId)) {
      complete(callback, failure('NO_SESSION', 'Сессия Martin не открыта', { session: sessionId, fatal: true }));
      return false;
    }
    if ((universe !== 1 && universe !== 2) || !Buffer.isBuffer(data) || data.length !== 512) {
      complete(callback, failure('INVALID_FRAME', 'Martin ожидает 512 байт и выход 1 или 2', { session: sessionId }));
      return false;
    }
    const previous = session.latest.get(universe);
    const item = { universe, data: Buffer.from(data), callback };
    session.latest.set(universe, item);
    if (previous) complete(previous.callback, failure('COALESCED', 'Кадр заменён более свежим', { session: sessionId, cancelled: true, expected: true, coalesced: true }));
    this._pump();
    return true;
  }

  _pump() {
    const session = this._session;
    if (!session || session.state !== 'open' || session.inFlight || !this.ready || this._writeBlocked) return;
    const preferred = session.lastUniverse === 1 ? 2 : 1;
    const universe = session.latest.has(preferred) ? preferred : (session.latest.has(1) ? 1 : 2);
    const item = session.latest.get(universe);
    if (!item) return;
    session.latest.delete(universe);
    session.lastUniverse = universe;
    session.inFlight = item;
    void this._request('SEND', { session: session.id, universe, data: item.data.toString('base64') }, this.sendTimeoutMs, outcome => {
      if (session.inFlight !== item) return;
      session.inFlight = null;
      complete(item.callback, outcome);
      if (this._session === session) this._pump();
    });
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    if (this.proc) this._endProcess(this.proc, failure('CANCELLED', 'MartinBridge остановлен'), true);
    else {
      this._settleStart(false);
      if (this._session) this._cancelFrames(this._session);
      this._session = null;
    }
    this._listeners.clear();
  }
}

let sharedBridge = null;
const exitEmitters = new WeakSet();

function getSharedBridge(opts = {}) {
  if (!sharedBridge || sharedBridge.disposed) sharedBridge = new MartinBridge(opts);
  const emitter = opts.exitEmitter || process;
  if (!exitEmitters.has(emitter)) {
    exitEmitters.add(emitter);
    emitter.once('exit', () => disposeSharedBridge());
  }
  return sharedBridge;
}

function disposeSharedBridge() {
  const bridge = sharedBridge;
  sharedBridge = null;
  if (bridge) bridge.dispose();
}

module.exports = { MartinBridge, getSharedBridge, disposeSharedBridge };
