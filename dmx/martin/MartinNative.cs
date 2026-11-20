// SDK calls are pinned to the official 4.0.364 library, verified on both outputs.
// All hardware operations run on the sidecar's message-pump thread.
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Forms;

namespace SvetoMaster.Martin
{
    internal sealed class MartinException : Exception
    {
        internal readonly string Code;
        internal MartinException(string code, string text) : base(text) { Code = code; }
    }

    internal sealed class PnpDevice
    {
        public string instanceId;
        public string name;
        public string vendorId = "11BE";
        public string productId;
        public int problemCode;
        public string service;
        internal bool Supported { get { return productId == "F028" || productId == "F0A8"; } }
    }

    internal interface IPnp
    {
        // Includes unknown 11BE products internally: OPEN must not guess their mapping.
        List<PnpDevice> ReadAllMartin();
    }

    internal sealed class PnpScanner : IPnp
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DeviceInfo { public int cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(IntPtr guid, string enumerator, IntPtr parent, uint flags);
        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref DeviceInfo info);
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDeviceInstanceId(IntPtr set, ref DeviceInfo info, StringBuilder value, int length, out int required);
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set, ref DeviceInfo info, uint property, out uint type, byte[] value, uint length, out uint required);
        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
        [DllImport("cfgmgr32.dll")]
        private static extern uint CM_Get_DevNode_Status(out uint status, out uint problem, uint devInst, uint flags);
        private static MartinException Win32(string operation)
        {
            int code = Marshal.GetLastWin32Error();
            return new MartinException("PNP_WIN32_" + code, "Не удалось прочитать подключённые USB-устройства: " + operation + ", Win32=" + code + " (" + new Win32Exception(code).Message + ").");
        }
        private static string Property(IntPtr set, ref DeviceInfo info, uint property)
        {
            byte[] bytes = new byte[8192]; uint type, required;
            if (!SetupDiGetDeviceRegistryProperty(set, ref info, property, out type, bytes, (uint)bytes.Length, out required))
            {
                int code = Marshal.GetLastWin32Error();
                if (code == 13 || code == 1168) return ""; // Optional property absent.
                throw Win32("SetupDiGetDeviceRegistryProperty");
            }
            return Encoding.Unicode.GetString(bytes, 0, (int)Math.Min(required, (uint)bytes.Length)).TrimEnd('\0');
        }
        public List<PnpDevice> ReadAllMartin()
        {
            // PRESENT | ALLCLASSES. Restrict enumeration to USB; this never opens SDK/DMX.
            IntPtr set = SetupDiGetClassDevs(IntPtr.Zero, "USB", IntPtr.Zero, 2 | 4);
            if (set == new IntPtr(-1)) throw Win32("SetupDiGetClassDevs");
            try
            {
                List<PnpDevice> found = new List<PnpDevice>();
                for (uint index = 0; ; index++)
                {
                    DeviceInfo info = new DeviceInfo(); info.cbSize = Marshal.SizeOf(typeof(DeviceInfo));
                    if (!SetupDiEnumDeviceInfo(set, index, ref info))
                    {
                        if (Marshal.GetLastWin32Error() == 259) break;
                        throw Win32("SetupDiEnumDeviceInfo");
                    }
                    StringBuilder idBuffer = new StringBuilder(4096); int required;
                    if (!SetupDiGetDeviceInstanceId(set, ref info, idBuffer, idBuffer.Capacity, out required)) throw Win32("SetupDiGetDeviceInstanceId");
                    string id = idBuffer.ToString(); string upper = id.ToUpperInvariant();
                    if (!upper.StartsWith("USB\\VID_11BE&PID_", StringComparison.Ordinal)) continue;
                    string pid = upper.Length >= 21 ? upper.Substring(17, 4) : "";
                    // A composite child is not the verified physical interface.
                    if (upper.Length < 22 || upper[21] != '\\') pid = "UNKNOWN";
                    uint status, problem; uint cr = CM_Get_DevNode_Status(out status, out problem, info.DevInst, 0);
                    if (cr != 0) throw new MartinException("PNP_CM_" + cr, "Не удалось прочитать состояние Martin: CM_Get_DevNode_Status=" + cr + ".");
                    string name = Property(set, ref info, 12);
                    if (String.IsNullOrWhiteSpace(name)) name = Property(set, ref info, 0);
                    found.Add(new PnpDevice { instanceId = id, name = name, productId = pid, problemCode = (int)problem, service = Property(set, ref info, 4) });
                }
                return found;
            }
            finally { SetupDiDestroyDeviceInfoList(set); }
        }
    }

    internal interface IApi : IDisposable
    {
        uint Call(uint command, byte node, int value, IntPtr data);
        string ReadName(IntPtr pointer);
        object Metadata { get; }
    }

    internal sealed class NativeApi : IApi
    {
        internal const string KnownHash = "eb2420090304ba6e28cb7b74c5e8e6cafde98c7bbb16fd30cf71014cfd06a8c7";
        internal const string Export = "?Dmxbox@@YGKKEHPAX@Z";
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate uint Dmxbox(uint command, byte node, int value, IntPtr data);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr module);
        private IntPtr module;
        private Dmxbox function;
        private readonly object metadata;
        public object Metadata { get { return metadata; } }
        internal NativeApi()
        {
            if (IntPtr.Size != 4) throw new MartinException("WRONG_PROCESS_ARCHITECTURE", "Для Martin нужен 32-битный помощник СветоМастера.");
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string system = Path.Combine(windows, Environment.Is64BitOperatingSystem ? "SysWOW64" : "System32");
            string path = null;
            List<string> seen = new List<string>();
            foreach (string name in new string[] { "MartinUSBDMX.dll", "usbdmx.dll" })
            {
                string candidate = Path.Combine(system, name);
                if (!File.Exists(candidate)) continue;
                string hash = Hash(candidate); seen.Add(name + ": " + hash);
                if (hash == KnownHash) { path = candidate; break; }
            }
            if (path == null) throw new MartinException("SUPPORTED_DLL_NOT_FOUND", "Не найдена проверенная библиотека драйвера Martin Universal USB-DMX 4.0.364 в " + system + ". Установите штатный драйвер Martin; если LightJockey работает, отправьте диагностику СветоМастера. Найдено: " + String.Join("; ", seen.ToArray()));
            using (BinaryReader reader = new BinaryReader(File.OpenRead(path)))
            {
                reader.BaseStream.Position = 0x3c;
                reader.BaseStream.Position = reader.ReadInt32() + 4;
                if (reader.ReadUInt16() != 0x14c) throw new MartinException("WRONG_DLL_ARCHITECTURE", "Библиотека Martin должна быть x86: " + path);
            }
            // Same restricted loader policy as the physically verified probe.
            // No current-directory/PATH lookup; use only this installed directory + system.
            module = LoadLibraryEx(path, IntPtr.Zero, 0x100 | 0x800);
            if (module == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                throw new MartinException("DLL_LOAD_WIN32_" + error, "Не удалось загрузить штатную библиотеку Martin (включая x86 WDAPI921.dll), Win32=" + error + ": " + new Win32Exception(error).Message);
            }
            try
            {
                IntPtr address = GetProcAddress(module, Export);
                if (address == IntPtr.Zero) throw new MartinException("SDK_EXPORT_MISSING", "В библиотеке Martin отсутствует Dmxbox: " + Export);
                function = (Dmxbox)Marshal.GetDelegateForFunctionPointer(address, typeof(Dmxbox));
                metadata = new { path = path, sha256 = KnownHash, version = FileVersionInfo.GetVersionInfo(path).FileVersion };
            }
            catch { Dispose(); throw; }
        }
        private static string Hash(string path)
        {
            using (SHA256 hash = SHA256.Create())
            using (Stream stream = File.OpenRead(path)) return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }
        public uint Call(uint command, byte node, int value, IntPtr data) { return function(command, node, value, data); }
        public string ReadName(IntPtr pointer)
        {
            if (pointer == IntPtr.Zero) return "";
            byte[] bytes = new byte[16]; Marshal.Copy(pointer, bytes, 0, bytes.Length);
            int end = Array.IndexOf(bytes, (byte)0);
            return Encoding.ASCII.GetString(bytes, 0, end < 0 ? 15 : Math.Min(end, 15)).Trim();
        }
        public void Dispose() { if (module != IntPtr.Zero) { FreeLibrary(module); module = IntPtr.Zero; } }
    }

    internal interface IWindow : IDisposable
    {
        IntPtr Handle { get; }
        int Message { get; }
    }
    internal sealed class NotificationWindow : NativeWindow, IWindow
    {
        private readonly Action removed;
        private readonly int message;
        public int Message { get { return message; } }
        internal NotificationWindow(int message, Action removed)
        {
            this.message = message; this.removed = removed;
            CreateParams options = new CreateParams(); options.Caption = "SvetoMaster Martin session";
            options.Parent = new IntPtr(-3); // HWND_MESSAGE: a real hidden Win32 window.
            CreateHandle(options);
        }
        protected override void WndProc(ref Message value)
        {
            // DLL destructor uses PostMessage(hwnd, configuredMessage, 0, 4).
            if (value.Msg == message && value.LParam == new IntPtr(4)) removed();
            base.WndProc(ref value);
        }
        public void Dispose() { DestroyHandle(); }
    }

    internal sealed class Session : IDisposable
    {
        private readonly IPnp pnp;
        private readonly Func<IApi> createApi;
        private readonly Func<int, Action, IWindow> createWindow;
        private readonly Action<object> emit;
        private readonly HashSet<string> usedSessions = new HashSet<string>(StringComparer.Ordinal);
        private IApi api;
        private IWindow window;
        private string token;
        private string instance;
        private byte node;
        private bool initialized, opened, bound, closing;
        private int generation;
        internal bool CleanupOk { get; private set; }
        internal bool Active { get { return token != null; } }
        internal string Token { get { return token; } }
        internal Action<int> Sleep = Thread.Sleep;
        internal Session(IPnp pnp, Func<IApi> createApi, Func<int, Action, IWindow> createWindow, Action<object> emit)
        { this.pnp = pnp; this.createApi = createApi; this.createWindow = createWindow; this.emit = emit; CleanupOk = true; }
        internal List<PnpDevice> Scan() { return pnp.ReadAllMartin().FindAll(delegate(PnpDevice d) { return d.Supported; }); }
        private void ValidatePnp(string selected)
        {
            List<PnpDevice> all = pnp.ReadAllMartin();
            if (all.Exists(delegate(PnpDevice d) { return !d.Supported; }))
                throw new MartinException("UNKNOWN_MARTIN_PRESENT", "Подключено другое устройство Martin (VID 11BE). Отключите его: безопасно сопоставить его с библиотекой пока нельзя.");
            if (all.Count != 1) throw new MartinException("AMBIGUOUS_PNP", "Для подключения требуется ровно один Martin Universal USB-DMX на компьютере; найдено: " + all.Count + ".");
            if (!String.Equals(all[0].instanceId, selected, StringComparison.OrdinalIgnoreCase))
                throw new MartinException("PNP_DEVICE_CHANGED", "Выбранный USB-экземпляр Martin отключён или заменён. Выполните поиск и подключение заново.");
            if (all[0].problemCode != 0) throw new MartinException("PNP_PROBLEM_" + all[0].problemCode, "Windows сообщает об ошибке драйвера Martin: код " + all[0].problemCode + ".");
            if (!String.Equals(all[0].service, "WinDriver6", StringComparison.OrdinalIgnoreCase))
                throw new MartinException("UNSUPPORTED_DRIVER_SERVICE", "Для Martin требуется штатный драйвер WinDriver6; Windows использует: " + all[0].service + ".");
        }
        private static void Check(uint status, string operation)
        {
            if (status != 0) throw new MartinException("SDK_" + status.ToString("X8", CultureInfo.InvariantCulture), "Martin: ошибка " + operation + ", SDK=0x" + status.ToString("X8", CultureInfo.InvariantCulture) + ". Закройте LightJockey и другие программы, использующие этот контроллер.");
        }
        private uint Call(uint command, int value, IntPtr data, bool control)
        {
            byte target = command == 51 ? (byte)(value == 0 ? 0 : 255) : node;
            if (control) emit(new { @event = "native-call", phase = "before", session = token, command = command, node = target, value = value });
            uint status;
            try { status = api.Call(command, target, value, data); }
            catch (Exception error)
            {
                emit(new { @event = "native-call", phase = "failure", session = token, command = command, node = target, error = error.Message });
                throw;
            }
            if (control || status != 0) emit(new { @event = "native-call", phase = "after", session = token, command = command, node = target, status = "0x" + status.ToString("X8", CultureInfo.InvariantCulture) });
            return status;
        }
        private void Require(string requested)
        {
            if (token == null || !String.Equals(requested, token, StringComparison.Ordinal))
                throw new MartinException("STALE_SESSION", "Эта сессия Martin уже закрыта или заменена. Старый запрос не применяется к новому подключению.");
        }
        private void Anchor()
        {
            if (!bound || window == null) throw new MartinException("SDK_ANCHOR_MISSING", "Не установлена привязка сессии Martin.");
            IntPtr value = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                Marshal.WriteIntPtr(value, IntPtr.Zero);
                Check(Call(48, 0, value, false), "проверка привязки USB");
                if (Marshal.ReadIntPtr(value) != window.Handle)
                    throw new MartinException("SDK_NODE_REUSED", "Martin был отключён или заменён: библиотека создала другой экземпляр USB. Подключите контроллер заново.");
            }
            finally { Marshal.FreeHGlobal(value); }
        }
        private void SendFrame(int universe, byte[] data)
        {
            Anchor();
            IntPtr buffer = Marshal.AllocHGlobal(512);
            try { Marshal.Copy(data, 0, buffer, 512); Check(Call(5, universe - 1, buffer, false), "передача выхода " + universe); }
            finally { Marshal.FreeHGlobal(buffer); }
            Anchor();
        }
        internal object Open(string selected, string requested)
        {
            if (String.IsNullOrWhiteSpace(selected) || String.IsNullOrWhiteSpace(requested) || requested.Length > 128)
                throw new MartinException("INVALID_OPEN", "Не указаны USB-экземпляр и сессия Martin.");
            if (Active) throw new MartinException("SESSION_BUSY", "Martin уже открыт в другой сессии СветоМастера.");
            if (usedSessions.Contains(requested)) throw new MartinException("SESSION_REUSED", "Идентификатор закрытой сессии нельзя использовать повторно.");
            if (generation >= 16000) throw new MartinException("RESTART_REQUIRED", "Перезапустите помощник Martin после большого числа подключений.");
            ValidatePnp(selected);
            usedSessions.Add(requested); generation++;
            token = requested; instance = selected; CleanupOk = true;
            try
            {
                string captured = requested;
                window = createWindow(0x8000 + generation, delegate { if (!closing && token == captured) Lose(new MartinException("USB_REMOVED", "Martin отключён: родная библиотека сообщила об удалении устройства.")); });
                emit(new { @event = "native-call", phase = "before", operation = "load-native-runtime", session = token });
                try
                {
                    api = createApi();
                    emit(new { @event = "native-call", phase = "after", operation = "load-native-runtime", session = token, native = api.Metadata });
                }
                catch (Exception error)
                {
                    emit(new { @event = "native-call", phase = "failure", operation = "load-native-runtime", session = token, error = error.Message });
                    throw;
                }
                initialized = true;
                Check(Call(51, 0x11be, new IntPtr(0xf028), true), "инициализация");
                Sleep(350);
                ValidatePnp(selected);
                IntPtr list = Marshal.AllocHGlobal(256);
                try
                {
                    Marshal.Copy(new byte[256], 0, list, 256);
                    uint count = Call(54, 0, list, true);
                    if (count > 255) Check(count, "перечисление устройств");
                    if (count != 1 || Marshal.ReadByte(list) == 0)
                        throw new MartinException("AMBIGUOUS_SDK", "Родная библиотека Martin должна найти ровно один контроллер; найдено: " + count + ". Проверьте драйвер и закройте LightJockey.");
                    node = Marshal.ReadByte(list);
                }
                finally { Marshal.FreeHGlobal(list); }
                Check(Call(3, 0, IntPtr.Zero, true), "открытие"); opened = true;
                Check(Call(16, window.Message, window.Handle, true), "привязка USB-сессии"); bound = true;
                Anchor();
                string name; int firmware;
                IntPtr metadata = Marshal.AllocHGlobal(IntPtr.Size);
                try
                {
                    Marshal.WriteIntPtr(metadata, IntPtr.Zero);
                    Check(Call(46, 0, metadata, true), "чтение имени"); name = api.ReadName(Marshal.ReadIntPtr(metadata));
                    Marshal.WriteInt32(metadata, 0);
                    Check(Call(58, 0, metadata, true), "чтение прошивки"); firmware = (ushort)Marshal.ReadInt16(metadata);
                }
                finally { Marshal.FreeHGlobal(metadata); }
                Anchor();
                Check(Call(26, 0, IntPtr.Zero, true), "режим двух выходов");
                SendFrame(1, new byte[512]); SendFrame(2, new byte[512]); Sleep(120);
                ValidatePnp(selected); Anchor();
                return new { session = requested, universes = 2, backend = "MartinUSBDMX", native = api.Metadata, firmware = firmware, nativeName = name };
            }
            catch { Cleanup(true); throw; }
        }
        internal void Send(string requested, int universe, byte[] data)
        {
            Require(requested);
            if (universe < 1 || universe > 2 || data == null || data.Length != 512)
                throw new MartinException("INVALID_FRAME", "Martin принимает ровно 512 байт на выход 1 или 2.");
            try { SendFrame(universe, data); }
            catch (Exception error) { Lose(error); throw; }
        }
        internal bool Close(string requested)
        {
            Require(requested);
            return Cleanup(true);
        }
        internal void Poll()
        {
            if (!Active || closing) return;
            try { ValidatePnp(instance); Anchor(); }
            catch (Exception error) { Lose(error); }
        }
        private void Lose(Exception error)
        {
            if (!Active || closing) return;
            MartinException known = error as MartinException;
            emit(new { @event = "lost", session = token, code = known == null ? "NATIVE_FAILURE" : known.Code, error = error.Message });
            Cleanup(false);
        }
        private bool Cleanup(bool zero)
        {
            if (!Active || closing) return CleanupOk;
            closing = true;
            bool sameNode = false;
            try
            {
                if (opened && bound)
                {
                    try { ValidatePnp(instance); Anchor(); sameNode = true; }
                    catch (Exception error) { CleanupOk = false; CleanupError(error); }
                }
                if (zero && sameNode)
                {
                    for (int universe = 1; universe <= 2; universe++)
                    {
                        try { SendFrame(universe, new byte[512]); }
                        catch (Exception error) { CleanupOk = false; CleanupError(error); }
                    }
                    Sleep(120);
                }
                if (sameNode)
                {
                    try { Anchor(); Check(Call(1, 0, IntPtr.Zero, true), "закрытие"); }
                    catch (Exception error) { CleanupOk = false; CleanupError(error); }
                }
                // DEINIT owns only this sidecar SDK instance. A reused node is never sent
                // zeros/CLOSE1; deinit still releases its own library worker resources.
                if (initialized)
                {
                    try { Check(Call(51, 0, IntPtr.Zero, true), "завершение библиотеки"); }
                    catch (Exception error) { CleanupOk = false; CleanupError(error); }
                }
            }
            finally
            {
                initialized = false; opened = false; bound = false;
                if (api != null) { try { api.Dispose(); } catch (Exception error) { CleanupOk = false; CleanupError(error); } api = null; }
                if (window != null) { try { window.Dispose(); } catch (Exception error) { CleanupOk = false; CleanupError(error); } window = null; }
                node = 0; token = null; instance = null; closing = false;
            }
            return CleanupOk;
        }
        private void CleanupError(Exception error)
        { emit(new { @event = "native-call", phase = "cleanup-error", session = token, error = error.Message }); }
        public void Dispose() { Cleanup(true); }
    }
}
