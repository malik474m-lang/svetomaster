// ============================================================================
//  SiudiSidecar — 32-bit bridge process for Nicolaudie / Sunlite (SIUDI) DMX.
//
//  Electron (SvetoMaster) runs 64-bit and cannot load the 32-bit Nicolaudie SDK
//  (LsHardDevKit.dll). This tiny x86 process loads it via P/Invoke and exchanges
//  line-delimited commands with the main process over stdin/stdout:
//
//    IN  (one command per line):  <id> <CMD> [args...]
//        <id> SCAN                       -> {"id":..,"ok":true,"devices":[...]}
//        <id> OPEN <deviceIndex>         -> {"id":..,"ok":true,"universes":N}
//        <id> SEND <universeIdx> <b64>   -> (no reply; fire-and-forget hot path)
//        <id> CLOSE                      -> {"id":..,"ok":true}
//        <id> PING                       -> {"id":..,"ok":true}
//        <id> EXIT                       -> process exits
//    OUT (one JSON object per line):
//        {"event":"ready"}               emitted once after DHDK_init succeeds
//        {"event":"fatal","error":..}    DLL missing / init failed -> we exit
//        {"event":"lost","reason":..}    emitted once after N failed sends (unplug)
//        {"id":..,...}                   reply to a control command
//
//  The P/Invoke signatures are the ones validated end-to-end against a real
//  SIUDI7B (see ДОК/siudi-probe). SIUDI7A with firmware 1.20 is older than the
//  bundled DHDK/XHL and returns error 36 ("firmware too old"); that is reported
//  as-is so the app can tell the user plainly. There is deliberately NO fallback
//  library any more - see the note above DoOpen. Build:
//  scripts/build-siudi-sidecar.mjs (csc /platform:x86). NOTE: keep this file
//  dependency-free (framework assemblies only) so it compiles with the built-in
//  csc.exe on any Windows.
// ============================================================================
using System;
using System.IO;
using System.Text;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;

// --- Assembly identity (Win32 VERSIONINFO) ---
// csc bakes these attributes into the exe's version resource. Without them the
// sidecar shipped as an anonymous 12 KB MSIL binary: FileVersion 0.0.0.0, no
// CompanyName / ProductName keys at all, empty description and copyright. That
// "nameless tiny .NET helper" profile is one of the traits cloud ML classifiers
// weigh, and it cost us a false positive on a user's machine (Kaspersky
// UDS:Trojan-Downloader.MSIL.GenericML.xnet, 2026-08-21) - this process has no
// network code whatsoever: it only pipes stdin/stdout and P/Invokes the SDK.
// The version is the SIDECAR's own (bump when its protocol/logic changes); it is
// deliberately NOT tied to the app version, which would silently rot here.
// 1.1.0.0 (2026-09-05): the legacy SIUDI7A fallback became reachable at all (the
// getLastError entry point was a template placeholder), per-universe loss
// tracking, universe probing no longer trusts the pre-open SDK hint.
// 1.2.0.0 (2026-09-30): the DasHard2006 fallback is removed (it never opened a
// single SIUDI7A 1.20 in the field and would pop firmware dialogs if reached).
// This file is UTF-8 without a BOM, so the build passes /codepage:65001 to csc
// (build-siudi-sidecar.mjs) - otherwise the copyright sign below would be
// decoded in the build host's ANSI code page and land mangled in the resource.
[assembly: AssemblyTitle("SvetoMaster Sunlite (Nicolaudie) DMX bridge")]
[assembly: AssemblyDescription("32-bit helper process that drives SIUDI / Sunlite DMX interfaces for SvetoMaster.")]
[assembly: AssemblyProduct("SvetoMaster")]
[assembly: AssemblyCompany("udmx.net")]
[assembly: AssemblyCopyright("© udmx.net")]
[assembly: AssemblyVersion("1.2.0.0")]
[assembly: AssemblyFileVersion("1.2.0.0")]

namespace SvetoMaster
{
    internal static class SiudiSidecar
    {
        // ─── Nicolaudie DHDK API (LsHardDevKit.dll, x86, __stdcall) ──────────
        private const string DLL = "LsHardDevKit.dll";
        private const int DHDK_USB_PROTOCOL = 1;   // DHDK_init(protocol) — 1 = USB
        private const int DHDK_DMXOUT = 1;         // configureDmxUniverse mode
        private const int LOST_THRESHOLD = 20;     // consec. failed sends ≈ 0.5s @40Hz

        [DllImport(DLL, EntryPoint = "_DHDK_init@8", CallingConvention = CallingConvention.StdCall, ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern void DHDK_init(int protocol, string softwareName);
        [DllImport(DLL, EntryPoint = "_DHDK_deinit@0", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern void DHDK_deinit();
        [DllImport(DLL, EntryPoint = "_DHDK_enumerate@0", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_enumerate();
        [DllImport(DLL, EntryPoint = "_DHDK_getDeviceCount@0", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_getDeviceCount();
        [DllImport(DLL, EntryPoint = "_DHDK_getDevice@4", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_getDevice(int iDevice);
        [DllImport(DLL, EntryPoint = "_DHDK_openDevice@4", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_openDevice(int hDevice);
        [DllImport(DLL, EntryPoint = "_DHDK_closeDevice@4", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern void DHDK_closeDevice(int hDevice);
        [DllImport(DLL, EntryPoint = "_DHDK_getDeviceName@12", CallingConvention = CallingConvention.StdCall, ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern int DHDK_getDeviceName(int hDevice, StringBuilder buffer, int size);
        [DllImport(DLL, EntryPoint = "_DHDK_getDeviceTypeName@12", CallingConvention = CallingConvention.StdCall, ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern int DHDK_getDeviceTypeName(int hDevice, StringBuilder buffer, int size);
        [DllImport(DLL, EntryPoint = "_DHDK_getDeviceSerial@4", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_getDeviceSerial(int hDevice);
        [DllImport(DLL, EntryPoint = "_DHDK_getDmxUniverseCount@4", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_getDmxUniverseCount(int hDevice);
        [DllImport(DLL, EntryPoint = "_DHDK_getDmxUniverse@8", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_getDmxUniverse(int hDevice, int index);
        [DllImport(DLL, EntryPoint = "_DHDK_configureDmxUniverse@8", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_configureDmxUniverse(int hUniverse, int mode);
        [DllImport(DLL, EntryPoint = "_DHDK_sendDmx@12", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_sendDmx(int hUniverse, byte[] buffer, int size);
        // NOTE: every entry point here is the REAL decorated export (`_NAME@bytes`).
        // This one used to read "__P__DHDK_getLastError__S0__" - not a name at all
        // but an un-substituted placeholder from the diagnostic template in
        // ДОК/siudi-probe/SIUDI-ТЕСТ3.bat, where the child script rewrites `__P__`
        // to `_` and `__S<n>__` to `@<n>` before compiling. Copied verbatim it threw
        // EntryPointNotFoundException on every call; the swallowed exception left
        // `error` at 0, so `error == 36` never held and the (since removed) SIUDI7A
        // fallback was unreachable code (2026-09-05). The real code matters just as
        // much today: the app turns "DHDK error 36" into a plain "firmware too old"
        // message (main/clientHealth.js). Guarded by
        // src/__tests__/unit/siudiSidecarEntryPoints.test.ts.
        [DllImport(DLL, EntryPoint = "_DHDK_getLastError@0", CallingConvention = CallingConvention.StdCall, ExactSpelling = true)]
        private static extern int DHDK_getLastError();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SetDllDirectory(string path);

        // ─── State (single-threaded: the read loop drives everything) ────────
        private static int _openDevice = -1;
        private static int[] _universes = new int[0];
        // One streak per universe: a multi-output box loses a single DMX port
        // without the others noticing, and a shared counter was reset by every
        // successful frame to a neighbouring universe (so the loss stayed silent).
        private static int[] _sendFailStreaks = new int[0];
        private static bool _lostEmitted = false;
        private static readonly object _outLock = new object();

        private static void Main(string[] args)
        {
            try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }

            // Resolve LsHardDevKit.dll: an explicit dir arg wins, else next to the exe.
            try { SetDllDirectory(AppDomain.CurrentDomain.BaseDirectory); } catch { }
            if (args.Length >= 1 && !string.IsNullOrEmpty(args[0]))
            {
                try { SetDllDirectory(args[0]); } catch { }
            }

            // First P/Invoke also forces the DLL to load; a missing DLL / bad
            // runtime throws here and we report it as a clean fatal (fail-open).
            try { DHDK_init(DHDK_USB_PROTOCOL, "SvetoMaster"); }
            catch (Exception e)
            {
                Emit("{\"event\":\"fatal\",\"error\":" + JsonStr("init: " + e.Message) + "}");
                return;
            }

            Emit("{\"event\":\"ready\"}");

            // Read stdin ourselves instead of via Console.In: that one decodes with
            // the console code page, so a UTF-8 BOM arrives as three garbage
            // characters rather than U+FEFF and cannot be trimmed away. A client
            // whose writer emits that preamble is not hypothetical - Windows
            // PowerShell 5.1 (what every client actually runs) has no
            // StandardInputEncoding on ProcessStartInfo, so its default writer
            // prefixes the FIRST command with a BOM; that is exactly how the
            // one-click client probe timed out on its own opening SCAN. This
            // StreamReader decodes UTF-8 and swallows a leading BOM by itself.
            var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
            string line;
            while ((line = input.ReadLine()) != null)
            {
                // Second line of defence: a stray BOM/zero-width space anywhere
                // else must not decide whether we answer at all.
                line = line.Trim('\uFEFF', '\u200B', ' ', '\t');
                if (line.Length == 0) continue;
                try { Handle(line); }
                catch (Exception e)
                {
                    // Answer WITH the request id whenever the line carries one: a
                    // reply without it cannot be correlated on the Node side, which
                    // then sits out its 4 s timeout instead of failing at once.
                    string failedId = IdOf(line);
                    string body = "\"ok\":false,\"error\":" + JsonStr(e.Message);
                    if (failedId != null) Reply(failedId, body);
                    else Emit("{" + body + "}");
                }
            }
            Cleanup();
        }

        private static void Handle(string line)
        {
            // <id> <CMD> [args...]  — base64 payloads contain no spaces.
            string[] p = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (p.Length < 2) return;
            // The id is echoed into the reply verbatim, so it must be a bare
            // number — otherwise a stray line would produce invalid JSON.
            string id = IdOf(p[0]);
            if (id == null) return;
            string cmd = p[1];

            switch (cmd)
            {
                case "SCAN": DoScan(id); break;
                case "OPEN": DoOpen(id, int.Parse(p[2], CultureInfo.InvariantCulture)); break;
                case "SEND": DoSend(int.Parse(p[2], CultureInfo.InvariantCulture), p[3]); break;
                case "CLOSE": DoClose(); Reply(id, "\"ok\":true"); break;
                case "PING": Reply(id, "\"ok\":true"); break;
                case "EXIT": Cleanup(); Environment.Exit(0); break;
                default: Reply(id, "\"ok\":false,\"error\":\"unknown cmd\""); break;
            }
        }

        private static void DoScan(string id)
        {
            DHDK_enumerate();
            int n = DHDK_getDeviceCount();
            var sb = new StringBuilder();
            sb.Append("\"ok\":true,\"devices\":[");
            for (int i = 0; i < n; i++)
            {
                int h = DHDK_getDevice(i);
                var name = new StringBuilder(256); DHDK_getDeviceName(h, name, 256);
                var type = new StringBuilder(256); DHDK_getDeviceTypeName(h, type, 256);
                int serial = DHDK_getDeviceSerial(h);
                int uc = DHDK_getDmxUniverseCount(h);
                if (i > 0) sb.Append(',');
                sb.Append("{\"index\":").Append(i)
                  .Append(",\"name\":").Append(JsonStr(name.ToString()))
                  .Append(",\"type\":").Append(JsonStr(type.ToString()))
                  .Append(",\"serial\":").Append(serial)
                  .Append(",\"universes\":").Append(uc)
                  .Append('}');
            }
            sb.Append(']');
            Reply(id, sb.ToString());
        }

        // A refused open is reported with the SDK's own error code and nothing else.
        // Code 36 = "device firmware is older than this XHL": SIUDI7A units that
        // Nicolaudie keeps on firmware 1.20 on purpose. This used to fall back to the
        // 2014 DasHard2006.dll (96291bd, reachable since 2026-09-05). A probe on a real
        // SIUDI7A 1.20 (2026-09-30, ДОК/DMX_CONTROLLER_TROUBLESHOOTING.md §19) proved
        // it cannot open that firmware by ANY route - not even in a process that never
        // loaded DHDK - and once it does reach the device it apparently raises
        // firmware-upgrade message boxes. In the field it only stayed quiet because
        // DHDK still held the refused device. Removed for good: do not bring it back,
        // and do not "fix" it by releasing DHDK first.
        private static void DoOpen(string id, int index)
        {
            DoClose(); // release any previously-open device first
            int h = DHDK_getDevice(index);
            if (DHDK_openDevice(h) == 0)
            {
                int error = 0;
                string errorNote = "";
                try { error = DHDK_getLastError(); }
                catch (Exception e)
                {
                    // A broken/renamed export must NEVER masquerade as "error 0": the
                    // app reads this code to tell the user what actually went wrong.
                    errorNote = ", getLastError unavailable: " + e.GetType().Name;
                }
                Reply(id, "\"ok\":false,\"error\":" + JsonStr("openDevice failed (DHDK error " + error.ToString(CultureInfo.InvariantCulture) + errorNote + ")"));
                return;
            }

            _openDevice = h;
            int uc = DHDK_getDmxUniverseCount(h);
            _universes = new int[uc];
            for (int u = 0; u < uc; u++)
            {
                int uh = DHDK_getDmxUniverse(h, u);
                _universes[u] = uh;
                DHDK_configureDmxUniverse(uh, DHDK_DMXOUT);
            }
            _sendFailStreaks = new int[uc];
            _lostEmitted = false;
            Reply(id, "\"ok\":true,\"universes\":" + uc.ToString(CultureInfo.InvariantCulture) + ",\"backend\":\"DHDK\"");
        }

        // Fire-and-forget hot path: no per-frame reply. Consecutive failures past
        // the threshold surface once as a 'lost' event (physical unplug). The
        // streak is counted PER UNIVERSE: on a two/three-output box a healthy
        // neighbour used to reset the counter of a dead port, so losing a single
        // DMX output was invisible.
        private static void DoSend(int universe, string b64)
        {
            if (universe < 0 || universe >= _universes.Length) return;
            byte[] data = Convert.FromBase64String(b64);
            byte[] buf = data;
            if (data.Length != 512) { buf = new byte[512]; Array.Copy(data, buf, Math.Min(data.Length, 512)); }

            bool succeeded = DHDK_sendDmx(_universes[universe], buf, 512) != 0;
            if (universe >= _sendFailStreaks.Length) return; // open() sizes both arrays
            if (succeeded)
            {
                _sendFailStreaks[universe] = 0;
            }
            else if (!_lostEmitted && ++_sendFailStreaks[universe] >= LOST_THRESHOLD)
            {
                _lostEmitted = true;
                Emit("{\"event\":\"lost\",\"reason\":" + JsonStr("send failed on universe " + (universe + 1).ToString(CultureInfo.InvariantCulture)) + "}");
            }
        }

        // Closing releases the device; it does NOT push an all-zero frame first.
        // That matches every other transport in the app (uDMX, Enttec, Open DMX):
        // «Отключить» stops the wire and fixtures hold their last frame. Owner's
        // call, 2026-09-05 — do not add a blackout here for one interface family alone.
        private static void DoClose()
        {
            if (_openDevice >= 0)
            {
                try { DHDK_closeDevice(_openDevice); } catch { }
                _openDevice = -1;
                _universes = new int[0];
                _sendFailStreaks = new int[0];
            }
        }

        private static void Cleanup()
        {
            DoClose();
            try { DHDK_deinit(); } catch { }
        }

        // Leading token of a command line when it is a plain number (the bridge
        // and the client probe always send numeric ids); null for anything else.
        private static string IdOf(string line)
        {
            if (line == null) return null;
            int end = line.IndexOf(' ');
            string head = end < 0 ? line : line.Substring(0, end);
            if (head.Length == 0 || head.Length > 18) return null;
            foreach (char c in head) if (c < '0' || c > '9') return null;
            return head;
        }

        // ─── Line output ─────────────────────────────────────────────────────
        private static void Reply(string id, string body)
        {
            Emit("{\"id\":" + id + "," + body + "}");
        }

        private static void Emit(string json)
        {
            lock (_outLock)
            {
                Console.Out.Write(json);
                Console.Out.Write('\n');
                Console.Out.Flush();
            }
        }

        private static string JsonStr(string s)
        {
            if (s == null) return "\"\"";
            var sb = new StringBuilder(s.Length + 2);
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }
    }
}
