// Fake-API checks exercise the production Session; no vendor DLL/USB is loaded.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SvetoMaster.Martin
{
    internal static class SelfTest
    {
        private sealed class FakePnp : IPnp
        {
            internal List<PnpDevice> Devices = new List<PnpDevice>();
            internal bool Fail;
            public List<PnpDevice> ReadAllMartin()
            {
                if (Fail) throw new MartinException("PNP_WIN32_5", "SetupAPI Win32=5");
                return new List<PnpDevice>(Devices);
            }
        }
        private sealed class CallRecord
        {
            internal uint Command;
            internal int Value;
            internal byte Node;
            internal byte[] Frame;
        }
        private sealed class FakeApi : IApi
        {
            internal List<CallRecord> Calls = new List<CallRecord>();
            internal int Count = 1;
            internal IntPtr Binding;
            internal uint FailCommand = UInt32.MaxValue;
            internal uint Failure = 0xd0000002;
            internal bool Disposed;
            internal bool ResetAfterSend;
            public object Metadata { get { return new { path = "fake", sha256 = NativeApi.KnownHash, version = "4.0.364" }; } }
            public uint Call(uint command, byte node, int value, IntPtr data)
            {
                CallRecord record = new CallRecord { Command = command, Node = node, Value = value };
                if (command == 5) { record.Frame = new byte[512]; Marshal.Copy(data, record.Frame, 0, 512); }
                Calls.Add(record);
                if (command == FailCommand) return Failure;
                if (command == 54) { for (int i = 0; i < Count; i++) Marshal.WriteByte(data, i, (byte)(i + 1)); return (uint)Count; }
                if (command == 16) Binding = data;
                if (command == 48) Marshal.WriteIntPtr(data, Binding);
                if (command == 46) Marshal.WriteIntPtr(data, IntPtr.Zero);
                if (command == 58) Marshal.WriteInt16(data, 0x108);
                if (command == 5 && ResetAfterSend) Binding = IntPtr.Zero;
                return 0;
            }
            public string ReadName(IntPtr pointer) { return ""; }
            public void Dispose() { Disposed = true; }
            internal int Times(uint command) { return Calls.FindAll(delegate(CallRecord c) { return c.Command == command; }).Count; }
            internal List<CallRecord> Frames { get { return Calls.FindAll(delegate(CallRecord c) { return c.Command == 5; }); } }
        }
        private sealed class FakeWindow : IWindow
        {
            internal Action Removed;
            internal bool Disposed;
            private readonly int message;
            public IntPtr Handle { get { return new IntPtr(message + 1000); } }
            public int Message { get { return message; } }
            internal FakeWindow(int message, Action removed) { this.message = message; Removed = removed; }
            public void Dispose() { Disposed = true; }
        }
        private sealed class Harness : IDisposable
        {
            internal const string Id = "USB\\VID_11BE&PID_F0A8\\TEST";
            internal FakePnp Pnp = new FakePnp();
            internal FakeApi Api;
            internal FakeWindow Window;
            internal Session Session;
            internal List<FakeApi> AllApis = new List<FakeApi>();
            internal List<object> Events = new List<object>();
            internal List<int> Sleeps = new List<int>();
            internal Action<FakeApi> Configure;
            internal bool FactoryFail;
            internal Harness()
            {
                Pnp.Devices.Add(Device(Id, "F0A8"));
                Session = new Session(Pnp, delegate
                {
                    if (FactoryFail) throw new MartinException("DLL_LOAD_WIN32_126", "DLL load failed, Win32=126");
                    Api = new FakeApi(); AllApis.Add(Api); if (Configure != null) Configure(Api); return Api;
                }, delegate(int message, Action removed) { Window = new FakeWindow(message, removed); return Window; }, delegate(object item) { Events.Add(item); });
                Session.Sleep = delegate(int milliseconds) { Sleeps.Add(milliseconds); };
            }
            internal void Open(string token) { Session.Open(Id, token); }
            internal static PnpDevice Device(string id, string pid)
            { return new PnpDevice { instanceId = id, productId = pid, service = "WinDriver6", problemCode = 0, name = "Martin Universal USB-DMX 2" }; }
            public void Dispose() { Session.Dispose(); }
        }
        private static int checks;
        private static List<string> failures;
        private static void Assert(bool condition, string label)
        { checks++; if (!condition) failures.Add(label); }
        private static void Error(Action action, string code, string label)
        {
            try { action(); Assert(false, label + ": expected " + code); }
            catch (MartinException error) { Assert(error.Code == code, label + ": got " + error.Code); }
        }
        private static bool IsZero(byte[] bytes)
        { foreach (byte value in bytes) if (value != 0) return false; return true; }
        private static bool HasLoadEvent(List<object> events, string phase, string token)
        {
            foreach (object value in events)
            {
                Type type = value.GetType();
                System.Reflection.PropertyInfo operation = type.GetProperty("operation");
                System.Reflection.PropertyInfo eventPhase = type.GetProperty("phase");
                System.Reflection.PropertyInfo eventSession = type.GetProperty("session");
                if (operation != null && eventPhase != null && eventSession != null
                    && Object.Equals(operation.GetValue(value, null), "load-native-runtime")
                    && Object.Equals(eventPhase.GetValue(value, null), phase)
                    && Object.Equals(eventSession.GetValue(value, null), token)) return true;
            }
            return false;
        }
        internal static int Run()
        {
            checks = 0; failures = new List<string>();
            try
            {
                using (Harness h = new Harness())
                {
                    Assert(h.Session.Scan().Count == 1, "scan present supported PnP");
                    Assert(h.AllApis.Count == 0 && h.Window == null, "scan does not load SDK or window");
                    h.Pnp.Devices.Add(Harness.Device("USB\\VID_11BE&PID_ABCD\\X", "ABCD"));
                    Assert(h.Session.Scan().Count == 1, "unknown model excluded from scan results");
                    Error(delegate { h.Open("unknown"); }, "UNKNOWN_MARTIN_PRESENT", "unknown Martin blocks OPEN");
                    Assert(h.AllApis.Count == 0, "unknown device cannot initialize SDK");
                }
                using (Harness h = new Harness())
                {
                    h.Pnp.Fail = true;
                    Error(delegate { h.Session.Scan(); }, "PNP_WIN32_5", "scan errors visible");
                    Assert(h.AllApis.Count == 0, "failed scan remains SDK-free");
                }
                using (Harness h = new Harness())
                {
                    h.Pnp.Devices.Clear();
                    Error(delegate { h.Open("none"); }, "AMBIGUOUS_PNP", "zero PnP blocks OPEN");
                    h.Pnp.Devices.Add(Harness.Device(Harness.Id, "F0A8"));
                    h.Pnp.Devices.Add(Harness.Device("USB\\VID_11BE&PID_F028\\OTHER", "F028"));
                    Error(delegate { h.Open("many"); }, "AMBIGUOUS_PNP", "multiple PnP blocks OPEN");
                    Assert(h.AllApis.Count == 0, "ambiguous PnP cannot initialize SDK");
                }
                using (Harness h = new Harness())
                {
                    Error(delegate { h.Session.Open("USB\\OTHER", "wrong"); }, "PNP_DEVICE_CHANGED", "exact PnP instance required");
                    h.Pnp.Devices[0].problemCode = 28;
                    Error(delegate { h.Open("problem"); }, "PNP_PROBLEM_28", "driver problem explicit");
                    h.Pnp.Devices[0].problemCode = 0; h.Pnp.Devices[0].service = "libusb";
                    Error(delegate { h.Open("service"); }, "UNSUPPORTED_DRIVER_SERVICE", "unverified driver service blocked");
                    Assert(h.AllApis.Count == 0, "preflight failures have no SDK calls");
                }
                using (Harness h = new Harness())
                {
                    h.FactoryFail = true;
                    Error(delegate { h.Open("loadfail"); }, "DLL_LOAD_WIN32_126", "runtime factory failure preserves Win32 code");
                    Assert(HasLoadEvent(h.Events, "before", "loadfail"), "runtime failure has session-scoped before event");
                    Assert(HasLoadEvent(h.Events, "failure", "loadfail") && !HasLoadEvent(h.Events, "after", "loadfail"), "runtime failure records failure without success");
                    Assert(!h.Session.Active && h.Session.CleanupOk && h.Window.Disposed && h.AllApis.Count == 0, "runtime factory failure cleans window/session without SDK calls");
                }
                using (Harness h = new Harness())
                {
                    object info = h.Session.Open(Harness.Id.ToLowerInvariant(), "session1");
                    Assert(info != null && h.Session.Active, "blank native name opens with unique PnP+SDK");
                    Assert(HasLoadEvent(h.Events, "before", "session1") && HasLoadEvent(h.Events, "after", "session1")
                        && !HasLoadEvent(h.Events, "failure", "session1"), "runtime success records session-scoped before/after events");
                    Assert(h.Api.Times(51) == 1 && h.Api.Calls[0].Node == 255 && h.Api.Calls[0].Value == 0x11be, "native INIT contract");
                    Assert(h.Api.Times(3) == 1 && h.Api.Times(16) == 1, "single native OPEN and window binding");
                    Assert(h.Api.Times(26) == 1 && h.Api.Calls.Find(delegate(CallRecord c) { return c.Command == 26; }).Value == 0, "mode zero means both outputs");
                    Assert(h.Api.Frames.Count == 2 && h.Api.Frames[0].Value == 0 && h.Api.Frames[1].Value == 1, "initial zeros for both outputs");
                    Assert(IsZero(h.Api.Frames[0].Frame) && IsZero(h.Api.Frames[1].Frame), "initial zeros contain 512 zero bytes");
                    int calls = h.Api.Calls.Count;
                    Assert(h.Session.Scan().Count == 1 && h.Api.Calls.Count == calls, "scan during output never touches SDK");
                    Error(delegate { h.Open("other"); }, "SESSION_BUSY", "second OPEN cannot replace live session");
                    byte[] first = new byte[512]; first[0] = 11; first[511] = 12;
                    byte[] second = new byte[512]; second[0] = 21; second[511] = 22;
                    h.Session.Send("session1", 1, first); h.Session.Send("session1", 2, second);
                    Assert(h.Api.Frames[2].Value == 0 && h.Api.Frames[2].Frame[0] == 11 && h.Api.Frames[2].Frame[511] == 12, "output1 preserves channels1/512");
                    Assert(h.Api.Frames[3].Value == 1 && h.Api.Frames[3].Frame[0] == 21 && h.Api.Frames[3].Frame[511] == 22, "output2 preserves different channels1/512");
                    Assert(h.Api.Times(48) >= 10, "native object sentinel checked around writes");
                    calls = h.Api.Calls.Count;
                    Error(delegate { h.Session.Send("stale", 1, first); }, "STALE_SESSION", "stale SEND rejected");
                    Error(delegate { h.Session.Close("stale"); }, "STALE_SESSION", "stale CLOSE rejected");
                    Error(delegate { h.Session.Send("session1", 0, first); }, "INVALID_FRAME", "output zero rejected");
                    Error(delegate { h.Session.Send("session1", 3, first); }, "INVALID_FRAME", "output three rejected");
                    Error(delegate { h.Session.Send("session1", 1, new byte[511]); }, "INVALID_FRAME", "short frame rejected");
                    Error(delegate { h.Session.Send("session1", 1, new byte[513]); }, "INVALID_FRAME", "oversized frame rejected");
                    Assert(h.Api.Calls.Count == calls && h.Session.Active, "invalid/stale requests do not touch or close current output");
                    Assert(h.Session.Close("session1"), "clean CLOSE succeeds");
                    Assert(!h.Session.Active && h.Api.Disposed && h.Window.Disposed, "CLOSE releases API/window/session");
                    Assert(h.Api.Frames.Count == 6 && IsZero(h.Api.Frames[4].Frame) && IsZero(h.Api.Frames[5].Frame), "CLOSE zeros both universes");
                    Assert(h.Api.Times(1) == 1 && h.Api.Times(51) == 2, "CLOSE then DEINIT exactly once");
                    Assert(h.Sleeps.FindAll(delegate(int ms) { return ms == 120; }).Count == 2, "allow native worker to flush before close");
                    Assert(h.Api.Times(2) == 0, "never use command2 as flush");
                    Error(delegate { h.Open("session1"); }, "SESSION_REUSED", "cannot recycle old session token");
                }
                for (int count = 0; count <= 2; count += 2)
                {
                    using (Harness h = new Harness())
                    {
                        int requested = count; h.Configure = delegate(FakeApi api) { api.Count = requested; };
                        Error(delegate { h.Open("sdk" + requested); }, "AMBIGUOUS_SDK", "SDK cardinality " + requested);
                        Assert(!h.Session.Active && h.Api.Disposed && h.Api.Times(3) == 0 && h.Api.Times(5) == 0, "ambiguous SDK closed without sends " + requested);
                        Assert(h.Api.Times(51) == 2, "ambiguous SDK DEINIT " + requested);
                    }
                }
                using (Harness h = new Harness())
                {
                    h.Configure = delegate(FakeApi api) { api.FailCommand = 26; };
                    Error(delegate { h.Open("modefail"); }, "SDK_D0000002", "mode failure has SDK status");
                    Assert(!h.Session.Active && h.Api.Disposed && h.Api.Times(1) == 1 && h.Api.Times(51) == 2, "partial OPEN cleans up");
                }
                using (Harness h = new Harness())
                {
                    h.Open("unplug"); FakeApi old = h.Api;
                    old.Binding = IntPtr.Zero; int sent = old.Times(5);
                    Error(delegate { h.Session.Send("unplug", 1, new byte[512]); }, "SDK_NODE_REUSED", "SDK accepting dead buffers still fails sentinel");
                    Assert(old.Times(5) == sent && old.Times(1) == 0, "reused node receives no SEND or CLOSE1");
                    Assert(!h.Session.Active && old.Disposed && old.Times(51) == 2, "reused node releases own SDK");
                    Assert(h.Events.Exists(delegate(object value) { return value.ToString().Contains("lost") && value.ToString().Contains("unplug"); }), "loss event has session");
                }
                using (Harness h = new Harness())
                {
                    h.Open("after-write"); h.Api.ResetAfterSend = true;
                    Error(delegate { h.Session.Send("after-write", 2, new byte[512]); }, "SDK_NODE_REUSED", "post-write sentinel catches replacement during SDK call");
                    Assert(!h.Session.Active && h.Api.Times(1) == 0, "post-write replacement not closed as old node");
                }
                using (Harness h = new Harness())
                {
                    h.Open("poll"); int sent = h.Api.Times(5); h.Pnp.Devices.Clear(); h.Session.Poll();
                    Assert(!h.Session.Active && h.Api.Times(5) == sent, "PnP loss detected without next SEND");
                    Assert(h.Api.Times(1) == 0 && h.Api.Times(51) == 2, "PnP loss skips addressing detached node");
                }
                using (Harness h = new Harness())
                {
                    h.Open("notification"); h.Window.Removed();
                    Assert(!h.Session.Active && h.Api.Disposed, "native removal notification tears down session");
                }
                using (Harness h = new Harness())
                {
                    h.Open("old"); Action lateRemoval = h.Window.Removed; int oldMessage = h.Window.Message;
                    h.Session.Close("old"); h.Open("new"); int calls = h.Api.Calls.Count;
                    lateRemoval();
                    Assert(h.Session.Active && h.Session.Token == "new" && h.Api.Calls.Count == calls, "late old native notification cannot close new session");
                    Assert(h.Window.Message != oldMessage, "message ID differs across sessions to reject recycled HWND posts");
                    Error(delegate { h.Session.Send("old", 1, new byte[512]); }, "STALE_SESSION", "old SEND after reopen");
                    Error(delegate { h.Session.Close("old"); }, "STALE_SESSION", "old CLOSE after reopen");
                    Assert(h.Api.Calls.Count == calls && h.Session.Active, "old operations leave new SDK untouched");
                }
                using (Harness h = new Harness())
                {
                    h.Open("sendfail"); h.Api.FailCommand = 5; h.Api.Failure = 0xd0000003;
                    Error(delegate { h.Session.Send("sendfail", 1, new byte[512]); }, "SDK_D0000003", "SEND failure includes real SDK status");
                    Assert(!h.Session.Active && h.Api.Disposed, "SEND failure releases session");
                }
                using (Harness h = new Harness())
                {
                    h.Open("cleanupfail"); h.Api.FailCommand = 5;
                    Assert(!h.Session.Close("cleanupfail"), "cleanup failure is returned");
                    Assert(h.Api.Times(5) == 4, "cleanup tries both zeros even when first fails");
                    Assert(!h.Session.Active && h.Api.Disposed && h.Api.Times(1) == 1 && h.Api.Times(51) == 2, "cleanup failure still releases all resources");
                }
                using (Harness h = new Harness())
                {
                    h.Open("eof"); h.Session.Dispose();
                    Assert(!h.Session.Active && h.Api.Times(5) == 4 && h.Api.Disposed, "EOF/dispose zeros and closes session");
                    int calls = h.Api.Calls.Count; h.Session.Dispose();
                    Assert(h.Api.Calls.Count == calls, "dispose is idempotent");
                }
            }
            catch (Exception error) { failures.Add("Unexpected test exception: " + error); }
            Program.Emit(new { @event = "self-test", ok = failures.Count == 0, checks = checks, failures = failures });
            return failures.Count == 0 ? 0 : 1;
        }
    }
}
