using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("SvetoMaster Martin Universal USB-DMX helper")]
[assembly: AssemblyDescription("32-bit session-isolated transport for the installed Martin Universal USB-DMX driver")]
[assembly: AssemblyProduct("SvetoMaster")]
[assembly: AssemblyCompany("udmx.net")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace SvetoMaster.Martin
{
    internal static class Program
    {
        private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
        private static readonly object OutputLock = new object();
        internal static void Emit(object value)
        {
            lock (OutputLock) { Console.WriteLine(Json.Serialize(value)); Console.Out.Flush(); }
        }
        private static string Text(Dictionary<string, object> request, string name)
        {
            object value;
            return request.TryGetValue(name, out value) && value is string ? (string)value : null;
        }
        private static bool Handle(string line, Session session, ApplicationContext context)
        {
            object id = null; string token = null;
            try
            {
                if (line.Length > 8192) throw new MartinException("REQUEST_TOO_LARGE", "Слишком длинный запрос помощнику Martin.");
                Dictionary<string, object> request = Json.DeserializeObject(line) as Dictionary<string, object>;
                if (request == null || !request.TryGetValue("id", out id) || id == null)
                    throw new MartinException("INVALID_REQUEST", "Запрос Martin должен содержать id и command.");
                token = Text(request, "session");
                string command = Text(request, "command");
                if (command == "SCAN")
                    Emit(new { id = id, ok = true, devices = session.Scan() });
                else if (command == "OPEN")
                {
                    object result = session.Open(Text(request, "instanceId"), token);
                    Dictionary<string, object> reply = Json.Deserialize<Dictionary<string, object>>(Json.Serialize(result));
                    reply["id"] = id; reply["ok"] = true;
                    Emit(reply);
                }
                else if (command == "SEND")
                {
                    object rawUniverse; int universe;
                    if (!request.TryGetValue("universe", out rawUniverse) || !(rawUniverse is int) || !Int32.TryParse(rawUniverse.ToString(), out universe))
                        throw new MartinException("INVALID_FRAME", "Укажите номер выхода Martin 1 или 2.");
                    string data = Text(request, "data");
                    if (data == null || data.Length != 684) throw new MartinException("INVALID_FRAME", "Нужен полный DMX-кадр Martin: 512 байт в base64.");
                    byte[] bytes;
                    try { bytes = Convert.FromBase64String(data); }
                    catch (FormatException) { throw new MartinException("INVALID_FRAME", "Повреждён base64-кадр Martin."); }
                    session.Send(token, universe, bytes);
                    Emit(new { id = id, ok = true, session = token, confirmation = "sdk-buffer" });
                }
                else if (command == "CLOSE")
                {
                    bool cleanupOk = session.Close(token);
                    if (!cleanupOk) throw new MartinException("CLEANUP_FAILED", "Martin закрыт, но библиотека сообщила об ошибке завершения. Переподключите контроллер; подробности в диагностике.");
                    Emit(new { id = id, ok = true, session = token, closed = true, cleanupOk = true });
                }
                else if (command == "EXIT")
                {
                    session.Dispose();
                    Emit(new { id = id, ok = session.CleanupOk, session = token, closed = true, cleanupOk = session.CleanupOk });
                    context.ExitThread();
                    return true;
                }
                else throw new MartinException("UNKNOWN_COMMAND", "Неизвестная команда помощника Martin: " + command);
            }
            catch (Exception error)
            {
                MartinException known = error as MartinException;
                Emit(new { id = id, session = token, ok = false, error = error.Message,
                    code = known == null ? "NATIVE_FAILURE" : known.Code, closed = !session.Active, cleanupOk = session.CleanupOk });
            }
            return false;
        }
        [STAThread]
        private static int Main(string[] args)
        {
            Console.InputEncoding = new UTF8Encoding(false);
            Console.OutputEncoding = new UTF8Encoding(false);
            if (Array.IndexOf(args, "--self-test") >= 0) return SelfTest.Run();
            if (IntPtr.Size != 4)
            {
                Emit(new { @event = "fatal", code = "WRONG_PROCESS_ARCHITECTURE", error = "Для Martin требуется 32-битный помощник." });
                return 1;
            }
            Session session = new Session(new PnpScanner(), delegate { return new NativeApi(); },
                delegate(int message, Action removed) { return new NotificationWindow(message, removed); }, Emit);
            Queue<string> requests = new Queue<string>(); object requestLock = new object();
            bool eof = false;
            Thread input = new Thread(delegate()
            {
                try
                {
                    string line;
                    while ((line = Console.ReadLine()) != null)
                    {
                        lock (requestLock)
                        {
                            if (requests.Count >= 128)
                            {
                                Emit(new { @event = "fatal", code = "REQUEST_QUEUE_FULL", error = "Переполнена очередь помощника Martin." });
                                eof = true; return;
                            }
                            requests.Enqueue(line);
                        }
                    }
                }
                catch (System.IO.IOException) { /* Broken stdin follows the same cleanup path as EOF. */ }
                catch (ObjectDisposedException) { /* Parent closed its pipe. */ }
                finally { lock (requestLock) eof = true; }
            });
            input.IsBackground = true;
            using (ApplicationContext context = new ApplicationContext())
            using (System.Windows.Forms.Timer commands = new System.Windows.Forms.Timer())
            using (System.Windows.Forms.Timer health = new System.Windows.Forms.Timer())
            {
                commands.Interval = 10;
                commands.Tick += delegate
                {
                    for (int count = 0; count < 16; count++)
                    {
                        string line = null; bool done;
                        lock (requestLock) { if (requests.Count > 0) line = requests.Dequeue(); done = eof && requests.Count == 0; }
                        if (line != null && Handle(line, session, context)) break;
                        if (done) { context.ExitThread(); break; }
                        if (line == null) break;
                    }
                };
                health.Interval = 500;
                health.Tick += delegate { session.Poll(); };
                try
                {
                    commands.Start(); health.Start(); input.Start();
                    Emit(new { @event = "ready", version = "1.0.0" });
                    Application.Run(context);
                }
                finally { commands.Stop(); health.Stop(); session.Dispose(); }
            }
            return session.CleanupOk ? 0 : 1;
        }
    }
}
