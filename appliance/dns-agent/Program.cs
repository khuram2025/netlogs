using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace ZenShield;

sealed record Config(string Endpoint, string SourceId, string Token, string CertificateSha256, long SpoolLimitBytes = 1073741824);
sealed class DnsService : ServiceBase
{
    readonly CancellationTokenSource stop = new();
    readonly BlockingCollection<Dictionary<string, object?>> queue = new(50000);
    readonly string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ZenShield", "DnsAgent");
    TraceEventSession? session;
    Timer? statusTimer;
    readonly object statusLock = new();
    volatile bool stopping;
    Task? worker, reader, writer;
    readonly ConcurrentQueue<string> pending = new();
    long dropped, captured, sent, parseErrors, spoolBytes;
    string lastError = "", lastSend = "";
    DateTime lastHeartbeat = DateTime.MinValue;
    static readonly JsonSerializerOptions json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, PropertyNameCaseInsensitive = true };

    public DnsService() { ServiceName = "ZenShieldDnsAgent"; CanStop = true; AutoLog = true; }
    protected override void OnStart(string[] args)
    {
        Directory.CreateDirectory(Path.Combine(root, "spool"));
        var cfg = JsonSerializer.Deserialize<Config>(File.ReadAllText(Path.Combine(root, "config.json")), json)!;
        if (!Uri.TryCreate(cfg.Endpoint, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.AbsolutePath != "/api/dns/ingest") throw new InvalidOperationException("A verified HTTPS ingestion endpoint is required.");
        if (cfg.CertificateSha256.Length != 64 || cfg.Token.Length < 32 || !Guid.TryParse(cfg.SourceId, out _)) throw new InvalidOperationException("Invalid source configuration.");
        foreach(var path in Directory.GetFiles(Path.Combine(root,"spool"),"*.json").OrderBy(x=>x,StringComparer.Ordinal)) { pending.Enqueue(path); spoolBytes += new FileInfo(path).Length; }
        writer = Task.Run(() => Persist(cfg));
        worker = Task.Run(() => Deliver(cfg));
        reader = Task.Run(() => Capture());
        statusTimer = new Timer(_ => WriteStatus(),null,1000,5000);
    }
    void Capture()
    {
        try
        {
            using var trace = new TraceEventSession("ZenShield-DNS");
            session = trace; trace.StopOnDispose = true; trace.BufferSizeMB = 32;
            trace.Source.Dynamic.All += ev =>
            {
                if ((int)ev.ID < 256 || (int)ev.ID > 262) return;
                try
                {
                    var fields = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (var name in ev.PayloadNames)
                    {
                        var value = ev.PayloadByName(name);
                        if (value is byte[] bytes) fields[name] = Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 4096)));
                        else fields[name] = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
                    }
                    var record = new Dictionary<string, object?> { ["event_id"] = Guid.NewGuid().ToString(), ["timestamp"] = ev.TimeStamp.ToUniversalTime().ToString("O"), ["event_code"] = (int)ev.ID, ["fields"] = fields };
                    if (!queue.TryAdd(record)) Interlocked.Increment(ref dropped);
                    else Interlocked.Increment(ref captured);
                }
                catch { Interlocked.Increment(ref parseErrors); }
            };
            trace.EnableProvider("Microsoft-Windows-DNSServer", TraceEventLevel.Verbose, 0x7FFFF);
            using var flush = new Timer(_ => { if(stopping)return; try { trace.Flush(); } catch (Exception e) { if(!stopping){lastError="ETW flush: "+e.GetType().Name;Interlocked.Increment(ref parseErrors);} } }, null, 1000, 1000);
            trace.Source.Process();
            if (!stopping) throw new IOException("DNS ETW session stopped unexpectedly.");
        }
        catch (Exception e) { lastError = "Capture: " + e.GetType().Name; WriteStatus(); if (!stopping) Environment.Exit(1); }
    }
    void Persist(Config cfg)
    {
        var spool=Path.Combine(root,"spool");
        try
        {
            while (!queue.IsCompleted)
            {
                var batch=new List<Dictionary<string,object?>>(250);
                if(!queue.TryTake(out var first,250))continue;
                batch.Add(first);
                // Coalesce small bursts while keeping capture-to-disk latency bounded.
                var until=DateTime.UtcNow.AddMilliseconds(200);
                while(batch.Count<250 && DateTime.UtcNow<until) { if(queue.TryTake(out var next,10))batch.Add(next); else if(queue.IsCompleted)break; }
                var bytes=Encoding.UTF8.GetBytes(Payload(cfg,batch));
                if(Interlocked.Read(ref spoolBytes)+bytes.Length>cfg.SpoolLimitBytes) { Interlocked.Add(ref dropped,batch.Count);lastError="Disk buffer full; new events dropped";continue; }
                var path=Path.Combine(spool,DateTime.UtcNow.Ticks.ToString("D19")+"-"+Guid.NewGuid().ToString("N")+".json");
                using(var f=new FileStream(path+".tmp",FileMode.CreateNew,FileAccess.Write,FileShare.None,65536,FileOptions.WriteThrough)){f.Write(bytes);f.Flush(true);}
                File.Move(path+".tmp",path);Interlocked.Add(ref spoolBytes,bytes.Length);pending.Enqueue(path);
            }
        }
        catch(Exception e) { lastError="Disk writer: "+e.GetType().Name;WriteStatus();Environment.Exit(1); }
    }
    async Task Deliver(Config cfg)
    {
        var spool = Path.Combine(root, "spool");
        // Pin exactly this appliance certificate. No global certificate bypass or OS trust changes.
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) => cert != null && DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow <= cert.NotAfter.ToUniversalTime() && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData), Convert.FromHexString(cfg.CertificateSha256));
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", cfg.SourceId + "." + cfg.Token);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("ZenShield-DNS-Agent/1.0");
        DateTime retryAfter = DateTime.MinValue; int failures = 0;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                // Sending is independent of capture; continue persisting while the endpoint is unavailable.
                if (DateTime.UtcNow >= retryAfter)
                {
                    if (pending.TryPeek(out var path))
                    {
                        await Send(http, cfg, File.ReadAllText(path));
                        var size = new FileInfo(path).Length; File.Delete(path); pending.TryDequeue(out _); Interlocked.Add(ref spoolBytes,-size);
                        failures = 0; lastSend = DateTime.UtcNow.ToString("O"); lastError = "";
                    }
                    if (DateTime.UtcNow - lastHeartbeat > TimeSpan.FromSeconds(30))
                    {
                        await Send(http, cfg, Payload(cfg, [])); lastHeartbeat = DateTime.UtcNow;
                    }
                }
                WriteStatus();
                await Task.Delay(pending.IsEmpty || DateTime.UtcNow<retryAfter ? 500 : 20,stop.Token);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                lastError = e is HttpRequestException h && h.StatusCode.HasValue ? "Delivery: HTTP " + (int)h.StatusCode.Value : "Delivery: " + e.GetType().Name;
                retryAfter = DateTime.UtcNow.AddSeconds(Math.Min(60, Math.Pow(2, Math.Min(++failures, 6))) + Random.Shared.NextDouble());
                WriteStatus();
            }
        }
    }
    string Payload(Config cfg, List<Dictionary<string, object?>> events) => JsonSerializer.Serialize(new { batch_id = Guid.NewGuid().ToString(), hostname = Environment.MachineName, agent_version = "1.0.0", captured, dropped, parse_errors = parseErrors, etw_lost = session?.Source.EventsLost ?? 0, spool_bytes = spoolBytes, capture_running = reader is { IsCompleted: false }, events }, json);
    async Task Send(HttpClient http, Config cfg, string payload)
    {
        using var response = await http.PostAsync(cfg.Endpoint, new StringContent(payload, Encoding.UTF8, "application/json"), stop.Token);
        response.EnsureSuccessStatusCode();
        using var ack = JsonDocument.Parse(await response.Content.ReadAsStringAsync(stop.Token));
        using var request = JsonDocument.Parse(payload);
        if (ack.RootElement.GetProperty("batch_id").GetString() != request.RootElement.GetProperty("batch_id").GetString()) throw new IOException("Batch acknowledgement mismatch.");
        Interlocked.Add(ref sent, ack.RootElement.GetProperty("accepted").GetInt64());
    }
    void WriteStatus()
    {
        lock(statusLock)
        try { File.WriteAllText(Path.Combine(root, "status.tmp"), JsonSerializer.Serialize(new { updated_at = DateTime.UtcNow.ToString("O"), captured, sent, dropped, parse_errors = parseErrors, etw_lost = session?.Source.EventsLost ?? 0, spool_bytes = spoolBytes, last_send = lastSend, last_error = lastError }, json)); File.Move(Path.Combine(root, "status.tmp"), Path.Combine(root, "status.json"), true); } catch { }
    }
    protected override void OnStop() { stopping=true; session?.Dispose(); reader?.Wait(TimeSpan.FromSeconds(5)); queue.CompleteAdding(); writer?.Wait(TimeSpan.FromSeconds(15)); stop.Cancel(); worker?.Wait(TimeSpan.FromSeconds(5)); statusTimer?.Dispose(); WriteStatus(); }
    public static void Main(string[] args) { var service = new DnsService(); if (args.Contains("--console")) { service.OnStart(args); Console.CancelKeyPress += (_, e) => { e.Cancel = true; service.OnStop(); }; service.worker!.GetAwaiter().GetResult(); } else Run(service); }
}
