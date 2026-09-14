using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent.Collection;
using ZentrycDnsAgent.Config;
using ZentrycDnsAgent.Mapping;

namespace ZentrycDnsAgent.Transport;

/// <summary>
/// Sends DNS events as syslog messages over UDP to the Zentryc SIEM server.
/// Reads from the event channel, batches messages, and sends with retry logic.
/// Falls back to DiskBuffer when the server is unreachable.
/// </summary>
public sealed class SyslogSender : IDisposable
{
    private readonly ZentrycConfig _zentrycConfig;
    private readonly BufferConfig _bufferConfig;
    private readonly Channel<DnsEvent> _inputChannel;
    private readonly DiskBuffer _diskBuffer;
    private readonly ILogger _logger;

    private UdpClient? _udpClient;
    private IPEndPoint? _endpoint;
    private long _messagesSent;
    private long _messagesBuffered;
    private long _sendErrors;
    private bool _serverReachable = true;

    public SyslogSender(
        IOptions<ZentrycConfig> zentrycConfig,
        IOptions<BufferConfig> bufferConfig,
        Channel<DnsEvent> inputChannel,
        DiskBuffer diskBuffer)
    {
        _zentrycConfig = zentrycConfig.Value;
        _bufferConfig = bufferConfig.Value;
        _inputChannel = inputChannel;
        _diskBuffer = diskBuffer;
        _logger = Log.ForContext<SyslogSender>();
    }

    public long MessagesSent => Interlocked.Read(ref _messagesSent);
    public long MessagesBuffered => Interlocked.Read(ref _messagesBuffered);
    public long SendErrors => Interlocked.Read(ref _sendErrors);
    public bool ServerReachable => _serverReachable;

    /// <summary>
    /// Main send loop. Reads events from channel, formats as syslog, sends via UDP.
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        InitializeUdpClient();

        _logger.Information("Syslog sender started. Target: {Host}:{Port}/UDP",
            _zentrycConfig.ServerHost, _zentrycConfig.ServerPort);

        // Two parallel tasks: drain live events + replay buffered events
        var drainTask = DrainChannelAsync(ct);
        var replayTask = ReplayBufferAsync(ct);

        await Task.WhenAll(drainTask, replayTask);

        _logger.Information("Syslog sender stopped. Sent={Sent}, Buffered={Buffered}, Errors={Errors}",
            _messagesSent, _messagesBuffered, _sendErrors);
    }

    private async Task DrainChannelAsync(CancellationToken ct)
    {
        var batch = new List<DnsEvent>(_bufferConfig.BatchSize);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                batch.Clear();

                // Wait for first event
                if (!await _inputChannel.Reader.WaitToReadAsync(ct))
                    break;

                // Drain up to BatchSize events
                while (batch.Count < _bufferConfig.BatchSize &&
                       _inputChannel.Reader.TryRead(out var evt))
                {
                    batch.Add(evt);
                }

                // Send batch
                foreach (var evt in batch)
                {
                    var message = DnsEventMapper.ToSyslogMessage(evt);
                    await SendOrBufferAsync(message, ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in syslog drain loop");
                await Task.Delay(1000, ct);
            }
        }

        // Drain remaining events on shutdown
        while (_inputChannel.Reader.TryRead(out var remaining))
        {
            var message = DnsEventMapper.ToSyslogMessage(remaining);
            _diskBuffer.Enqueue(message);
            Interlocked.Increment(ref _messagesBuffered);
        }
    }

    private async Task ReplayBufferAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_bufferConfig.FlushIntervalMs * 5, ct);

                if (!_serverReachable || _diskBuffer.Count == 0)
                    continue;

                var replayed = 0;
                while (_diskBuffer.TryDequeue(out var message) && replayed < _bufferConfig.BatchSize)
                {
                    if (await TrySendAsync(message, ct))
                    {
                        replayed++;
                        Interlocked.Increment(ref _messagesSent);
                    }
                    else
                    {
                        // Server went offline during replay — put it back
                        _diskBuffer.Enqueue(message);
                        break;
                    }
                }

                if (replayed > 0)
                    _logger.Debug("Replayed {Count} buffered messages", replayed);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error in buffer replay loop");
            }
        }
    }

    private async Task SendOrBufferAsync(string message, CancellationToken ct)
    {
        if (_serverReachable && await TrySendAsync(message, ct))
        {
            Interlocked.Increment(ref _messagesSent);
        }
        else
        {
            _diskBuffer.Enqueue(message);
            Interlocked.Increment(ref _messagesBuffered);
        }
    }

    private async Task<bool> TrySendAsync(string message, CancellationToken ct)
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(message);

            if (_udpClient is null)
                InitializeUdpClient();

            await _udpClient!.SendAsync(bytes, bytes.Length, _endpoint);
            _serverReachable = true;
            return true;
        }
        catch (SocketException ex)
        {
            _serverReachable = false;
            Interlocked.Increment(ref _sendErrors);
            _logger.Warning("Syslog send failed ({Error}). Buffering to disk.", ex.SocketErrorCode);

            // Recreate client on socket errors
            RecreateUdpClient();
            return false;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _sendErrors);
            _logger.Debug(ex, "Syslog send error");
            return false;
        }
    }

    private void InitializeUdpClient()
    {
        _udpClient?.Dispose();
        _udpClient = new UdpClient();
        _udpClient.Client.SendBufferSize = 1024 * 1024; // 1MB send buffer
        _endpoint = new IPEndPoint(
            IPAddress.Parse(_zentrycConfig.ServerHost),
            _zentrycConfig.ServerPort);

        _logger.Debug("UDP client initialized for {Endpoint}", _endpoint);
    }

    private void RecreateUdpClient()
    {
        try
        {
            _udpClient?.Dispose();
            _udpClient = null;
        }
        catch { }
    }

    public void Dispose()
    {
        _udpClient?.Dispose();
    }
}
