using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent.Config;

namespace ZentrycDnsAgent.Transport;

/// <summary>
/// SQLite-backed persistent buffer for syslog messages that couldn't be sent.
/// Uses WAL mode for concurrent read/write. Automatically purges old entries.
/// Survives service restarts — any buffered messages from a previous crash
/// will be replayed on the next startup.
/// </summary>
public sealed class DiskBuffer : IDisposable
{
    private readonly BufferConfig _config;
    private readonly ILogger _logger;
    private readonly object _lock = new();
    private SqliteConnection? _connection;
    private long _count;

    public DiskBuffer(IOptions<BufferConfig> config)
    {
        _config = config.Value;
        _logger = Log.ForContext<DiskBuffer>();
    }

    public long Count => Interlocked.Read(ref _count);

    /// <summary>
    /// Initialize the SQLite database and create the buffer table.
    /// </summary>
    public void Initialize()
    {
        try
        {
            // Ensure directory exists
            var dir = Path.GetDirectoryName(_config.DatabasePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = _config.DatabasePath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Shared
            }.ToString();

            _connection = new SqliteConnection(connectionString);
            _connection.Open();

            // Enable WAL mode for concurrent access
            ExecuteNonQuery("PRAGMA journal_mode=WAL");
            ExecuteNonQuery("PRAGMA synchronous=NORMAL");
            ExecuteNonQuery("PRAGMA temp_store=MEMORY");

            // Create buffer table
            ExecuteNonQuery(@"
                CREATE TABLE IF NOT EXISTS buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )");

            // Create index for cleanup queries
            ExecuteNonQuery(@"
                CREATE INDEX IF NOT EXISTS idx_buffer_created
                ON buffer(created_at)");

            // Count existing buffered messages (from previous crash/restart)
            _count = ExecuteScalar("SELECT COUNT(*) FROM buffer");

            if (_count > 0)
                _logger.Information("Disk buffer initialized with {Count} pending messages from previous session",
                    _count);
            else
                _logger.Debug("Disk buffer initialized at {Path}", _config.DatabasePath);

            // Run initial cleanup
            Cleanup();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to initialize disk buffer at {Path}", _config.DatabasePath);
            throw;
        }
    }

    /// <summary>
    /// Add a syslog message to the persistent buffer.
    /// </summary>
    public void Enqueue(string message)
    {
        lock (_lock)
        {
            try
            {
                using var cmd = _connection!.CreateCommand();
                cmd.CommandText = "INSERT INTO buffer (message) VALUES (@msg)";
                cmd.Parameters.AddWithValue("@msg", message);
                cmd.ExecuteNonQuery();
                Interlocked.Increment(ref _count);
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Failed to buffer message to disk");
            }
        }
    }

    /// <summary>
    /// Try to dequeue the oldest buffered message.
    /// Returns false if the buffer is empty.
    /// </summary>
    public bool TryDequeue(out string message)
    {
        message = string.Empty;
        lock (_lock)
        {
            try
            {
                // Read oldest
                using var readCmd = _connection!.CreateCommand();
                readCmd.CommandText = "SELECT id, message FROM buffer ORDER BY id ASC LIMIT 1";
                using var reader = readCmd.ExecuteReader();

                if (!reader.Read())
                    return false;

                var id = reader.GetInt64(0);
                message = reader.GetString(1);
                reader.Close();

                // Delete it
                using var deleteCmd = _connection.CreateCommand();
                deleteCmd.CommandText = "DELETE FROM buffer WHERE id = @id";
                deleteCmd.Parameters.AddWithValue("@id", id);
                deleteCmd.ExecuteNonQuery();

                Interlocked.Decrement(ref _count);
                return true;
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Failed to dequeue from disk buffer");
                return false;
            }
        }
    }

    /// <summary>
    /// Remove old entries and enforce size limits.
    /// </summary>
    public void Cleanup()
    {
        lock (_lock)
        {
            try
            {
                // Remove entries older than MaxAgeDays
                using var ageCmd = _connection!.CreateCommand();
                ageCmd.CommandText = "DELETE FROM buffer WHERE created_at < datetime('now', @days)";
                ageCmd.Parameters.AddWithValue("@days", $"-{_config.MaxAgeDays} days");
                var ageDeleted = ageCmd.ExecuteNonQuery();

                // Enforce size limit: estimate ~200 bytes per message average
                var maxRows = (_config.MaxSizeMB * 1024 * 1024) / 200;
                using var sizeCmd = _connection.CreateCommand();
                sizeCmd.CommandText = @"
                    DELETE FROM buffer WHERE id IN (
                        SELECT id FROM buffer ORDER BY id ASC
                        LIMIT MAX(0, (SELECT COUNT(*) FROM buffer) - @max)
                    )";
                sizeCmd.Parameters.AddWithValue("@max", maxRows);
                var sizeDeleted = sizeCmd.ExecuteNonQuery();

                if (ageDeleted > 0 || sizeDeleted > 0)
                {
                    _logger.Debug("Buffer cleanup: removed {Age} expired + {Size} overflow entries",
                        ageDeleted, sizeDeleted);
                    ExecuteNonQuery("PRAGMA optimize");
                }

                _count = ExecuteScalar("SELECT COUNT(*) FROM buffer");
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Buffer cleanup failed");
            }
        }
    }

    private void ExecuteNonQuery(string sql)
    {
        using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private long ExecuteScalar(string sql)
    {
        using var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        var result = cmd.ExecuteScalar();
        return result is long l ? l : Convert.ToInt64(result);
    }

    public void Dispose()
    {
        _connection?.Close();
        _connection?.Dispose();
    }
}
