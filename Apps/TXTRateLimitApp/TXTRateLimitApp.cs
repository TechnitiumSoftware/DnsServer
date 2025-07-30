using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using TechnitiumLibrary.App;
using TechnitiumLibrary.DnsServer;

namespace TxtRateLimiter
{
    public class TxtRateLimiterApp : DnsServerApp
    {
        private readonly ConcurrentDictionary<string, RateLimitEntry> _clientLimits = new();
        private Timer _cleanupTimer;

        private int _maxRequests;
        private TimeSpan _timeWindow;
        private TimeSpan _cleanupInterval;

        public override string Name => "TXT Rate Limit";
        public override string Description => "Rate limits DNS TXT queries per client IP.";
        public override Version Version => new(1, 0);

        public TxtRateLimiterApp()
        {
            LoadConfig();
            _cleanupTimer = new Timer(Cleanup, null, _cleanupInterval, _cleanupInterval);
        }

        public override void Dispose()
        {
            _cleanupTimer?.Dispose();
        }

        public override DnsAppResolveResult ResolveRequest(DnsServerRequest request)
        {
            if (request.RequestType != DnsRecordType.TXT)
                return DnsAppResolveResult.Continue;

            string clientIP = request.RemoteEndPoint?.Address?.ToString();
            if (string.IsNullOrEmpty(clientIP))
                return DnsAppResolveResult.Continue;

            var now = DateTime.UtcNow;
            var entry = _clientLimits.GetOrAdd(clientIP, _ => new RateLimitEntry());

            lock (entry)
            {
                entry.PurgeOld(now - _timeWindow);

                if (entry.Timestamps.Count >= _maxRequests)
                {
                    return DnsAppResolveResult.ReplyWith(DnsServerResponse.Create(request, DnsResponseCode.Refused));
                }

                entry.Timestamps.Enqueue(now);
            }

            return DnsAppResolveResult.Continue;
        }

        private void Cleanup(object state)
        {
            var threshold = DateTime.UtcNow - _timeWindow;
            foreach (var kvp in _clientLimits)
            {
                var entry = kvp.Value;
                lock (entry)
                {
                    entry.PurgeOld(threshold);
                    if (entry.Timestamps.Count == 0)
                        _clientLimits.TryRemove(kvp.Key, out _);
                }
            }
        }

        private void LoadConfig()
        {
            try
            {
                const string configFile = "dnsApp.config";

                if (!File.Exists(configFile))
                {
                    SetDefaults();
                    return;
                }

                var json = File.ReadAllText(configFile);
                var config = JsonSerializer.Deserialize<TxtRateLimiterConfig>(json);

                _maxRequests = config?.MaxRequests ?? 5;
                _timeWindow = TimeSpan.FromSeconds(config?.TimeWindowSeconds ?? 60);
                _cleanupInterval = TimeSpan.FromSeconds(config?.CleanupIntervalSeconds ?? 300);
            }
            catch
            {
                SetDefaults();
            }
        }

        private void SetDefaults()
        {
            _maxRequests = 5;
            _timeWindow = TimeSpan.FromSeconds(60);
            _cleanupInterval = TimeSpan.FromSeconds(300);
        }

        private class RateLimitEntry
        {
            public Queue<DateTime> Timestamps = new();

            public void PurgeOld(DateTime threshold)
            {
                while (Timestamps.Count > 0 && Timestamps.Peek() < threshold)
                    Timestamps.Dequeue();
            }
        }

        private class TxtRateLimiterConfig
        {
            public int MaxRequests { get; set; } = 5;
            public int TimeWindowSeconds { get; set; } = 60;
            public int CleanupIntervalSeconds { get; set; } = 300;
        }
    }
}
