using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace LogExporter.Strategy
{
    /// <summary>
    /// ADR: NDJSON serialization is used by all export strategies and must remain
    /// consistent across sinks. Previously, each strategy copy/pasted its own
    /// serialization loop, creating long-term maintenance and drift risks.
    /// This helper centralizes NDJSON formatting so changes occur in one place,
    /// ensuring consistency, reducing boilerplate, and eliminating subtle bugs.
    /// </summary>
    public static class NdjsonSerializer
    {
        public static void WriteBatch(Stream target, IReadOnlyList<LogEntry> logs)
        {
            using var writer = new Utf8JsonWriter(target, new JsonWriterOptions
            {
                Indented = false,
                SkipValidation = true
            });

            for (int i = 0; i < logs.Count; i++)
            {
                JsonSerializer.Serialize(writer, logs[i], LogEntry.DnsLogSerializerOptions.Default);
                writer.WriteRawValue("\n"u8, skipInputValidation: true);
            }
        }
    }
}
