using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace LogExporter.Sinks
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
        private static readonly JsonWriterOptions WriterOptions = new JsonWriterOptions
        {
            Indented = false
        };

        public static void WriteBatch(Stream target, IReadOnlyList<LogEntry> logs)
        {
            ArgumentNullException.ThrowIfNull(target);
            ArgumentNullException.ThrowIfNull(logs);

            if (logs.Count == 0)
            {
                return;
            }

            using Utf8JsonWriter writer = new Utf8JsonWriter(target, WriterOptions);

            for (int i = 0; i < logs.Count; i++)
            {
                JsonSerializer.Serialize(writer, logs[i]);
                writer.Flush();

                target.WriteByte((byte)'\n');

                if (i < logs.Count - 1)
                {
                    writer.Reset(target);
                }
            }
        }
    }
}
