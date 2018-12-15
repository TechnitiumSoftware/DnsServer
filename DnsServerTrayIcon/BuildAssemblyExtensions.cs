using System;
using System.IO;
using System.Reflection;

namespace DnsServerTrayIcon
{
    public static class BuildAssemblyExtensions
    {
        public static DateTime GetLinkerTime(this Assembly assembly, TimeZoneInfo target = null)
        {
            var filePath = assembly.Location;
            const int c_PeHeaderOffset = 60;
            const int c_LinkerTimestampOffset = 8;

            var buffer = new byte[2048];

            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                stream.Read(buffer, 0, 2048);

            var offset = BitConverter.ToInt32(buffer, c_PeHeaderOffset);
            var secondsSince1970 = BitConverter.ToInt32(buffer, offset + c_LinkerTimestampOffset);
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            var linkTimeUtc = epoch.AddSeconds(secondsSince1970);

            var tz = target ?? TimeZoneInfo.Local;
            var localTime = TimeZoneInfo.ConvertTimeFromUtc(linkTimeUtc, tz);

            return localTime;
        }

        public static string GetBuildVersion(this Assembly assembly)
        {
            var linkTimeLocal = assembly.GetLinkerTime(TimeZoneInfo.Utc);
            return new Version(1, 0, 0,
            ((int)new TimeSpan(linkTimeLocal.Hour, linkTimeLocal.Minute, linkTimeLocal.Second).TotalSeconds) / 2).ToString();
        }
    }
}
