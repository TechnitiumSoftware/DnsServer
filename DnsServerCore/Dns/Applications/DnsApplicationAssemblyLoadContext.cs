using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;

namespace DnsServerCore.Dns.Applications
{
    class DnsApplicationAssemblyLoadContext : AssemblyLoadContext
    {
        #region variables

        private static readonly Type _dnsApplicationInterface = typeof(IDnsApplication);
        private readonly IDnsServer _dnsServer;

        private readonly List<Assembly> _appAssemblies = new();
        private readonly Dictionary<string, Assembly> _loadedAssemblies = new(StringComparer.OrdinalIgnoreCase);

        private readonly Dictionary<string, nint> _loadedUnmanagedDlls = new();
        readonly AssemblyDependencyResolver _dependencyResolver;

        readonly List<string> _unmanagedDllTempPaths = new List<string>();
        #endregion

        #region constructor

        public DnsApplicationAssemblyLoadContext(IDnsServer dnsServer)
            : base(isCollectible: true)
        {
            _dnsServer = dnsServer ?? throw new ArgumentNullException(nameof(dnsServer));

            Unloading += UnloadTempFiles;

            LoadPlugins();
        }

        #endregion

        #region public methods

        public void LoadPlugins()
        {
            var pluginDirectory = _dnsServer.ApplicationFolder;
            if (!Directory.Exists(pluginDirectory))
                throw new DirectoryNotFoundException($"Directory not found: {pluginDirectory}");

            // Step 1: Build the dependency graph
            var assemblyPaths = Directory.GetFiles(pluginDirectory, "*.dll");
            var dependencyGraph = BuildDependencyGraph(assemblyPaths);

            // Step 2: Resolve dependencies in correct load order
            foreach (var assemblyPath in ResolveLoadOrder(dependencyGraph))
            {
                LoadAssemblyAndDependencies(assemblyPath);
            }

            // Step 3: Identify and register plugins
            foreach (var assembly in _loadedAssemblies.Values)
            {
                RegisterPlugin(assembly);
            }
        }

        public IReadOnlyList<Assembly> AppAssemblies => _appAssemblies;

        #endregion

        #region overrides

        protected override Assembly Load(AssemblyName assemblyName)
        {
            return null; // Default behavior for now
        }

        protected override nint LoadUnmanagedDll(string unmanagedDllName)
        {
            string unmanagedDllPath = ResolveUnmanagedDllPath(unmanagedDllName);

            if (unmanagedDllPath is null)
                return nint.Zero;

            lock (_loadedUnmanagedDlls)
            {
                if (!_loadedUnmanagedDlls.TryGetValue(unmanagedDllPath, out nint dllHandle))
                {
                    string tempPath = CopyToTempFile(unmanagedDllPath);
                    dllHandle = LoadUnmanagedDllFromPath(tempPath);
                    _loadedUnmanagedDlls[unmanagedDllPath] = dllHandle;
                    _unmanagedDllTempPaths.Add(tempPath);
                }

                return dllHandle;
            }
        }

        #endregion

        #region private methods

        private void RegisterPlugin(Assembly assembly)
        {
            try
            {
                foreach (var type in assembly.GetTypes())
                {
                    if (type.GetInterfaces().Contains(_dnsApplicationInterface))
                    {
                        _appAssemblies.Add(assembly);
                        break;
                    }
                }
            }
            catch (ReflectionTypeLoadException ex)
            {
                _dnsServer.WriteLog($"Failed to load types from assembly {assembly.FullName}: {ex}");
            }
        }

        private void LoadAssemblyAndDependencies(string assemblyPath)
        {
            if (_loadedAssemblies.ContainsKey(assemblyPath))
                return;

            var assembly = LoadFromAssemblyPath(assemblyPath);
            _loadedAssemblies[assemblyPath] = assembly;

            foreach (var dependency in assembly.GetReferencedAssemblies())
            {
                var dependencyPath = Path.Combine(_dnsServer.ApplicationFolder, dependency.Name + ".dll");

                if (File.Exists(dependencyPath) && !_loadedAssemblies.ContainsKey(dependencyPath))
                {
                    LoadAssemblyAndDependencies(dependencyPath);
                }
                else if (!_loadedAssemblies.ContainsKey(dependency.FullName))
                {
                    try
                    {
                        var resolvedAssembly = LoadFromAssemblyName(dependency);
                        _loadedAssemblies[dependency.FullName] = resolvedAssembly;
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.WriteLog($"Failed to load dependency {dependency.FullName}: {ex}");
                    }
                }
            }
        }

        private Dictionary<string, List<string>> BuildDependencyGraph(IEnumerable<string> assemblyPaths)
        {
            var dependencyGraph = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var assemblyPath in assemblyPaths)
            {
                try
                {
                    var dependencies = Assembly.LoadFrom(assemblyPath)
                        .GetReferencedAssemblies()
                        .Select(dep => Path.Combine(_dnsServer.ApplicationFolder, dep.Name + ".dll"))
                        .Where(File.Exists)
                        .ToList();

                    dependencyGraph[assemblyPath] = dependencies;
                }
                catch (Exception ex)
                {
                    // Log or handle exceptions here if necessary
                    Debug.WriteLine($"Failed to analyze assembly {assemblyPath}: {ex}");
                }
            }

            return dependencyGraph;
        }

        private static List<string> ResolveLoadOrder(Dictionary<string, List<string>> dependencyGraph)
        {
            var resolved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sorted = new List<string>();

            void Visit(string assemblyPath)
            {
                if (resolved.Add(assemblyPath))
                {
                    foreach (var dependency in dependencyGraph.GetValueOrDefault(assemblyPath, new List<string>()))
                    {
                        Visit(dependency);
                    }
                    sorted.Add(assemblyPath);
                }
            }

            foreach (var assemblyPath in dependencyGraph.Keys)
            {
                Visit(assemblyPath);
            }

            return sorted;
        }

        private string ResolveUnmanagedDllPath(string unmanagedDllName)
        {
            if (_dependencyResolver != null)
            {
                var resolvedPath = _dependencyResolver.ResolveUnmanagedDllToPath(unmanagedDllName);
                if (!string.IsNullOrEmpty(resolvedPath) && File.Exists(resolvedPath))
                    return resolvedPath;
            }

            // Additional OS-specific lookup logic here if needed
            return null;
        }

        private static string CopyToTempFile(string filePath)
        {
            var tempPath = Path.GetTempFileName();

            using (var srcStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (var dstStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write))
            {
                srcStream.CopyTo(dstStream);
            }

            return tempPath;
        }

        private void UnloadTempFiles(AssemblyLoadContext context)
        {
            foreach (var tempPath in _unmanagedDllTempPaths)
            {
                try
                {
                    File.Delete(tempPath);
                }
                catch
                {
                    // Log or handle exceptions here if necessary
                }
            }
        }

        #endregion
    }
}
