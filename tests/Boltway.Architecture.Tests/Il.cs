using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Boltway.Architecture.Tests;

/// <summary>Loads the compiled assemblies and walks their IL.</summary>
internal static class Il
{
    /// <summary>One method, named the way a person would write it.</summary>
    internal readonly record struct MethodRef(string Assembly, string Type, string Method)
    {
        public override string ToString() => $"{Type}.{Method}  [{Assembly}]";
    }

    /// <summary>
    /// Every assembly the rules apply to. <b>Discovered, not listed.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// This was a hand-maintained array, and a review measured what that costs. Deleting one entry
    /// silently removed five rules' coverage of that assembly — three planted violations went from
    /// three failures to zero — with the suite still reporting 11/11. Two shipping assemblies with
    /// real code were already missing, and the comment explaining the membership criterion described
    /// a grant that no longer exists, so the one thing a maintainer would read to decide whether to
    /// add an assembly was wrong.
    /// </para>
    /// <para>
    /// A list of what to check is the same shape of mistake as a documented invariant: it is correct
    /// on the day it is written and silently wrong afterwards. Every Boltway assembly beside the
    /// test binary is now in scope automatically, so a new project is covered by every rule the day
    /// it builds, without anyone remembering.
    /// </para>
    /// <para>
    /// Test assemblies are excluded because the rules are about shipped behaviour — a test may
    /// legitimately construct a hostile <see cref="Uri"/> or call a banned API to prove a guard
    /// fires, and several do.
    /// </para>
    /// </remarks>
    internal static IReadOnlyList<string> AssemblyNames { get; } = Discover();

    private static List<string> Discover()
    {
        var directory = Path.GetDirectoryName(typeof(Il).Assembly.Location)!;

        var names = Directory.EnumerateFiles(directory, "Boltway.*.dll")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(n => n is not null && !n.EndsWith(".Tests", StringComparison.Ordinal))
            .Select(n => n!)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // The control for the discovery itself. An empty or near-empty result would make every rule
        // in the suite pass over nothing, which is the exact failure the old hand-written list
        // produced one assembly at a time.
        Assert.True(
            names.Count >= 5,
            $"Only {names.Count} Boltway assemblies were found beside the tests; the rules would "
            + "be scanning almost nothing. Found: " + string.Join(", ", names));

        return names;
    }

    private static readonly Lazy<List<AssemblyDefinition>> Loaded = new(Load);

    internal static IReadOnlyList<AssemblyDefinition> Assemblies => Loaded.Value;

    private static List<AssemblyDefinition> Load()
    {
        // Read the assemblies from beside the test binary rather than from a configured output path.
        // A path that names a configuration is a rule that silently stops running in Release.
        var directory = Path.GetDirectoryName(typeof(Il).Assembly.Location)!;
        List<AssemblyDefinition> loaded = [];

        foreach (var name in AssemblyNames)
        {
            var path = Path.Combine(directory, name + ".dll");

            Assert.True(File.Exists(path), $"{name}.dll is not beside the tests; the rules would silently pass.");

            loaded.Add(AssemblyDefinition.ReadAssembly(path));
        }

        return loaded;
    }

    /// <summary>Every method in every assembly, including compiler-generated ones.</summary>
    internal static IEnumerable<(AssemblyDefinition Assembly, TypeDefinition Type, MethodDefinition Method)> AllMethods()
    {
        foreach (var assembly in Assemblies)
        {
            foreach (var module in assembly.Modules)
            {
                foreach (var type in AllTypes(module.Types))
                {
                    foreach (var method in type.Methods)
                    {
                        yield return (assembly, type, method);
                    }
                }
            }
        }
    }

    /// <summary>
    /// The name of the type a reader would say this code lives in.
    /// </summary>
    /// <remarks>
    /// A call inside an <c>async</c> method or a lambda is emitted into a compiler-generated nested
    /// type — <c>AuthorizeEndpoint/&lt;HandleAsync&gt;d__1</c> — so a call-site rule comparing
    /// <c>FullName</c> against the type a person wrote does not match it. Every such rule was
    /// therefore blind to any call made from an async method, which in this codebase is most of
    /// them. Walking out to the outermost declaring type fixes all of them at once, and here rather
    /// than in each rule so a rule added later inherits it.
    /// </remarks>
    internal static string OutermostType(TypeDefinition type)
    {
        var current = type;

        while (current.DeclaringType is { } parent)
        {
            current = parent;
        }

        return current.FullName;
    }

    /// <summary>Nested types included — a lambda's closure is a nested type, and IL lands there.</summary>
    private static IEnumerable<TypeDefinition> AllTypes(IEnumerable<TypeDefinition> types)
    {
        foreach (var type in types)
        {
            yield return type;

            foreach (var nested in AllTypes(type.NestedTypes))
            {
                yield return nested;
            }
        }
    }

    /// <summary>Every method that emits a call to <paramref name="predicate"/>.</summary>
    internal static IReadOnlyList<MethodRef> CallersOf(Func<MethodReference, bool> predicate)
    {
        var callers = new List<MethodRef>();

        foreach (var (assembly, type, method) in AllMethods())
        {
            if (!method.HasBody)
            {
                continue;
            }

            foreach (var instruction in method.Body.Instructions)
            {
                if (instruction.Operand is MethodReference called && predicate(called))
                {
                    callers.Add(new MethodRef(assembly.Name.Name, OutermostType(type), method.Name));
                    break;
                }
            }
        }

        return callers;
    }

    /// <summary>
    /// Every method reachable from <paramref name="root"/>, following calls transitively.
    /// </summary>
    /// <remarks>
    /// Transitivity is what makes a ban mean anything. Without it, "the matcher does not touch
    /// <see cref="Uri"/>" is satisfied by moving the call one helper away, and the rule proves a
    /// property about a single method body rather than about the decision it makes.
    /// </remarks>
    /// <summary>
    /// How many call targets the last <see cref="ReachableFrom"/> could not resolve.
    /// </summary>
    /// <remarks>
    /// Exposed so a rule can assert it is zero. Cecil raises
    /// <see cref="AssemblyResolutionException"/> for a target in an assembly it cannot find, and
    /// swallowing that silently truncates the walk — which would turn a reachability rule green by
    /// failing to look, on a machine configured slightly differently from this one. Counting it
    /// makes the difference between "found no violation" and "did not look" observable.
    /// </remarks>
    internal static int UnresolvedCallTargets { get; private set; }

    internal static IReadOnlyList<MethodDefinition> ReachableFrom(MethodDefinition root)
    {
        UnresolvedCallTargets = 0;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var reached = new List<MethodDefinition>();
        var queue = new Queue<MethodDefinition>();

        queue.Enqueue(root);
        seen.Add(root.FullName);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            reached.Add(current);

            if (!current.HasBody)
            {
                continue;
            }

            foreach (var instruction in current.Body.Instructions)
            {
                if (instruction.Operand is not MethodReference called)
                {
                    continue;
                }

                MethodDefinition? resolved;

                try
                {
                    resolved = called.Resolve();
                }
                catch (AssemblyResolutionException)
                {
                    // Counted, not just skipped. See UnresolvedCallTargets.
                    UnresolvedCallTargets++;
                    continue;
                }

                if (resolved is null || !seen.Add(resolved.FullName))
                {
                    continue;
                }

                queue.Enqueue(resolved);
            }
        }

        return reached;
    }

    /// <summary>Find one method by type and name, failing the test when it has moved.</summary>
    internal static MethodDefinition Method(string typeFullName, string methodName)
    {
        foreach (var (_, type, method) in AllMethods())
        {
            if (string.Equals(type.FullName, typeFullName, StringComparison.Ordinal)
                && string.Equals(method.Name, methodName, StringComparison.Ordinal))
            {
                return method;
            }
        }

        Assert.Fail($"{typeFullName}.{methodName} was not found. A renamed target makes its rule vacuous.");
        return null!;
    }

    /// <summary>Every instruction in a method that references a member of a named type.</summary>
    internal static IReadOnlyList<string> ReferencesTo(MethodDefinition method, string typeFullName)
    {
        var found = new List<string>();

        if (!method.HasBody)
        {
            return found;
        }

        foreach (var instruction in method.Body.Instructions)
        {
            var referenced = instruction.Operand switch
            {
                MethodReference m => m.DeclaringType?.FullName,
                FieldReference f => f.DeclaringType?.FullName,
                TypeReference t => t.FullName,
                _ => null,
            };

            if (string.Equals(referenced, typeFullName, StringComparison.Ordinal))
            {
                found.Add($"{method.DeclaringType.FullName}.{method.Name} → {instruction.Operand}");
            }
        }

        return found;
    }
}
