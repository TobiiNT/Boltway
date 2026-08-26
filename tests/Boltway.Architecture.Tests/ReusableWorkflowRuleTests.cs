using YamlDotNet.RepresentationModel;

namespace Boltway.Architecture.Tests;

/// <summary>
/// Rules about what the workflow files say, checked here because nothing else reads them.
/// </summary>
/// <remarks>
/// <para>
/// The architecture tests reflect over compiled assemblies; a workflow is neither compiled nor
/// covered by that scan, so until this file existed the only thing standing between a release
/// pipeline and a rule it broke was somebody remembering. Twice that was not enough.
/// </para>
/// <para>
/// Everything here reads the files on disk rather than a copy, and fails loudly when it cannot find
/// them: a workflow test that silently scans nothing is green in exactly the situation it was
/// written for.
/// </para>
/// </remarks>
public sealed class ReusableWorkflowRuleTests
{
    private static readonly string[] Levels = ["none", "read", "write"];

    /// <summary>
    /// A workflow called by another never asks for a permission its caller did not grant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// GitHub restricts a called workflow to the permissions of the job that calls it, and asking
    /// for more is not narrowed or ignored - <b>the whole dispatch fails before any job is
    /// scheduled</b>. The symptom is a run with conclusion <c>startup_failure</c>, zero jobs, and no
    /// annotation naming the scope, so the only way to find it is to compare the two files by hand.
    /// </para>
    /// <para>
    /// This has cost two releases. The first was <c>id-token</c>, needed by nuget.org Trusted
    /// Publishing and declared only in the called workflow: the tag-push path published and the
    /// documented release path could not, and it failed after the tag was pushed and after GitHub
    /// Packages was written - neither reversible. The second was <c>attestations</c>, added to
    /// <c>publish-packages.yml</c> in the commit that started attesting what it ships, with nothing
    /// exercising <c>release.yml</c> until the next release tried to cut a tag and never started.
    /// </para>
    /// <para>
    /// Both times a comment was written explaining the trap. The comment is still there; this is
    /// what makes it checkable.
    /// </para>
    /// </remarks>
    [Fact]
    public void A_called_workflow_never_asks_for_more_than_its_caller_grants()
    {
        var directory = WorkflowDirectory();
        var files = Directory.GetFiles(directory, "*.yml");

        Assert.NotEmpty(files);

        var problems = new List<string>();
        var callers = 0;

        foreach (var file in files)
        {
            var caller = Load(file);
            if (!TryGetMapping(caller, "jobs", out var jobs))
            {
                continue;
            }

            foreach (var entry in jobs.Children)
            {
                if (entry.Value is not YamlMappingNode job
                    || !TryGetScalar(job, "uses", out var uses)
                    || !uses.StartsWith("./", StringComparison.Ordinal))
                {
                    continue;
                }

                var calleePath = Path.Combine(RepositoryRoot(), uses[2..]);
                Assert.True(File.Exists(calleePath), $"{Path.GetFileName(file)} calls '{uses}', which does not exist.");

                callers++;

                var granted = Permissions(job);
                var asked = Asked(Load(calleePath));

                foreach (var (scope, want) in asked)
                {
                    var have = granted.GetValueOrDefault(scope, "none");
                    if (Rank(want) > Rank(have))
                    {
                        problems.Add(
                            $"{Path.GetFileName(file)} job '{entry.Key}' grants {scope}: {have}, but "
                                + $"{uses} asks for {scope}: {want}. The dispatch will fail at startup "
                                + "with no jobs and no annotation naming the scope.");
                    }
                }
            }
        }

        // The control for the assertion below: a scan that found no caller proves nothing, and the
        // two rules this file exists for both live on the release path.
        Assert.True(callers >= 2, $"only {callers} job(s) call a workflow in this repository - the scan found nothing to check");

        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>Where the workflows live, or a failure naming what it looked for.</summary>
    private static string WorkflowDirectory()
    {
        var directory = Path.Combine(RepositoryRoot(), ".github", "workflows");

        Assert.True(Directory.Exists(directory), $"no .github/workflows under '{RepositoryRoot()}'");
        return directory;
    }

    /// <summary>The repository root, walked up from the test assembly.</summary>
    /// <remarks>
    /// Walked rather than pinned as a relative path, so it survives a change to the output layout -
    /// and it throws rather than returning a default, because a test that quietly scans the wrong
    /// directory finds nothing and passes.
    /// </remarks>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Boltway.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"No Boltway.slnx above '{AppContext.BaseDirectory}'.");
    }

    private static YamlMappingNode Load(string path)
    {
        var stream = new YamlStream();
        using var reader = new StreamReader(path);
        stream.Load(reader);

        return (YamlMappingNode)stream.Documents[0].RootNode;
    }

    /// <summary>Every permission a workflow asks for, top-level and per job, keeping the widest.</summary>
    /// <remarks>
    /// Both levels, because either one can exceed the caller: a job-level block overrides the
    /// top-level one for that job rather than being bounded by it, so reading only the top would
    /// miss a job that asks for more than the whole file does.
    /// </remarks>
    private static Dictionary<string, string> Asked(YamlMappingNode workflow)
    {
        var asked = Permissions(workflow);

        if (TryGetMapping(workflow, "jobs", out var jobs))
        {
            foreach (var entry in jobs.Children)
            {
                if (entry.Value is not YamlMappingNode job)
                {
                    continue;
                }

                foreach (var (scope, level) in Permissions(job))
                {
                    if (Rank(level) > Rank(asked.GetValueOrDefault(scope, "none")))
                    {
                        asked[scope] = level;
                    }
                }
            }
        }

        return asked;
    }

    private static Dictionary<string, string> Permissions(YamlMappingNode node)
    {
        var permissions = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!node.Children.TryGetValue(new YamlScalarNode("permissions"), out var value))
        {
            return permissions;
        }

        // `permissions: read-all` and `write-all` are shorthands for every scope at that level. Read
        // as a wildcard rather than skipped, because skipping would let the shorthand hide exactly
        // the escalation this test is for.
        if (value is YamlScalarNode shorthand)
        {
            permissions["*"] = shorthand.Value == "write-all" ? "write" : "read";
            return permissions;
        }

        foreach (var entry in ((YamlMappingNode)value).Children)
        {
            permissions[((YamlScalarNode)entry.Key).Value!] = ((YamlScalarNode)entry.Value).Value!;
        }

        return permissions;
    }

    private static bool TryGetMapping(YamlMappingNode node, string key, out YamlMappingNode mapping)
    {
        if (node.Children.TryGetValue(new YamlScalarNode(key), out var value) && value is YamlMappingNode found)
        {
            mapping = found;
            return true;
        }

        mapping = null!;
        return false;
    }

    private static bool TryGetScalar(YamlMappingNode node, string key, out string value)
    {
        if (node.Children.TryGetValue(new YamlScalarNode(key), out var found) && found is YamlScalarNode scalar)
        {
            value = scalar.Value ?? string.Empty;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static int Rank(string level) => Array.IndexOf(Levels, level) is var index && index >= 0 ? index : 0;
}
