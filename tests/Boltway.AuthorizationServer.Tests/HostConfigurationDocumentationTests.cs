using System.Text.RegularExpressions;

namespace Boltway.AuthorizationServer.Tests;

/// <summary>
/// Every environment variable a host reads has a row in that host's README, and every row names a
/// variable it reads.
/// </summary>
/// <remarks>
/// <para>
/// <b>The host READMEs are the only documents in this repository an operator acts on today</b>, and
/// they had drifted in both directions at once. Reading the code and not the document:
/// <c>ADMIN_ROLES</c>, which the authorization server <i>refuses to start</i> without once the admin
/// API is on, appeared in no table - so the one setting whose absence costs a restart was the one
/// nothing told you to set. So did <c>CLIENTS</c>, while the admin BFF's own README said to register
/// it "in the server's <c>CLIENTS</c>": the admin UI could not be stood up from the documentation.
/// Reading the document and not the code: <c>SMTP_STARTTLS</c>, replaced by <c>SMTP_SECURITY</c>,
/// still documented with a warning attached to it - a value an operator could set, and did, that
/// this image never looks up and never complains about.
/// </para>
/// <para>
/// Both directions matter and they fail differently. A key with no row is a capability nobody can
/// reach. A row with no key is worse: it is a promise, the same shape as <c>N-06</c> one layer out,
/// and the operator has no way to tell - an environment variable nothing reads produces no error,
/// no log line and no symptom until the day the behaviour it was supposed to configure matters.
/// </para>
/// <para>
/// This is the <c>check:emitted</c> pattern the repository already uses in
/// <c>StructuralRuleTests.PackableProjects</c> and <c>Every_project_says_whether_it_packs</c>: the
/// source moved, so the artefact derived from it must move with it, or the build fails on purpose.
/// A README is an emitted artefact in exactly that sense - it is derived from <c>Program.cs</c> and
/// nothing but a person's memory was keeping it so.
/// </para>
/// <para>
/// <b>It reads the two files off disk rather than reflecting over a loaded host.</b> No test project
/// references either host - the only thing that has ever compiled <c>Program.cs</c> is the Docker
/// build, which is its own defect and is written up on <c>ProxyHeaders</c> - and referencing one to
/// get at its configuration would give this test a way to fail that has nothing to do with what it
/// measures. The repository root is found by shape, the same walk
/// <c>StructuralRuleTests.RepositoryRoot</c> makes, because a relative path with a fixed number of
/// <c>..</c> segments changes with the target framework and the configuration in the output path,
/// and a path that resolves to nothing turns an absence assertion into a pass.
/// </para>
/// <para>
/// <b>What it cannot see</b>: a key reached by something other than the four spellings below. Every
/// read in both hosts today goes through <c>config["…"]</c> or through <c>Required</c>,
/// <c>Flag</c> or <c>Duration</c>, and the helpers that wrap a single key - <c>LogFormat</c>,
/// <c>Hops</c> - read it with the indexer, so they are covered too. A fifth spelling would be
/// invisible here, which is what the count controls are for: they fail when the scan stops finding
/// what it used to rather than reporting green over a file it can no longer parse.
/// </para>
/// </remarks>
public sealed partial class HostConfigurationDocumentationTests
{
    /// <summary>The two deployables under <c>hosts/</c>, each with a README an operator reads.</summary>
    public static TheoryData<string> Hosts =>
    [
        "Boltway.AuthorizationServer.Host",
        "Boltway.AdminBff",
    ];

    /// <summary>
    /// Keys documented deliberately, and read by something other than the host's own
    /// <c>Program.cs</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A named list here rather than a suppression file, on the rule CLAUDE.md states for the
    /// architecture tests: an exemption goes in the code with a justification saying what makes this
    /// case different, never somewhere nobody reads it. Two entries, one reason.
    /// </para>
    /// <para>
    /// <c>OTEL_EXPORTER_OTLP_PROTOCOL</c> and <c>OTEL_EXPORTER_OTLP_HEADERS</c> are read by the
    /// OpenTelemetry exporter out of the environment directly. They belong in the table anyway,
    /// because a deployment pointing this host at a vendor gateway has to set both and would
    /// otherwise send an <c>https://</c> base URL over gRPC - the transport the .NET exporter
    /// defaults to. Documenting a setting somebody else reads is the opposite of the defect this
    /// test exists for: the variable does something, and the row is the only place that says so.
    /// </para>
    /// </remarks>
    private static readonly HashSet<string> DocumentedButReadElsewhere = new(StringComparer.Ordinal)
    {
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_HEADERS",
    };

    [Theory]
    [MemberData(nameof(Hosts))]
    public void Every_setting_the_host_reads_has_a_row_in_its_readme(string host)
    {
        var directory = Path.Combine(RepositoryRoot(), "hosts", host);

        var read = SettingsRead(Path.Combine(directory, "Program.cs"));
        var documented = SettingsDocumented(Path.Combine(directory, "README.md"));

        // The controls, and they are not ceremony: both halves are absence assertions, so a scan
        // that found nothing - a moved file, a renamed heading, a table rewritten in another shape -
        // would report a clean pass over two files it never read. The numbers are floors well under
        // what is there rather than exact counts, because an exact count is the thing this test is
        // here to stop anybody maintaining by hand.
        Assert.True(read.Count >= 8, $"Only {read.Count} settings were found in {host}/Program.cs.");
        Assert.True(documented.Count >= 8, $"Only {documented.Count} rows were found in {host}/README.md's Configuration table.");

        var undocumented = read.Except(documented, StringComparer.Ordinal)
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            undocumented.Count == 0,
            $"{host}/Program.cs reads these and {host}/README.md has no row for them, so the "
            + "capability exists and nothing deploying this image can find it. Add a row to the "
            + "Configuration table — and say whether it is required, and what unset means:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, undocumented.Select(k => "  " + k)));
    }

    /// <summary>
    /// The other direction: a documented setting the code does not read is a promise with nothing
    /// behind it.
    /// </summary>
    /// <remarks>
    /// The control for the rule above, and the half that caught the live defect. <c>SMTP_STARTTLS</c>
    /// sat in the table with a warning that setting it <c>false</c> would put the SMTP password on
    /// the wire in the clear, long after <c>SMTP_SECURITY</c> replaced it - so an operator following
    /// the document configured nothing, was told nothing, and held a belief about their mail
    /// transport that no line of code supported. Renaming a setting without moving its row leaves
    /// exactly that, and there is no runtime signal for it: an unread environment variable is
    /// indistinguishable from one that agrees with the default.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Hosts))]
    public void Every_row_in_the_readme_names_a_setting_the_host_reads(string host)
    {
        var directory = Path.Combine(RepositoryRoot(), "hosts", host);

        var read = SettingsRead(Path.Combine(directory, "Program.cs"));
        var documented = SettingsDocumented(Path.Combine(directory, "README.md"));

        Assert.True(read.Count >= 8, $"Only {read.Count} settings were found in {host}/Program.cs.");
        Assert.True(documented.Count >= 8, $"Only {documented.Count} rows were found in {host}/README.md's Configuration table.");

        var unread = documented
            .Except(read, StringComparer.Ordinal)
            .Except(DocumentedButReadElsewhere, StringComparer.Ordinal)
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unread.Count == 0,
            $"{host}/README.md documents these and {host}/Program.cs reads none of them, so setting "
            + "one configures nothing and reports nothing. Remove the row, or — if something other "
            + $"than this host reads it — add it to {nameof(DocumentedButReadElsewhere)} with the "
            + "reason:" + Environment.NewLine
            + string.Join(Environment.NewLine, unread.Select(k => "  " + k)));
    }

    /// <summary>Every configuration key <c>Program.cs</c> reads.</summary>
    /// <remarks>
    /// Uppercase and underscores only, which is what an environment variable looks like and what
    /// keeps <c>config.GetConnectionString("Postgres")</c> - a different lookup shape, documented on
    /// the <c>DATABASE_URL</c> row it falls back from - out of the set.
    /// </remarks>
    private static HashSet<string> SettingsRead(string program)
    {
        var source = File.ReadAllText(program);

        return Indexer().Matches(source).Concat(Helper().Matches(source))
            .Select(m => m.Groups["key"].Value)
            .ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>Every key named in the first cell of the README's Configuration table.</summary>
    /// <remarks>
    /// The table under <c>## Configuration</c> and no further: the scan stops at the next heading of
    /// any depth, so the tables inside the subsections below it - the <c>/userinfo</c> claims, the
    /// <c>LOG_FORMAT</c> values - are not rows and cannot satisfy this. That is the strict reading
    /// on purpose. A setting explained in a paragraph is a setting an operator finds only by reading
    /// the whole document, and the table is what they scan.
    /// </remarks>
    private static HashSet<string> SettingsDocumented(string readme)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var inConfiguration = false;

        foreach (var line in File.ReadAllLines(readme))
        {
            if (line.StartsWith("## Configuration", StringComparison.Ordinal))
            {
                inConfiguration = true;
                continue;
            }

            if (!inConfiguration) continue;
            if (line.StartsWith('#')) break;
            if (!line.StartsWith('|')) continue;

            // The first cell only. The second is prose, and it cites other settings by name -
            // reading the whole row would let `ADMIN_ROLES` be "documented" by a sentence about it
            // on somebody else's row, which is how a row goes missing without this noticing.
            var cells = line.Split('|');
            if (cells.Length < 2) continue;

            foreach (Match named in Documented().Matches(cells[1]))
            {
                keys.Add(named.Groups["key"].Value);
            }
        }

        return keys;
    }

    /// <summary>Walk up from the test binary to the repository root.</summary>
    /// <remarks>
    /// By shape rather than by a fixed number of <c>..</c> segments, copied from
    /// <c>StructuralRuleTests.RepositoryRoot</c>, which carries the reason: the segment count
    /// changes with the target framework and the configuration in the output path, and a path that
    /// silently resolves to nothing turns every assertion above into a pass.
    /// </remarks>
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(
            Path.GetDirectoryName(typeof(HostConfigurationDocumentationTests).Assembly.Location)!);

        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "src"))
                && Directory.Exists(Path.Combine(directory.FullName, "hosts")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        Assert.Fail("Could not find the repository root above the test binary.");
        return null!;
    }

    [GeneratedRegex(@"config\[\s*""(?<key>[A-Z][A-Z0-9_]*)""\s*\]")]
    private static partial Regex Indexer();

    [GeneratedRegex(@"\b(?:Required|Flag|Duration)\(\s*(?:config\s*,\s*)?""(?<key>[A-Z][A-Z0-9_]*)""")]
    private static partial Regex Helper();

    [GeneratedRegex(@"`(?<key>[A-Z][A-Z0-9_]*)`")]
    private static partial Regex Documented();
}
