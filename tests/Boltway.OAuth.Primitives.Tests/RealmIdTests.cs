using Boltway.OAuth.Primitives.Ids;

namespace Boltway.OAuth.Primitives.Tests;

/// <summary>
/// <see cref="RealmId"/> - constrained where it is created, wrapped where it is read back.
/// </summary>
/// <remarks>
/// The same split <see cref="SubjectId"/> records: a shape is a promise about what gets created, so
/// the creation site is the only place it can be kept. Refusing at the rehydration path would make a
/// row written by an older version unreadable rather than merely unusual.
/// </remarks>
public sealed class RealmIdTests
{
    [Theory]
    [InlineData("default")]
    [InlineData("acme")]
    [InlineData("acme-corp")]
    [InlineData("a")]
    [InlineData("tenant-2026")]
    public void A_name_of_lowercase_letters_digits_and_dashes_is_a_realm(string value)
    {
        Assert.True(RealmId.TryParse(value, out var realm, out var error), error);
        Assert.Equal(value, realm.Value);
    }

    /// <summary>
    /// Everything that would make the value need sanitising somewhere else is refused here.
    /// </summary>
    /// <remarks>
    /// It lands in a composite unique index and is a candidate for a cache key and a URL segment.
    /// Uppercase is refused for a second reason: two realms whose names differ only by case are two
    /// directories that look like one, and which one a lookup reaches would depend on a collation.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Acme")]
    [InlineData("acme corp")]
    [InlineData("acme/corp")]
    [InlineData("acme.corp")]
    [InlineData("acme_corp")]
    [InlineData("acme:corp")]
    [InlineData("-acme")]
    [InlineData("acme-")]
    public void Anything_needing_a_sanitiser_downstream_is_refused(string? value)
    {
        Assert.False(RealmId.TryParse(value, out _, out var error));
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void A_name_longer_than_the_column_is_refused()
    {
        Assert.False(RealmId.TryParse(new string('a', RealmId.MaxLength + 1), out _, out var error));
        Assert.Contains("at most", error, StringComparison.Ordinal);

        Assert.True(RealmId.TryParse(new string('a', RealmId.MaxLength), out _, out _));
    }

    /// <summary>
    /// <c>default(RealmId)</c> reports itself rather than pretending to be a realm.
    /// </summary>
    /// <remarks>
    /// A struct cannot stop a caller getting the uninitialised value, and it is written into a NOT
    /// NULL column - so the type says which one it is and offers the substitution, rather than every
    /// store rediscovering the problem at the database.
    /// </remarks>
    [Fact]
    public void The_uninitialised_value_says_so_and_substitutes_the_default()
    {
        RealmId unset = default;

        Assert.True(unset.IsUnset);
        Assert.Equal(RealmId.Default, unset.OrDefault);
        Assert.Equal("<unset>", unset.ToString());

        Assert.False(RealmId.Default.IsUnset);
        Assert.Equal(RealmId.Default, RealmId.Default.OrDefault);
    }

    [Fact]
    public void Storage_rehydration_wraps_without_judging()
    {
        // A row written before the rules, or by a version that had different ones. Reading it has to
        // work; creating one like it does not.
        Assert.Equal("Legacy_Realm", RealmId.FromStorage("Legacy_Realm").Value);
        Assert.False(RealmId.TryParse("Legacy_Realm", out _, out _));
    }

    [Fact]
    public void Equality_is_ordinal()
    {
        Assert.Equal(RealmId.FromStorage("acme"), RealmId.FromStorage("acme"));
        Assert.NotEqual(RealmId.FromStorage("acme"), RealmId.FromStorage("ACME"));
        Assert.True(RealmId.FromStorage("acme") == RealmId.FromStorage("acme"));
        Assert.True(RealmId.FromStorage("acme") != RealmId.Default);
    }
}
