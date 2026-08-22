using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Boltway.AuthorizationServer.Configuration;

namespace Boltway.AuthorizationServer.Metadata;

/// <summary>
/// The discovery document as bytes, serialized once at startup.
/// </summary>
/// <remarks>
/// <para>
/// Bytes rather than an object, because the requirement is that E-01 through E-06 serve
/// <b>byte-identical</b> bodies. Serializing per request would satisfy that only as long as nothing
/// about the serializer's behaviour varied — dictionary ordering, a culture-sensitive formatter, a
/// future property whose value is computed — and each of those is a bug that would show up as one
/// endpoint disagreeing with another under load rather than in a test.
/// </para>
/// <para>
/// It also makes the ETag honest: the tag is the hash of exactly what is sent, so a conditional
/// request cannot be answered <c>304</c> against a body that has since changed.
/// </para>
/// </remarks>
public sealed class MetadataDocument
{
    private MetadataDocument(ImmutableArray<byte> json, string etag, AuthorizationServerMetadata metadata)
    {
        _json = json;
        ETag = etag;
        Metadata = metadata;
    }

    private readonly ImmutableArray<byte> _json;

    /// <summary>
    /// The serialized document.
    /// </summary>
    /// <remarks>
    /// An <see cref="ImmutableArray{T}"/> rather than a <see cref="ReadOnlyMemory{T}"/>, because
    /// the latter is not read-only in the sense the ETag needs. Measured:
    /// <c>MemoryMarshal.TryGetArray</c> handed back the live array and writing through it changed
    /// the body every subsequent request received, while <see cref="ETag"/> — computed once here —
    /// went on advertising the old bytes. This object is a singleton, so that is a cache-poisoning
    /// primitive, not a theoretical aliasing note. Reaching the array now requires
    /// <c>ImmutableCollectionsMarshal</c>, which is an explicit opt-out of the guarantee rather
    /// than an ordinary call.
    /// </remarks>
    public ImmutableArray<byte> Json => _json;

    /// <summary>A strong ETag over <see cref="Json"/>, quoted and ready for the header.</summary>
    /// <remarks>
    /// Strong, not weak: the bytes are the resource, so two responses with this tag are byte-equal.
    /// A weak tag would be a smaller promise than the one this can keep.
    /// </remarks>
    public string ETag { get; }

    /// <summary>The document before serialization, for the doctor and for tests.</summary>
    public AuthorizationServerMetadata Metadata { get; }

    /// <summary>Build and serialize from validated configuration.</summary>
    public static MetadataDocument Create(AuthorizationServerOptions options)
    {
        var metadata = MetadataBuilder.Build(options);
        return Create(metadata);
    }

    /// <summary>Serialize an already-built document.</summary>
    public static MetadataDocument Create(AuthorizationServerMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var json = JsonSerializer.SerializeToUtf8Bytes(metadata, MetadataJsonContext.Default.AuthorizationServerMetadata);
        var etag = '"' + Convert.ToHexStringLower(SHA256.HashData(json)) + '"';

        return new MetadataDocument([.. json], etag, metadata);
    }
}

/// <summary>
/// The serializer for the discovery document.
/// </summary>
/// <remarks>
/// Source-generated, so the shape of the JSON is decided at compile time. Reflection-based
/// serialization would work today and break silently under trimming, and this assembly is meant to
/// be publishable into a customer's trimmed or AOT-compiled host.
/// </remarks>
[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    GenerationMode = JsonSourceGenerationMode.Serialization)]
[JsonSerializable(typeof(AuthorizationServerMetadata))]
internal sealed partial class MetadataJsonContext : JsonSerializerContext;
