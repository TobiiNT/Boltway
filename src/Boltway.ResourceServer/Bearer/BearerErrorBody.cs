using System.Text.Json.Serialization;

namespace Boltway.ResourceServer.Bearer;

/// <summary>The advisory JSON body that accompanies a challenge.</summary>
/// <remarks>
/// Two fields, both copies of what the <c>WWW-Authenticate</c> header already carries. RFC 6750 §3
/// puts the machine-readable signal in the header, so this body exists for the person reading a
/// terminal — and keeping it to an exact copy is what stops it becoming a second, divergent source
/// of truth about why a request was refused.
/// </remarks>
internal sealed record BearerErrorBody
{
    /// <summary>The RFC 6750 §3.1 error code.</summary>
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    /// <summary>Human-readable detail. Always a constant; never derived from the request.</summary>
    [JsonPropertyName("error_description")]
    public required string ErrorDescription { get; init; }
}

/// <summary>Source-generated serializer, so the body survives trimming.</summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Serialization)]
[JsonSerializable(typeof(BearerErrorBody))]
internal sealed partial class BearerErrorJsonContext : JsonSerializerContext;
