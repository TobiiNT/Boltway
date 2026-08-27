using Boltway.OAuth.Primitives.Http;

namespace Boltway.OAuth.Primitives.Tests.Http;

/// <summary>
/// The §10 correction: tolerating a charset parameter is mandatory, not optional.
/// </summary>
public sealed class MediaTypeTests
{
    [Theory]
    // Measured live 2026-08-03. claude.ai serves the bare type; chatgpt.com adds a charset. A
    // fetcher comparing the header to "application/json" by equality accepts every Claude document
    // and rejects every ChatGPT one, and the failure surfaces as invalid_client - which reads as
    // the client's fault.
    [InlineData("application/json")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("application/json;charset=UTF-8")]
    [InlineData("application/json ; charset=utf-8 ; profile=x")]
    [InlineData("APPLICATION/JSON")]
    [InlineData("  application/json  ")]
    public void Json_is_recognized_regardless_of_parameters_or_case(string header)
    {
        Assert.True(MediaType.TryParse(header, out var mediaType));
        Assert.True(mediaType.IsJson);
    }

    [Theory]
    // RFC 6839 structured suffix. An authorization server metadata document served as
    // application/jwk-set+json is still JSON.
    [InlineData("application/jwk-set+json")]
    [InlineData("application/at+jwt+json")]
    public void Structured_json_suffixes_count_as_json(string header)
    {
        Assert.True(MediaType.TryParse(header, out var mediaType));
        Assert.True(mediaType.IsJson);
    }

    [Theory]
    [InlineData("text/html")]
    [InlineData("application/xml")]
    [InlineData("text/json")]                 // wrong type, and not what any spec asks for
    [InlineData("application/jsonify")]       // prefix match must not be enough
    public void Non_json_is_not_json(string header)
    {
        Assert.True(MediaType.TryParse(header, out var mediaType));
        Assert.False(mediaType.IsJson);
    }

    [Fact]
    public void Form_encoding_is_recognized()
    {
        // The /token content type. Getting this wrong returns 415 and kills the flow at exchange.
        Assert.True(MediaType.TryParse("application/x-www-form-urlencoded; charset=utf-8", out var mediaType));
        Assert.True(mediaType.IsFormUrlEncoded);
        Assert.False(mediaType.IsJson);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("application")]     // no slash
    [InlineData("/json")]           // no type
    [InlineData("application/")]    // no subtype
    [InlineData(";charset=utf-8")]
    public void Malformed_headers_do_not_parse(string? header)
    {
        Assert.False(MediaType.TryParse(header, out _));
    }

    [Theory]
    // Content-Type is attacker-controlled on every /token and /register request. Without tchar
    // validation these all parsed, and the parsed value flowing into a 415 body, a log line or a
    // diagnostic header is log injection or response splitting - out of the very type whose job is
    // to be the trusted parse of that header.
    [InlineData("application/json\r\nX-Injected: yes")]
    [InlineData("application/json\0; charset=x")]
    [InlineData("application/json/evil")]
    [InlineData("application / json")]
    [InlineData("application/js on")]
    [InlineData("text/html, application/json")]
    public void Control_characters_and_non_token_bytes_do_not_parse(string header)
    {
        Assert.False(MediaType.TryParse(header, out _));
    }

    [Theory]
    // RFC 6839 requires a non-empty base before a +json suffix.
    [InlineData("application/+json")]
    [InlineData("application/++json")]
    public void A_bare_json_suffix_is_not_json(string header)
    {
        Assert.True(MediaType.TryParse(header, out var mediaType));
        Assert.False(mediaType.IsJson);
    }

    [Fact]
    public void Equality_ignores_parameters()
    {
        Assert.True(MediaType.TryParse("application/json; charset=utf-8", out var withCharset));
        Assert.True(MediaType.TryParse("application/json", out var without));

        Assert.Equal(without, withCharset);
    }
}
