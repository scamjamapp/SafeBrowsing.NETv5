using System.Text.RegularExpressions;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     URL Percent Escaping Tests.
    /// </summary>
    /// <remarks>
    ///     Covers V4 in the 2026-09-07 review. The specification asks that every character &lt;= ASCII 32, &gt;= 127,
    ///     "#", or "%" be percent-escaped with uppercase hexadecimal characters, and says nothing about how a
    ///     character above ASCII 127 becomes bytes. Escaping the UTF-8 bytes is the only reading under which the
    ///     "&gt;= 127" threshold is well defined, and it is the one a browser agrees with.
    ///
    ///     Escaping UTF-16 code units instead splits every character outside the Basic Multilingual Plane into its
    ///     two surrogate halves and substitutes the Unicode replacement character for each, canonicalizing an emoji
    ///     or a CJK Extension B ideograph to "%EF%BF%BD%EF%BF%BD". Nothing throws; the hash is simply wrong and
    ///     the URL is reported safe.
    /// </remarks>
    public sealed class UrlPercentEscapingTests {
        /// <summary>
        ///     Multi Byte Character Cases.
        /// </summary>
        public static TheoryData<string, string> MultiByteCases => new TheoryData<string, string> {
            // emoji, U+1F600, outside the BMP
            {"http://host.com/\U0001F600", "http://host.com/%F0%9F%98%80"},
            // non-BMP character between ASCII characters
            {"http://host.com/a\U0001F600b", "http://host.com/a%F0%9F%98%80b"},
            // CJK Extension B ideograph, U+20BB7, outside the BMP
            {"http://host.com/\U00020BB7", "http://host.com/%F0%A0%AE%B7"},
            // mathematical bold capital A, U+1D400, outside the BMP
            {"http://host.com/\U0001D400", "http://host.com/%F0%9D%90%80"},
            // e-acute, U+00E9, two UTF-8 bytes
            {"http://host.com/\u00E9", "http://host.com/%C3%A9"},
            // CJK, U+4E2D U+6587, three UTF-8 bytes each
            {"http://host.com/\u4E2D\u6587", "http://host.com/%E4%B8%AD%E6%96%87"},
            // black sun, U+2600, inside the BMP
            {"http://host.com/\u2600", "http://host.com/%E2%98%80"}
        };

        [Theory]
        [MemberData(nameof(MultiByteCases))]
        public void Encode_EscapesUtf8Bytes(string url, string expected) {
            Assert.Equal(expected, new Url(url).Value);
        }

        /// <summary>
        ///     A non-BMP character must never canonicalize to the Unicode replacement character.
        /// </summary>
        [Theory]
        [InlineData("http://host.com/\U0001F600")]
        [InlineData("http://host.com/\U00020BB7")]
        [InlineData("http://host.com/query?q=\U0001F600")]
        public void Encode_NeverEmitsTheReplacementCharacter(string url) {
            Assert.DoesNotContain("%EF%BF%BD", new Url(url).Value);
        }

        /// <summary>
        ///     The specification asks for uppercase hexadecimal characters.
        /// </summary>
        [Fact]
        public void Encode_UsesUppercaseHexadecimalCharacters() {
            var value = new Url("http://host.com/😀/é/☀").Value;
            var escapes = Regex.Matches(value, "%[0-9a-fA-F]{2}");

            Assert.NotEmpty(escapes);
            foreach (Match escape in escapes) {
                Assert.Equal(escape.Value.ToUpperInvariant(), escape.Value);
            }
        }

    }
}
