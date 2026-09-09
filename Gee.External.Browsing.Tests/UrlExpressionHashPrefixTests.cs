using System.Linq;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     URL Expression Hash Prefix Tests.
    /// </summary>
    /// <remarks>
    ///     Covers V3 in the 2026-09-07 review. Every threat list the Safe Browsing v5 API supports is a four byte
    ///     list, so an expression computes to exactly one hash prefix. Emitting none is a total fail-open - the
    ///     database lookup loop never runs a single query and reports every URL safe - and emitting the 61 prefixes
    ///     v4 allowed costs 60 guaranteed-miss database round trips per expression.
    /// </remarks>
    public sealed class UrlExpressionHashPrefixTests {
        /// <summary>
        ///     Hash Prefix Length, In Hexadecimal Characters.
        /// </summary>
        private const int Sha256HashPrefixLength = 8;

        [Theory]
        [InlineData("http://malware.testing.google.test/testing/malware/")]
        [InlineData("http://a.b.c/1/2.html?param=1")]
        [InlineData("http://1.2.3.4/1/")]
        [InlineData("http://notrailingslash.com")]
        public void Sha256HashPrefixes_AreExactlyTheFourBytePrefix(string url) {
            var expressions = new Url(url).Expressions.ToArray();
            Assert.NotEmpty(expressions);

            foreach (var expression in expressions) {
                var prefixes = expression.Sha256HashPrefixes.ToArray();
                var prefix = Assert.Single(prefixes);

                Assert.Equal(Sha256HashPrefixLength, prefix.Length);
                Assert.Equal(expression.Sha256Hash.Substring(0, Sha256HashPrefixLength), prefix);
            }
        }

        [Fact]
        public void Sha256Hash_IsAFullSha256Hash() {
            var expression = new Url("http://a.b.c/1/2.html?param=1").Expressions.First();
            Assert.Equal(64, expression.Sha256Hash.Length);
        }
    }
}
