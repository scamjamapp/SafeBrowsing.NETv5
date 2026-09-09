using System.Linq;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     URL Expression Tests.
    /// </summary>
    /// <remarks>
    ///     The expected expression sets below are the worked examples published in Google's Safe Browsing "URLs and
    ///     Hashing" documentation. The client hashes exactly these strings, so an expression the client fails to emit
    ///     is a threat it can never match, and an expression it emits that Google never publishes is a wasted lookup.
    /// </remarks>
    public sealed class UrlExpressionTests {
        [Fact]
        public void Expressions_HostAndPathWithQuery_MatchSpecification() {
            var expected = new[] {
                "a.b.c/1/2.html?param=1",
                "a.b.c/1/2.html",
                "a.b.c/",
                "a.b.c/1/",
                "b.c/1/2.html?param=1",
                "b.c/1/2.html",
                "b.c/",
                "b.c/1/"
            };

            AssertExpressions("http://a.b.c/1/2.html?param=1", expected);
        }

        [Fact]
        public void Expressions_DeepHost_MatchSpecification() {
            var expected = new[] {
                "a.b.c.d.e.f.g/1.html",
                "a.b.c.d.e.f.g/",
                "c.d.e.f.g/1.html",
                "c.d.e.f.g/",
                "d.e.f.g/1.html",
                "d.e.f.g/",
                "e.f.g/1.html",
                "e.f.g/",
                "f.g/1.html",
                "f.g/"
            };

            AssertExpressions("http://a.b.c.d.e.f.g/1.html", expected);
        }

        [Fact]
        public void Expressions_IpAddressHost_MatchSpecification() {
            var expected = new[] {
                "1.2.3.4/1/",
                "1.2.3.4/"
            };

            AssertExpressions("http://1.2.3.4/1/", expected);
        }

        /// <summary>
        ///     Covers V2 in the 2026-09-07 review. The spec requires the four successively-appended path prefixes to
        ///     carry a trailing slash. Before the fix a path deeper than four segments emitted "/a/b/c" - a string
        ///     Google never hashes - in place of "/a/b/c/".
        /// </summary>
        [Fact]
        public void Expressions_PathDeeperThanFourSegments_KeepsTrailingSlashOnPrefixes() {
            var url = new Url("http://host.com/a/b/c/d/e");
            var pathExpressions = url.Expressions
                .Select(expression => expression.Value.Substring("host.com".Length))
                .ToArray();

            Assert.Equal(
                new[] {"/a/b/c/d/e", "/", "/a/", "/a/b/", "/a/b/c/"}.OrderBy(value => value),
                pathExpressions.OrderBy(value => value)
            );
        }

        private static void AssertExpressions(string url, string[] expected) {
            var actual = new Url(url).Expressions.Select(expression => expression.Value).ToArray();
            Assert.Equal(expected.OrderBy(value => value), actual.OrderBy(value => value));
        }
    }
}
