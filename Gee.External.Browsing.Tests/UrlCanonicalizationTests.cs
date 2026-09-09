using System;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     URL Canonicalization Tests.
    /// </summary>
    /// <remarks>
    ///     Every case below is taken verbatim from the canonicalization examples published in Google's Safe Browsing
    ///     "URLs and Hashing" documentation. The algorithm is unchanged from v4 to v5, so these remain the normative
    ///     examples. A regression here means the client hashes a different string than Google does, no prefix
    ///     matches, and an unsafe URL is silently reported safe.
    /// </remarks>
    public sealed class UrlCanonicalizationTests {
        /// <summary>
        ///     Repeated Percent Decoding Cases.
        /// </summary>
        public static TheoryData<string, string> RepeatedPercentDecodingCases => new TheoryData<string, string> {
            {"http://host/%25%32%35", "http://host/%25"},
            {"http://host/%25%32%35%25%32%35", "http://host/%25%25"},
            {"http://host/%2525252525252525", "http://host/%25"},
            {"http://host/asdf%25%32%35asd", "http://host/asdf%25asd"},
            {"http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25"}
        };

        /// <summary>
        ///     Host Canonicalization Cases.
        /// </summary>
        public static TheoryData<string, string> HostCases => new TheoryData<string, string> {
            {"http://www.google.com/", "http://www.google.com/"},
            {"http://www.GOOgle.com/", "http://www.google.com/"},
            {"http://www.google.com.../", "http://www.google.com/"},
            {"http://www.gotaport.com:1234/", "http://www.gotaport.com/"},
            {"https://www.securesite.com/", "https://www.securesite.com/"},
            {"http://notrailingslash.com", "http://notrailingslash.com/"},
            {"www.google.com/", "http://www.google.com/"},
            {"www.google.com", "http://www.google.com/"}
        };

        /// <summary>
        ///     IP Address Host Cases.
        /// </summary>
        public static TheoryData<string, string> IpAddressCases => new TheoryData<string, string> {
            {"http://3279880203/blah", "http://195.127.0.11/blah"},
            {
                "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
                "http://168.188.99.26/.secure/www.ebay.com/"
            }
        };

        /// <summary>
        ///     Path Canonicalization Cases.
        /// </summary>
        public static TheoryData<string, string> PathCases => new TheoryData<string, string> {
            {"http://www.google.com/blah/..", "http://www.google.com/"},
            {"http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes"},
            {"http://host.com/ab%23cd", "http://host.com/ab%23cd"},
            {
                "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
                "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"
            }
        };

        /// <summary>
        ///     Fragment, Query, Whitespace and Control Character Cases.
        /// </summary>
        public static TheoryData<string, string> FragmentAndQueryCases => new TheoryData<string, string> {
            {"http://www.evil.com/blah#frag", "http://www.evil.com/blah"},
            {"http://evil.com/foo#bar#baz", "http://evil.com/foo"},
            {"http://evil.com/foo;", "http://evil.com/foo;"},
            {"http://evil.com/foo?bar;", "http://evil.com/foo?bar;"},
            {"http://www.google.com/q?", "http://www.google.com/q?"},
            {"http://www.google.com/q?r?", "http://www.google.com/q?r?"},
            {"http://www.google.com/q?r?s", "http://www.google.com/q?r?s"},
            {"http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2"},
            {"  http://www.google.com/  ", "http://www.google.com/"},
            {"http:// leadingspace.com/", "http://%20leadingspace.com/"},
            {"http://%20leadingspace.com/", "http://%20leadingspace.com/"},
            {"%20leadingspace.com/", "http://%20leadingspace.com/"},
            {"http://\u0001x.com/", "http://%01x.com/"}
        };

        /// <summary>
        ///     Dot Segment Resolution Cases.
        /// </summary>
        /// <remarks>
        ///     These are not published examples but they cover the bypass vector recorded as V1 in the 2026-09-07
        ///     review: nested "/./" and "/../" sequences, and parent segments containing characters outside \w.
        /// </remarks>
        public static TheoryData<string, string> DotSegmentCases => new TheoryData<string, string> {
            {"http://host.com/a/b/../../c", "http://host.com/c"},
            {"http://host.com/./././x", "http://host.com/x"},
            {"http://host.com/1/2/3/../../../x", "http://host.com/x"},
            {"http://host.com/a-b/../c", "http://host.com/c"},
            {"http://host.com/a.b/../c", "http://host.com/c"},
            {"http://host.com/a~b/../c", "http://host.com/c"},
            {"http://host.com/../../../etc/passwd", "http://host.com/etc/passwd"},
            {"http://host.com/a/./b/../c/", "http://host.com/a/c/"}
        };

        /// <summary>
        ///     Documented Divergences From Google's Published Examples.
        /// </summary>
        /// <remarks>
        ///     Two of Google's published examples do not agree with what this implementation produces. Neither is a
        ///     defect in the canonicalization itself, but both change the hash, so they are asserted here to make the
        ///     divergence explicit and to fail loudly if the behaviour ever moves.
        /// </remarks>
        public static TheoryData<string, string, string> DivergenceCases => new TheoryData<string, string, string> {
            {
                // Google documents this as ending "(44)55", which requires dropping the orphaned "%2" left behind
                // after "%25" decodes to "%". The same example ends "%25f" earlier in the very same string, where an
                // equally orphaned "%f" is kept and re-escaped. The two halves cannot both be right; we keep the
                // orphan in both places, which is the self-consistent reading.
                "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252C33%252844%252)55",
                "http://host%23.com/~a!b@c%23d$e%25f^00&11*22,33(44%252)55",
                "http://host%23.com/~a!b@c%23d$e%25f^00&11*22,33(44)55"
            },
            {
                // Google's example is byte-oriented: the raw byte 0x80 escapes to "%80". This implementation takes a
                // string, so U+0080 is UTF-8 encoded to two bytes and escapes to "%C2%80". Tracked as V4 in the
                // 2026-09-07 review, which also covers the non-BMP characters that break the same encoder.
                "http://.com/",
                "http://%01%C2%80.com/",
                "http://%01%80.com/"
            }
        };

        [Theory]
        [MemberData(nameof(DivergenceCases))]
        public void Canonicalize_DivergesFromSpecification(string url, string actual, string documented) {
            Assert.NotEqual(documented, actual);
            Assert.Equal(actual, new Url(url).Value);
        }

        [Theory]
        [MemberData(nameof(RepeatedPercentDecodingCases))]
        [MemberData(nameof(HostCases))]
        [MemberData(nameof(IpAddressCases))]
        [MemberData(nameof(PathCases))]
        [MemberData(nameof(FragmentAndQueryCases))]
        [MemberData(nameof(DotSegmentCases))]
        public void Canonicalize_MatchesSpecification(string url, string expected) {
            var canonicalizedUrl = new Url(url);
            Assert.Equal(expected, canonicalizedUrl.Value);
        }
    }
}
