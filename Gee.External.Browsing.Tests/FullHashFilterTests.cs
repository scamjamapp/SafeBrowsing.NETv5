using System;
using System.Linq;
using System.Threading.Tasks;
using Flurl.Http.Testing;
using Gee.External.Browsing.Clients;
using Gee.External.Browsing.Clients.Http;
using Google.Protobuf;
using SafeBrowsing.V5;
using Xunit;
using ProtoThreatType = SafeBrowsing.V5.ThreatType;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     Full Hash Filter Tests.
    /// </summary>
    /// <remarks>
    ///     Covers V9 in the 2026-09-07 review. HttpBrowsingClient drops any full hash detail whose threat list is not
    ///     named in the request's queries. hashes:search is not told which lists to answer for - only the hash prefix
    ///     is sent - so the server answers for every list the full hash appears in, and this filter decides which of
    ///     those answers survive.
    /// </remarks>
    public sealed class FullHashFilterTests {
        /// <summary>
        ///     A SHA256 hash, hexadecimal encoded, and its four byte prefix.
        /// </summary>
        private const string Sha256Hash = "51864045AAB1B0F0AD1B7C5D5B5E5C5A5948474645444342414039383736353433";
        private const string Sha256HashPrefix = "51864045";

        /// <summary>
        ///     Build a hashes:search response naming a single threat type for a single full hash.
        /// </summary>
        private static byte[] BuildResponse(ProtoThreatType threatType) {
            var fullHash = new FullHash {
                FullHash_ = ByteString.CopyFrom(Convert.FromHexString(Sha256Hash))
            };

            fullHash.FullHashDetails.Add(new FullHash.Types.FullHashDetail {ThreatType = threatType});

            var response = new SearchHashesResponse {
                CacheDuration = new Duration {Seconds = 300}
            };

            response.FullHashes.Add(fullHash);
            return response.ToByteArray();
        }

        /// <summary>
        ///     Issue a request carrying exactly the queries the caller passes, against a canned response.
        /// </summary>
        private static async Task<FullHashResponse> FindAsync(ProtoThreatType serverAnswer, params ThreatListName[] queried) {
            using var client = new HttpBrowsingClient("test-api-key");
            using var httpTest = new HttpTest();

            httpTest.ResponseQueue.Enqueue(new System.Net.Http.HttpResponseMessage {
                Content = new System.Net.Http.ByteArrayContent(BuildResponse(serverAnswer))
            });

            var builder = FullHashRequest.Build();
            builder.AddSha256HashPrefix(Sha256HashPrefix);
            foreach (var threatListName in queried) {
                builder.AddQuery(new ThreatListDescriptor(threatListName), "AA00");
            }

            return await client.FindFullHashesAsync(builder.Build());
        }

        /// <summary>
        ///     The baseline: when the list the server answers for is the list that matched locally, the threat
        ///     survives the filter.
        /// </summary>
        [Fact]
        public async Task FindFullHashes_QueriedListMatchesServerAnswer_ReturnsThreat() {
            var response = await FindAsync(ProtoThreatType.Malware, ThreatListName.mw_4b);

            var threat = Assert.Single(response.UnsafeThreats);
            Assert.Equal(ThreatListName.mw_4b, threat.AssociatedThreatListDescriptor.ThreatListName);
        }

        /// <summary>
        ///     V9. The prefix matched se-4b locally, so se-4b is the only list in the request's queries. The API
        ///     answers that the full hash is MALWARE. The filter drops that answer because mw-4b was not queried,
        ///     and the caller is told the URL is safe.
        /// </summary>
        [Fact]
        public async Task FindFullHashes_ServerAnswersForAnUnqueriedList_DropsTheThreat() {
            var response = await FindAsync(ProtoThreatType.Malware, ThreatListName.se_4b);

            Assert.Empty(response.UnsafeThreats);
        }
    }
}
