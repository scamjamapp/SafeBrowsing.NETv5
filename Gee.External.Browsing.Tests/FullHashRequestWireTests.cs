using System;
using System.Linq;
using System.Threading.Tasks;
using Flurl.Http.Testing;
using Gee.External.Browsing.Clients;
using Gee.External.Browsing.Clients.Http;
using Google.Protobuf;
using SafeBrowsing.V5;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     Full Hash Request Wire Format Tests.
    /// </summary>
    /// <remarks>
    ///     hashes.search takes a repeated hashPrefixes field, each prefix base64 encoded, up to 1000 per request.
    ///     These tests pin what actually reaches the wire, since V12 turns on whether the client can carry a batch
    ///     once the service layer stops handing it a single prefix.
    /// </remarks>
    public sealed class FullHashRequestWireTests {
        private static byte[] EmptyResponse() {
            var response = new SearchHashesResponse {
                CacheDuration = new Duration {Seconds = 300}
            };

            return response.ToByteArray();
        }

        private static async Task<string> CapturedUrlAsync(params string[] sha256HashPrefixes) {
            using var client = new HttpBrowsingClient("test-api-key");
            using var httpTest = new HttpTest();

            httpTest.ResponseQueue.Enqueue(new System.Net.Http.HttpResponseMessage {
                Content = new System.Net.Http.ByteArrayContent(EmptyResponse())
            });

            var builder = FullHashRequest.Build();
            foreach (var sha256HashPrefix in sha256HashPrefixes) {
                builder.AddSha256HashPrefix(sha256HashPrefix);
            }

            await client.FindFullHashesAsync(builder.Build());
            return httpTest.CallLog.Single().Request.RequestUri.ToString();
        }

        [Fact]
        public async Task FindFullHashes_ManyPrefixes_SendsEveryPrefixAsARepeatedQueryParameter() {
            var url = await CapturedUrlAsync("51864045", "8D0E7169", "DFBADAD1");

            // Base64 of each four byte prefix, url-escaped.
            Assert.Equal(3, url.Split("hashPrefixes=").Length - 1);
            Assert.Contains(Uri.EscapeDataString(Convert.ToBase64String(Convert.FromHexString("51864045"))), url);
            Assert.Contains(Uri.EscapeDataString(Convert.ToBase64String(Convert.FromHexString("8D0E7169"))), url);
            Assert.Contains(Uri.EscapeDataString(Convert.ToBase64String(Convert.FromHexString("DFBADAD1"))), url);
        }

        [Fact]
        public async Task FindFullHashes_SinglePrefix_SendsOneQueryParameter() {
            var url = await CapturedUrlAsync("51864045");

            Assert.Equal(1, url.Split("hashPrefixes=").Length - 1);
        }
    }
}
