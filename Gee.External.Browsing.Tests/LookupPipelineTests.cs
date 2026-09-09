using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Gee.External.Browsing.Cache;
using Gee.External.Browsing.Clients;
using Gee.External.Browsing.Databases;
using Gee.External.Browsing.Services;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     Lookup Pipeline Tests.
    /// </summary>
    /// <remarks>
    ///     Drives BaseBrowsingService.LookupAsync with in-memory doubles, so the v5 Local List Mode procedure
    ///     recorded as V12 can be checked without touching the network. Every assertion here corresponds to a
    ///     numbered step of that procedure.
    /// </remarks>
    public sealed class LookupPipelineTests {
        /// <summary>
        ///     A URL and the SHA256 hash prefix of its most specific expression.
        /// </summary>
        private const string TestUrl = "http://malware.example.com/bad/";

        /// <summary>
        ///     A service that exposes the protected lookup pipeline.
        /// </summary>
        private sealed class TestService : BaseBrowsingService {
            private readonly IBrowsingCache _cache;
            private readonly IBrowsingClient _client;
            private readonly IUnmanagedBrowsingDatabase _database;

            internal TestService(IBrowsingCache cache, IBrowsingClient client, IUnmanagedBrowsingDatabase database) {
                this._cache = cache;
                this._client = client;
                this._database = database;
            }

            public override void Dispose() { }

            public override Task<UrlLookupResult> LookupAsync(Url url, CancellationToken cancellationToken) =>
                this.LookupAsync(this._cache, this._client, this._database, url, cancellationToken);
        }

        /// <summary>
        ///     A database holding an explicit set of hash prefixes, and reporting an explicit health.
        /// </summary>
        private sealed class FakeDatabase : IUnmanagedBrowsingDatabase {
            private readonly HashSet<string> _prefixes;
            private readonly IReadOnlyCollection<ThreatList> _threatLists;

            internal FakeDatabase(IReadOnlyCollection<ThreatList> threatLists, params string[] prefixes) {
                this._threatLists = threatLists;
                this._prefixes = new HashSet<string>(prefixes);
            }

            /// <summary>
            ///     A database that has synchronized and is not due another update.
            /// </summary>
            internal static FakeDatabase Healthy(params string[] prefixes) =>
                new FakeDatabase(new[] {BuildThreatList(DateTime.UtcNow.AddMinutes(30))}, prefixes);

            /// <summary>
            ///     A database that has never synchronized.
            /// </summary>
            internal static FakeDatabase Empty() =>
                new FakeDatabase(Array.Empty<ThreatList>());

            /// <summary>
            ///     A database whose only list is overdue for an update.
            /// </summary>
            internal static FakeDatabase Stale(params string[] prefixes) =>
                new FakeDatabase(new[] {BuildThreatList(DateTime.UtcNow.AddMinutes(-30))}, prefixes);

            private static ThreatList BuildThreatList(DateTime waitToDate) =>
                ThreatList.Build()
                    .SetDescriptor(new ThreatListDescriptor(ThreatListName.mw_4b))
                    .SetState("AA00")
                    .SetRetrieveDate(DateTime.UtcNow)
                    .SetWaitToDate(waitToDate)
                    .Build();

            public Task<IReadOnlyCollection<ThreatList>> FindThreatListsAsync(string threatSha256HashPrefix, CancellationToken cancellationToken) {
                IReadOnlyCollection<ThreatList> result = this._prefixes.Contains(threatSha256HashPrefix)
                    ? this._threatLists
                    : Array.Empty<ThreatList>();

                return Task.FromResult(result);
            }

            public Task<ThreatList> GetThreatListAsync(ThreatListDescriptor threatListDescriptor, CancellationToken cancellationToken) =>
                Task.FromResult(this._threatLists.FirstOrDefault());

            public Task<IReadOnlyCollection<ThreatList>> GetThreatListsAsync(CancellationToken cancellationToken) =>
                Task.FromResult(this._threatLists);

            public Task<IReadOnlyCollection<string>> GetThreatsAsync(ThreatListDescriptor threatListDescriptor, CancellationToken cancellationToken) =>
                Task.FromResult<IReadOnlyCollection<string>>(this._prefixes.ToArray());

            public void Dispose() { }
        }

        /// <summary>
        ///     A client that records what it was asked and answers with a fixed threat set.
        /// </summary>
        private sealed class FakeClient : IBrowsingClient {
            private readonly IReadOnlyCollection<UnsafeThreat> _unsafeThreats;

            internal FullHashRequest LastRequest { get; private set; }
            internal int CallCount { get; private set; }

            internal FakeClient(params UnsafeThreat[] unsafeThreats) => this._unsafeThreats = unsafeThreats;

            public Task<FullHashResponse> FindFullHashesAsync(FullHashRequest request, CancellationToken cancellationToken) {
                this.CallCount += 1;
                this.LastRequest = request;

                var response = new FullHashResponse(request, DateTime.UtcNow.AddMinutes(5), this._unsafeThreats);
                return Task.FromResult(response);
            }

            public Task<IEnumerable<ThreatListDescriptor>> GetThreatListDescriptors(CancellationToken cancellationToken) =>
                Task.FromResult<IEnumerable<ThreatListDescriptor>>(Array.Empty<ThreatListDescriptor>());

            public Task<ThreatListUpdateResponse> GetThreatListUpdatesAsync(ThreatListUpdateRequest request, CancellationToken cancellationToken) =>
                throw new NotSupportedException();

            public void Dispose() { }
        }

        /// <summary>
        ///     The hash and prefix of the URL's most specific expression.
        /// </summary>
        private static (string Sha256Hash, string Sha256HashPrefix) MostSpecificExpression(string url) {
            var expression = new Url(url).Expressions.First();
            return (expression.Sha256Hash, expression.Sha256HashPrefixes.Single());
        }

        /// <summary>
        ///     Step 5. A URL in no local list leaves nothing to ask about, so the API is never called. The local
        ///     database is the whole point of Local List Mode.
        /// </summary>
        [Fact]
        public async Task Lookup_UrlAbsentFromDatabase_IsSafeWithoutCallingTheApi() {
            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Healthy());

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsSafe);
            Assert.Equal(0, client.CallCount);
        }

        /// <summary>
        ///     Step 6. Every surviving prefix goes to the API in a single request.
        /// </summary>
        [Fact]
        public async Task Lookup_PrefixInDatabase_SendsItInOneRequest() {
            var (_, sha256HashPrefix) = MostSpecificExpression(TestUrl);
            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Healthy(sha256HashPrefix));

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsSafe);
            Assert.Equal(1, client.CallCount);
            Assert.Equal(sha256HashPrefix, client.LastRequest.Sha256HashPrefixes.Single());
        }

        /// <summary>
        ///     Step 4. A cached unsafe full hash returns UNSAFE from the cache alone. Letting it fall through to the
        ///     database would lose the verdict entirely whenever the prefix has since left the local list.
        /// </summary>
        [Fact]
        public async Task Lookup_CachedUnsafe_ReturnsUnsafeWithoutCallingTheApi() {
            var (sha256Hash, _) = MostSpecificExpression(TestUrl);
            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();

            var unsafeThreat = new UnsafeThreat(
                sha256Hash,
                new ThreatListDescriptor(ThreatListName.mw_4b),
                DateTime.UtcNow.AddMinutes(5));

            await cache.PutUnsafeCacheEntryAsync(sha256Hash, new[] {unsafeThreat}, CancellationToken.None);

            // The database no longer holds the prefix - the verdict must survive that.
            using var service = new TestService(cache, client, FakeDatabase.Healthy());

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsUnsafe);
            Assert.Equal(0, client.CallCount);
        }

        /// <summary>
        ///     A URL the API confirms unsafe is reported unsafe, and cached for next time.
        /// </summary>
        [Fact]
        public async Task Lookup_ApiConfirmsThreat_ReturnsUnsafe() {
            var (sha256Hash, sha256HashPrefix) = MostSpecificExpression(TestUrl);

            var unsafeThreat = new UnsafeThreat(
                sha256Hash,
                new ThreatListDescriptor(ThreatListName.mw_4b),
                DateTime.UtcNow.AddMinutes(5));

            var client = new FakeClient(unsafeThreat);
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Healthy(sha256HashPrefix));

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsUnsafe);
            Assert.Equal(ThreatListName.mw_4b, result.UnsafeThreatListDescriptors.Single().ThreatListName);
        }

        /// <summary>
        ///     A database that has never synchronized prunes every prefix. Without a health check that path reports
        ///     every URL on the web safe, silently - the regression this guard exists to prevent.
        /// </summary>
        [Fact]
        public async Task Lookup_DatabaseNeverSynchronized_ReturnsDatabaseStale() {
            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Empty());

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsDatabaseStale);
            Assert.False(result.IsSafe);
            Assert.Equal(0, client.CallCount);
        }

        /// <summary>
        ///     A database whose lists are overdue for an update cannot answer either.
        /// </summary>
        [Fact]
        public async Task Lookup_DatabaseListExpired_ReturnsDatabaseStale() {
            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Stale());

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsDatabaseStale);
        }

        /// <summary>
        ///     A stale database must not mask a confirmed threat.
        /// </summary>
        [Fact]
        public async Task Lookup_StaleDatabaseButApiConfirmsThreat_ReturnsUnsafeNotStale() {
            var (sha256Hash, sha256HashPrefix) = MostSpecificExpression(TestUrl);

            var unsafeThreat = new UnsafeThreat(
                sha256Hash,
                new ThreatListDescriptor(ThreatListName.mw_4b),
                DateTime.UtcNow.AddMinutes(5));

            var client = new FakeClient(unsafeThreat);
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Stale(sha256HashPrefix));

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsUnsafe);
            Assert.False(result.IsDatabaseStale);
        }
        /// <summary>
        ///     v5: the cache duration "applies to every hash prefix queried by the client in the request, regardless
        ///     of how many full hashes are returned". A safe answer must be recorded, or the same question is asked
        ///     of the API on every lookup forever.
        /// </summary>
        [Fact]
        public async Task Lookup_ApiReturnsNothing_CachesTheNegativeAnswerAndDoesNotAskAgain() {
            var (_, sha256HashPrefix) = MostSpecificExpression(TestUrl);
            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();
            using var service = new TestService(cache, client, FakeDatabase.Healthy(sha256HashPrefix));

            var first = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);
            var second = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(first.IsSafe);
            Assert.True(second.IsSafe);
            Assert.Equal(1, client.CallCount);
        }

        /// <summary>
        ///     A safe cache entry settles the PREFIX it is keyed by, never the URL. A stale entry on a harmless
        ///     expression must not suppress a sibling expression that is genuinely listed.
        /// </summary>
        [Fact]
        public async Task Lookup_CachedSafePrefix_DoesNotSuppressAnotherExpression() {
            var url = new Url(TestUrl);
            var expressions = url.Expressions.ToArray();
            Assert.True(expressions.Length > 1);

            // Settle the LAST expression's prefix in the cache, and list the FIRST one as malware.
            var settled = expressions.Last();
            var listed = expressions.First();

            var client = new FakeClient(new UnsafeThreat(
                listed.Sha256Hash,
                new ThreatListDescriptor(ThreatListName.mw_4b),
                DateTime.UtcNow.AddMinutes(5)));

            using var cache = new MemoryBrowsingCache();
            await cache.PutSafeCacheEntryAsync(
                settled.Sha256HashPrefixes.Single(), DateTime.UtcNow.AddMinutes(5), CancellationToken.None);

            var database = FakeDatabase.Healthy(
                listed.Sha256HashPrefixes.Single(), settled.Sha256HashPrefixes.Single());

            using var service = new TestService(cache, client, database);

            var result = await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.True(result.IsUnsafe);
        }

        /// <summary>
        ///     The prefix the cache already answered for is not sent to the API again.
        /// </summary>
        [Fact]
        public async Task Lookup_CachedSafePrefix_IsPrunedFromTheRequest() {
            var url = new Url(TestUrl);
            var expressions = url.Expressions.ToArray();
            var settled = expressions.Last().Sha256HashPrefixes.Single();
            var other = expressions.First().Sha256HashPrefixes.Single();

            var client = new FakeClient();
            using var cache = new MemoryBrowsingCache();
            await cache.PutSafeCacheEntryAsync(settled, DateTime.UtcNow.AddMinutes(5), CancellationToken.None);

            using var service = new TestService(cache, client, FakeDatabase.Healthy(settled, other));

            await service.LookupAsync(new Url(TestUrl), CancellationToken.None);

            Assert.DoesNotContain(settled, client.LastRequest.Sha256HashPrefixes);
            Assert.Contains(other, client.LastRequest.Sha256HashPrefixes);
        }
    }
}
