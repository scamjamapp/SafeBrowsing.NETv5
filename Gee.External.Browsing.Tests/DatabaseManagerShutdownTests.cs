using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Gee.External.Browsing.Clients;
using Gee.External.Browsing.Databases;
using Gee.External.Browsing.Services;
using Xunit;

namespace Gee.External.Browsing.Tests {
    /// <summary>
    ///     Database Manager Shutdown Tests.
    /// </summary>
    /// <remarks>
    ///     Dispose cancels the synchronization task and waits for it. The wait is only prompt if the cancellation
    ///     token actually reaches the client and database calls the task makes; without that, Dispose blocks for as
    ///     long as an in-flight HTTP request takes, multiplied by the resiliency policy's retries.
    /// </remarks>
    public sealed class DatabaseManagerShutdownTests {
        /// <summary>
        ///     A client whose update call blocks until its cancellation token fires.
        /// </summary>
        private sealed class BlockingClient : IBrowsingClient {
            internal readonly ManualResetEventSlim Entered = new ManualResetEventSlim(false);
            internal volatile bool ObservedCancellation;

            public Task<FullHashResponse> FindFullHashesAsync(FullHashRequest request, CancellationToken cancellationToken) =>
                throw new NotSupportedException();

            public Task<IEnumerable<ThreatListDescriptor>> GetThreatListDescriptors(CancellationToken cancellationToken) =>
                Task.FromResult<IEnumerable<ThreatListDescriptor>>(new[] {new ThreatListDescriptor(ThreatListName.mw_4b)});

            public async Task<ThreatListUpdateResponse> GetThreatListUpdatesAsync(ThreatListUpdateRequest request, CancellationToken cancellationToken) {
                this.Entered.Set();
                try {
                    // Stands in for an HTTP request that would otherwise run to its timeout.
                    await Task.Delay(TimeSpan.FromMinutes(5), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) {
                    this.ObservedCancellation = true;
                    throw;
                }

                return new ThreatListUpdateResponse(request, Array.Empty<ThreatListUpdateResult>());
            }

            public void Dispose() { }
        }

        [Fact]
        public void Dispose_SynchronizationInFlight_CancelsItAndReturnsPromptly() {
            var client = new BlockingClient();
            var manager = BrowsingDatabaseManager.Build()
                .SetClient(client, true)
                .SetDatabase(new MemoryBrowsingDatabase(), true)
                .Build();

            Assert.True(client.Entered.Wait(TimeSpan.FromSeconds(10)), "the synchronization task never issued its update call");

            var stopwatch = Stopwatch.StartNew();
            manager.Dispose();
            stopwatch.Stop();

            Assert.True(client.ObservedCancellation, "the cancellation token never reached the in-flight client call");
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
                $"Dispose took {stopwatch.Elapsed}, which means it waited on the call rather than cancelling it");
        }
    }
}
