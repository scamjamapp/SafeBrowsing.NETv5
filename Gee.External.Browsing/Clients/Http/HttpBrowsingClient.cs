using Flurl;
using Flurl.Http;
using Flurl.Http.Configuration;
using Gee.Common.Guards;
using SafeBrowsing.V5;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;


namespace Gee.External.Browsing.Clients.Http {
    /// <summary>
    ///     HTTP Client.
    /// </summary>
    public sealed class HttpBrowsingClient : IBrowsingClient {
        /// <summary>
        ///     API Key Query Parameter Name.
        /// </summary>
        private const string ApiKeyQueryParameterName = "key";

        /// <summary>
        ///     Base URI.
        /// </summary>
        private const string BaseUri = "https://safebrowsing.googleapis.com/v5";

        /// <summary>
        ///     Find Full Hashes URI.
        /// </summary>
        private static readonly string FindFullHashesUri = $"{HttpBrowsingClient.BaseUri}/hashes:search";

        /// <summary>
        ///     Get Threat List Updates URI.
        /// </summary>
        private static readonly string GetThreatListUpdatesUri = $"{HttpBrowsingClient.BaseUri}/hashLists:batchGet";

        /// <summary>
        ///     API Key.
        /// </summary>
        [SuppressMessage("ReSharper", "PrivateFieldCanBeConvertedToLocalVariable")]
        private readonly string _apiKey;

        /// <summary>
        ///     Valid Threat List Names.
        /// </summary>
        /// <remarks>
        ///     The names of the threat lists that are available from the Google Safe Browsing API. The Google Safe
        ///     Browsing API guarantees a hash list it has ever made available is never removed, so the names are
        ///     hardcoded instead of being retrieved from the API. The API's global cache, "gc-32b", is deliberately
        ///     omitted since it identifies hashes that are likely safe, not hashes that pose a threat.
        /// </remarks>
        static readonly string[] ValidThreatListNames = {"se-4b", "mw-4b", "uws-4b", "pha-4b"};

        /// <summary>
        ///     Disposed Flag.
        /// </summary>
        private bool _disposed;

        /// <summary>
        ///     Create a Browsing Client.
        /// </summary>
        /// <param name="apiKey">
        ///     A Google Safe Browsing API key to authenticate to the Google Safe Browsing API with.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="apiKey" /> is a null reference.
        /// </exception>
        public HttpBrowsingClient(string apiKey) {
            Guard.ThrowIf(nameof(apiKey), apiKey).Null();

            this._apiKey = apiKey;
            this._disposed = false;
            // ...
            //
            // ...
            FlurlHttp.Configure(s => {
                s.CookiesEnabled = false;
                s.BeforeCall = OnFlurlClientBeforeCall;
                s.HttpClientFactory = new HttpClientFactory();
                s.Timeout = TimeSpan.FromMinutes(1);
            });

            // <summary>
            //      On Flurl Client Before Call.
            // </summary>
            void OnFlurlClientBeforeCall(HttpCall httpCall) {
                // ...
                //
                // Add the Google Safe Browsing API Key to every HTTP request so that we don't have explicitly add it
                // when creating every HTTP request.
                var requestQueryParameters = httpCall.FlurlRequest.Url.QueryParams;
                requestQueryParameters.Add(HttpBrowsingClient.ApiKeyQueryParameterName, this._apiKey, true);
            }
        }

        /// <summary>
        ///     Dispose Object.
        /// </summary>
        public void Dispose() {
            if (!this._disposed) {
                this._disposed = true;
            }
        }

        /// <summary>
        ///     Find Full Hashes Asynchronously.
        /// </summary>
        /// <param name="request">
        ///     A <see cref="FullHashRequest" />.
        /// </param>
        /// <param name="cancellationToken">
        ///     A cancellation token to cancel the asynchronous operation with.
        /// </param>
        /// <returns>
        ///     A <see cref="FullHashResponse" />.
        /// </returns>
        /// <exception cref="Gee.External.Browsing.Clients.BrowsingClientException">
        ///     Thrown if an error communicating with the Google Safe Browsing API occurs.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="request" /> is a null reference.
        /// </exception>
        /// <exception cref="System.ObjectDisposedException">
        ///     Thrown if the object is disposed.
        /// </exception>
        /// <exception cref="System.OperationCanceledException">
        ///     Thrown if the asynchronous operation is cancelled.
        /// </exception>
        /// <exception cref="System.TimeoutException">
        ///     Thrown if communication with the Google Safe Browsing API times out.
        /// </exception>
        public Task<FullHashResponse> FindFullHashesAsync(FullHashRequest request, CancellationToken cancellationToken) {
            this.ThrowIfDisposed();
            Guard.ThrowIf(nameof(request), request).Null();

            var findFullHashesTask = FindFullHashesAsync(request, cancellationToken);
            return findFullHashesTask;

            // <summary>
            //      Find Full Hashes Asynchronously.
            // </summary>
            async Task<FullHashResponse> FindFullHashesAsync(FullHashRequest cRequest, CancellationToken cCancellationToken) {
                try {
                    // ...
                    //
                    // Throws an exception if the operation fails.

                    List<string> prefixes = new List<string>();
                    foreach (var prefix in cRequest.Sha256HashPrefixes)
                    {
                        var prefixBytes = Convert.FromHexString(prefix);
                        if (prefixBytes.Length != 4)
                        {
                            throw new ArgumentOutOfRangeException(nameof(cRequest), "a hash prefix in the request is longer than four bytes!");
                        }                 
                        prefixes.Add(Convert.ToBase64String(Convert.FromHexString(prefix)));
                    }

                    if (prefixes.Count() > 1000)
                    {
                        throw new ArgumentOutOfRangeException(nameof(cRequest), "request contains more than 1000 hash prefixes!");
                    }

                    var cResponseBytes = await HttpBrowsingClient.FindFullHashesUri
                                                .SetQueryParam("hashPrefixes", prefixes)
                                                .GetBytesAsync(cCancellationToken)
                                                .ConfigureAwait(false);

                    var cResponseMessage = SearchHashesResponse.Parser.ParseFrom(cResponseBytes);
                    
                    var convertedDateTime = DateTime.UtcNow + DurationConverter.SafeBrowsingDurationToTimespan(cResponseMessage.CacheDuration);
                    var hashes = cResponseMessage.FullHashes;

                    var threatsToReturn = new List<UnsafeThreat>();
                    foreach (var fullHash in hashes)
                    {
                        var details = fullHash.FullHashDetails;

                        foreach (var detail in details)
                        {
                            var threatListName = ThreatConverter.ThreatTypeToThreatListName(detail.ThreatType);
                            if (threatListName == ThreatListName.unsupported) 
                            {
                                continue; 
                            }
                            if (detail.Attributes.Count > 0) 
                            {
                                continue; 
                            }
                            if (cRequest.Queries.Any() && !cRequest.Queries.Any(q => q.ThreatListDescriptor.ThreatListName == threatListName))
                            {
                                continue;
                            }


                            var descriptor = new ThreatListDescriptor(threatListName);


                            var sha256Hash = fullHash.FullHash_.ToByteArray();

                            UnsafeThreat unsafeThreat = new UnsafeThreat(Convert.ToHexString(sha256Hash), descriptor, convertedDateTime);
                            threatsToReturn.Add(unsafeThreat); 

                        }

                    }

                    FullHashResponse cResponse = new FullHashResponse(cRequest, convertedDateTime, threatsToReturn);
                    return cResponse;
                }
                catch (FlurlHttpTimeoutException cEx) {
                    // ...
                    //
                    // An HTTP 504 is not the most appropriate HTTP response code to use if there is a client timeout
                    // but its the closest one that makes sense, so we will go ahead and use it.
                    const string cDetailMessage = "An HTTP request to the Google Safe Browsing API timed out.";
                    throw new TimeoutException(cDetailMessage, cEx);
                }
                catch (FlurlHttpException cEx) {
                    var httpStatusCode = cEx.Call.HttpStatus ?? HttpStatusCode.BadRequest;
                    const string cDetailMessage = "An HTTP request to the Google Safe Browsing API failed.";
                    throw new BrowsingClientException(cDetailMessage, httpStatusCode, cEx);
                }
            }
        }

        /// <summary>
        ///     Get Threat List Descriptors Asynchronously.
        /// </summary>
        /// <remarks>
        ///     No HTTP request to the Google Safe Browsing API is made. The API guarantees a hash list it has ever
        ///     made available is never removed, and explicitly allows a client to hardcode the hash lists it needs, so
        ///     the threat list descriptors are created from <see cref="ValidThreatListNames" /> instead. The operation
        ///     always completes synchronously and always succeeds.
        /// </remarks>
        /// <param name="cancellationToken">
        ///     A cancellation token to cancel the asynchronous operation with. It is never observed, since the
        ///     operation never blocks, but is accepted to implement <see cref="IBrowsingClient" />.
        /// </param>
        /// <returns>
        ///     A collection of <see cref="ThreatListDescriptor" />.
        /// </returns>
        /// <exception cref="System.ObjectDisposedException">
        ///     Thrown if the object is disposed.
        /// </exception>
        public Task<IEnumerable<ThreatListDescriptor>> GetThreatListDescriptors(CancellationToken cancellationToken) {
            this.ThrowIfDisposed();

            var getThreatListDescriptorsTask = GetThreatListDescriptors();
            return getThreatListDescriptorsTask;

            // <summary>
            //      Get Threat List Descriptors Asynchronously.
            // </summary>
            async Task<IEnumerable<ThreatListDescriptor>> GetThreatListDescriptors() {

                List<ThreatListDescriptor> allLists = new List<ThreatListDescriptor>();
                foreach (var list in ValidThreatListNames)
                {
                    var name = ThreatListNameExtension.AsThreatListName(list);
                    var descriptor = new ThreatListDescriptor(name);
                    allLists.Add(descriptor);
                }

                return allLists;

            }
        }
    

        /// <summary>
        ///     Get Threat List Updates Asynchronously.
        /// </summary>
        /// <param name="request">
        ///     A <see cref="ThreatListUpdateRequest" />.
        /// </param>
        /// <param name="cancellationToken">
        ///     A cancellation token to cancel the asynchronous operation with.
        /// </param>
        /// <returns>
        ///     A <see cref="ThreatListUpdateResponse" />.
        /// </returns>
        /// <exception cref="Gee.External.Browsing.Clients.BrowsingClientException">
        ///     Thrown if an error communicating with the Google Safe Browsing API occurs.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="request" /> is a null reference.
        /// </exception>
        /// <exception cref="System.ObjectDisposedException">
        ///     Thrown if the object is disposed.
        /// </exception>
        /// <exception cref="System.OperationCanceledException">
        ///     Thrown if the asynchronous operation is cancelled.
        /// </exception>
        /// <exception cref="System.TimeoutException">
        ///     Thrown if communication with the Google Safe Browsing API times out.
        /// </exception>
        public Task<ThreatListUpdateResponse> GetThreatListUpdatesAsync(ThreatListUpdateRequest request, CancellationToken cancellationToken) {
            this.ThrowIfDisposed();
            Guard.ThrowIf(nameof(request), request).Null();

            var getThreatListUpdatesTask = GetThreatListUpdatesAsync(request, cancellationToken);
            return getThreatListUpdatesTask;

            // <summary>
            //      Get Threat List Updates Asynchronously.
            // </summary>
            async Task<ThreatListUpdateResponse> GetThreatListUpdatesAsync(ThreatListUpdateRequest cRequest, CancellationToken cCancellationToken) {
                try {
                    // ...
                    //
                    // Throws an exception if the operation fails.


                    var updateQueries = cRequest.Queries;
                    var url = new Flurl.Url(GetThreatListUpdatesUri);

                    List<int> maxUpdateEntries = new List<int>();
                    List<int> maxDatabaseEntries = new List<int>();

                    foreach (var query in updateQueries)
                    {
                        if (query.ThreatListDescriptor.ThreatListName == ThreatListName.unsupported)
                        {
                            continue;
                        }

                        url.QueryParams.Add("names", ThreatConverter.ThreatListNameToUrlQueryString(query.ThreatListDescriptor.ThreatListName));
                        if (query.ThreatListState != null)
                        {
                            url.QueryParams.Add("version", Convert.ToBase64String(Convert.FromHexString(query.ThreatListState)));
                        }
                        if (!(query.UpdateConstraints is null))
                        {
                            maxUpdateEntries.Add(query.UpdateConstraints.MaximumResponseEntries);
                            maxDatabaseEntries.Add(query.UpdateConstraints.MaximumDatabaseEntries);
                        }  

                    }

                    int maxUpdate = 0;
                    int maxDatabase = 0;
                    if (!(maxUpdateEntries.Count() == 0 || maxDatabaseEntries.Count() == 0))
                    {
                        maxUpdateEntries.Sort();
                        foreach (var entry in maxUpdateEntries)
                        {
                            if (entry > 0)
                            {
                                maxUpdate = entry;
                                break;
                            }
                        }
                        maxDatabaseEntries.Sort();
                         foreach (var entry in maxDatabaseEntries)
                        {
                            if (entry > 0)
                            {
                                maxDatabase = entry;
                                break;
                            }
                        }
                    }

                    url.QueryParams.Add("sizeConstraints.maxUpdateEntries",  maxUpdate);
                    url.QueryParams.Add("sizeConstraints.maxDatabaseEntries", maxDatabase);
                        

                    
                    var cResponseBytes = await url
                                        .GetBytesAsync(cCancellationToken)
                                        .ConfigureAwait(false);

                    var cResponseMessage = BatchGetHashListsResponse.Parser.ParseFrom(cResponseBytes);
                    


                    List<ThreatListUpdateResult> threatsToReturn = new List<ThreatListUpdateResult>();
                    foreach (var hashList in cResponseMessage.HashLists)
                    {
                        var threatListName = ThreatConverter.StringToThreatListName(hashList.Name);
                        if (threatListName == ThreatListName.unsupported)
                        {
                            continue;
                        }

                        uint[] decodedRemovals = Array.Empty<uint>();
                        if (!(hashList.CompressedRemovals is null))
                        {
                            decodedRemovals = GolombRiceDecoder32Bit.Decode(hashList.CompressedRemovals);
                        }

                        uint[] decodedAdditions = Array.Empty<uint>();
                        if (!(hashList.AdditionsFourBytes is null))
                        {
                            decodedAdditions = GolombRiceDecoder32Bit.Decode(hashList.AdditionsFourBytes);  
                        }

                        

                        ThreatListDescriptor descriptor = new ThreatListDescriptor(threatListName);
                        

                        var version = Convert.ToHexString(hashList.Version.ToByteArray()); 

                        DateTime? minimumWait = null;
                        if (!(hashList.MinimumWaitDuration is null))
                        {
                            minimumWait = DateTime.UtcNow + DurationConverter.SafeBrowsingDurationToTimespan(hashList.MinimumWaitDuration);
                        }
                      
                                              
                        var query = updateQueries.FirstOrDefault(q => q.ThreatListDescriptor.Equals(descriptor));
                        if (query is null) { continue; }    

                        ThreatList threatList = new ThreatList(descriptor, version, DateTime.UtcNow, minimumWait);

                        ThreatListUpdateResultBuilder builder = new ThreatListUpdateResultBuilder();

                        foreach (var entry in decodedRemovals)
                        {
                            builder.AddThreatToRemove((int)entry);
                        }
                        
                        
                        foreach (var entry in decodedAdditions)
                        {
                            builder.AddThreatToAdd(entry.ToString("X8"));
                        }
                        

                        builder.SetQuery(query);
                        builder.SetRetrievedThreatList(threatList);

                        if (!hashList.Sha256Checksum.IsEmpty)
                        {
                        builder.SetRetrievedThreatListChecksum(Convert.ToHexString(hashList.Sha256Checksum.ToByteArray()));
                        } 


                        if (hashList.PartialUpdate == true)
                        {
                            builder.SetUpdateType(ThreatListUpdateType.Partial);
                        }
                        else if (hashList.PartialUpdate == false)
                        {
                            builder.SetUpdateType(ThreatListUpdateType.Full);
                        }
                                              
                        var result = builder.Build();

                        threatsToReturn.Add(result);
                    }

                    return new ThreatListUpdateResponse(cRequest, threatsToReturn);
                }
                catch (FlurlHttpTimeoutException cEx) {
                    const string cDetailMessage = "An HTTP request to the Google Safe Browsing API timed out.";
                    throw new TimeoutException(cDetailMessage, cEx);
                }
                catch (FlurlHttpException cEx) {
                    var httpStatusCode = cEx.Call.HttpStatus ?? HttpStatusCode.BadRequest;
                    const string cDetailMessage = "An HTTP request to the Google Safe Browsing API failed.";
                    throw new BrowsingClientException(cDetailMessage, httpStatusCode, cEx);
                }
            }
        }

        /// <summary>
        ///     Throw an Exception if Object is Disposed.
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">
        ///     Thrown if the object is disposed.
        /// </exception>
        private void ThrowIfDisposed() {
            if (this._disposed) {
                var detailMessage = $"An object ({nameof(HttpBrowsingClient)}) is disposed.";
                throw new ObjectDisposedException(nameof(HttpBrowsingClient), detailMessage);
            }
        }

        /// <summary>
        ///     HTTP Client Factory.
        /// </summary>
        private sealed class HttpClientFactory : DefaultHttpClientFactory {
            /// <summary>
            ///     Create an HTTP Client.
            /// </summary>
            /// <param name="httpMessageHandler">
            ///     An HTTP message handler for the HTTP client to use.
            /// </param>
            /// <returns>
            ///     An HTTP client.
            /// </returns>
            public override HttpClient CreateHttpClient(HttpMessageHandler httpMessageHandler) {
                var httpClient = base.CreateHttpClient(httpMessageHandler);
                httpClient.DefaultRequestHeaders.Add("Accept", "application/x-protobuf");
                httpClient.Timeout = TimeSpan.FromMinutes(1);

                return httpClient;
            }

            /// <summary>
            ///     Create an HTTP Message Handler.
            /// </summary>
            /// <returns>
            ///     An HTTP message handler.
            /// </returns>
            public override HttpMessageHandler CreateMessageHandler() {
                var httpMessageHandler = base.CreateMessageHandler();
                if (httpMessageHandler is HttpClientHandler httpClientHandler) {
                    if (httpClientHandler.SupportsAutomaticDecompression) {
                        // ...
                        //
                        // The Google Safe Browsing API supports compressed HTTP responses if the correct HTTP headers
                        // are set in an HTTP request. This should make the HTTP client automatically add the correct
                        // HTTP headers with every HTTP request.
                        httpClientHandler.AutomaticDecompression = DecompressionMethods.Deflate |
                                                                   DecompressionMethods.GZip;
                    }

                    httpClientHandler.UseCookies = false;
                    httpClientHandler.UseDefaultCredentials = false;
                }

                return httpMessageHandler;
            }
        }
    }
}