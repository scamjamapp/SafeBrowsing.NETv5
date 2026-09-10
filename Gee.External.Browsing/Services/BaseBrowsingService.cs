using Gee.External.Browsing.Cache;
using Gee.External.Browsing.Clients;
using Gee.External.Browsing.Databases;
using Google.Protobuf.Collections;
using Google.Protobuf.WellKnownTypes;
using SafeBrowsing.V5;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Gee.External.Browsing.Services {
    /// <summary>
    ///     Base Service.
    /// </summary>
    public abstract class BaseBrowsingService : IBrowsingService {
        /// <summary>
        ///     Create a Base Service.
        /// </summary>
        private protected BaseBrowsingService() { }

        /// <summary>
        ///     Dispose Object.
        /// </summary>
        public abstract void Dispose();

        /// <summary>
        ///     Lookup a URL.
        /// </summary>
        /// <param name="url">
        ///     A <see cref="Url" /> to lookup.
        /// </param>
        /// <param name="cancellationToken">
        ///     A cancellation token to cancel the asynchronous operation with.
        /// </param>
        /// <returns>
        ///     A <see cref="UrlLookupResult" /> indicating whether <paramref name="url" /> is
        ///     <see cref="UrlLookupResultCode.Safe" /> or <see cref="UrlLookupResultCode.Unsafe" />.
        /// </returns>
        /// <exception cref="Gee.External.Browsing.Cache.BrowsingCacheException">
        ///     Thrown if a caching error occurs. If you're not interested in handling this exception, catch
        ///     <see cref="BrowsingException" /> instead.
        /// </exception>
        /// <exception cref="Gee.External.Browsing.Clients.BrowsingClientException">
        ///     Thrown if an error communicating with the Google Safe Browsing API occurs. If you're not interested
        ///     in handling this exception, catch <see cref="BrowsingException" /> instead.
        /// </exception>
        /// <exception cref="Gee.External.Browsing.Databases.BrowsingDatabaseException">
        ///     Thrown if a database error occurs. If you're not interested in handling this exception, catch
        ///     <see cref="BrowsingException" /> instead.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="url" /> is a null reference.
        /// </exception>
        /// <exception cref="System.ObjectDisposedException">
        ///     Thrown if the object is disposed.
        /// </exception>
        /// <exception cref="System.OperationCanceledException">
        ///     Thrown if the asynchronous operation is cancelled.
        /// </exception>
        public abstract Task<UrlLookupResult> LookupAsync(Url url, CancellationToken cancellationToken);

        /// <summary>
        ///     Lookup a URL.
        /// </summary>
        /// <param name="cache">
        ///     A <see cref="IBrowsingCache" />.
        /// </param>
        /// <param name="client">
        ///     A <see cref="IBrowsingClient" />.
        /// </param>
        /// <param name="database">
        ///     An <see cref="IUnmanagedBrowsingDatabase" />.
        /// </param>
        /// <param name="url">
        ///     A <see cref="Url" /> to lookup.
        /// </param>
        /// <param name="cancellationToken">
        ///     A cancellation token to cancel the asynchronous operation with.
        /// </param>
        /// <returns>
        ///     A <see cref="UrlLookupResult" /> indicating whether <paramref name="url" /> is
        ///     <see cref="UrlLookupResultCode.Safe" /> or <see cref="UrlLookupResultCode.Unsafe" />.
        /// </returns>
        /// <exception cref="Gee.External.Browsing.Cache.BrowsingCacheException">
        ///     Thrown if a caching error occurs. If you're not interested in handling this exception, catch
        ///     <see cref="BrowsingException" /> instead.
        /// </exception>
        /// <exception cref="Gee.External.Browsing.Clients.BrowsingClientException">
        ///     Thrown if an error communicating with the Google Safe Browsing API occurs. If you're not interested
        ///     in handling this exception, catch <see cref="BrowsingException" /> instead.
        /// </exception>
        /// <exception cref="Gee.External.Browsing.Databases.BrowsingDatabaseException">
        ///     Thrown if a database error occurs. If you're not interested in handling this exception, catch
        ///     <see cref="BrowsingException" /> instead.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="url" /> is a null reference.
        /// </exception>
        /// <exception cref="System.ObjectDisposedException">
        ///     Thrown if <paramref name="cache" /> is disposed, or if <paramref name="client" /> is disposed, or if
        ///     <paramref name="database" /> is disposed.
        /// </exception>
        /// <exception cref="System.OperationCanceledException">
        ///     Thrown if the asynchronous operation is cancelled.
        /// </exception>
        private protected async Task<UrlLookupResult> LookupAsync(IBrowsingCache cache, IBrowsingClient client, IUnmanagedBrowsingDatabase database, Url url, CancellationToken cancellationToken) {
            //Lookup in cache:
            var expressions = url.Expressions;
            Dictionary<UrlExpression, string> expressionToFullHash = new Dictionary<UrlExpression, string>();
            Dictionary<string, List<string>> fullHashToHashPrefixList = new Dictionary<string, List<string>>();
            foreach (var item in expressions)
            {
                expressionToFullHash.TryAdd(item, item.Sha256Hash);
                fullHashToHashPrefixList.TryAdd(item.Sha256Hash, (List<string>)item.Sha256HashPrefixes);
            }


            var urlLookupDate = DateTime.UtcNow;
            UrlLookupResult urlLookupResult;

            // ...
            //
            // Hash prefixes the cache has already answered for. A safe cache hit means the API was asked about that
            // prefix recently and told us the complete set of unsafe full hashes under it, and that this expression's
            // full hash was not among them. That settles the PREFIX, so we need not ask about it again - but it does
            // NOT settle the URL, which has an expression, and therefore a prefix, for each of its host and path
            // combinations. Answering safe here would let a stale entry on a harmless prefix such as "example.com/"
            // suppress every other expression, "example.com/malware/" included.
            var cacheAnsweredPrefixes = new HashSet<string>();
            foreach (var dictEntry in fullHashToHashPrefixList)
            {
                foreach (var hashPrefix in dictEntry.Value)
                {
                    var cacheLookupTask = cache.LookupAsync(dictEntry.Key, hashPrefix, cancellationToken);
                    var cacheLookupResult = await cacheLookupTask.ConfigureAwait(false);
                    if (cacheLookupResult.IsCacheExpiredHit)
                    {
                        continue;
                    }
                    else if (cacheLookupResult.IsCacheUnsafeHit)
                    {
                        var exp = expressionToFullHash.FirstOrDefault(x => x.Value == dictEntry.Key).Key;
                        return urlLookupResult = UrlLookupResult.Unsafe(url, urlLookupDate, exp, cacheLookupResult.UnsafeThreatListDescriptors);
                    }
                    else if (cacheLookupResult.IsCacheSafeHit)
                    {
                        cacheAnsweredPrefixes.Add(hashPrefix);
                    }
                }
            }

            var survivingPrefixes = new List<string>();
            foreach (var dictEntry in fullHashToHashPrefixList)
            {
                foreach (var hashPrefix in dictEntry.Value)
                {
                    if (cacheAnsweredPrefixes.Contains(hashPrefix))
                    {
                        continue;
                    }

                    var threatLists = await database.FindThreatListsAsync(hashPrefix, cancellationToken).ConfigureAwait(false);
                    if (threatLists.Count != 0)
                    {
                        survivingPrefixes.Add(hashPrefix);
                    }
                }
            }

            

            var builder = FullHashRequest.Build();
            foreach (var hashPrefix in survivingPrefixes)
            {
                builder.AddSha256HashPrefix(hashPrefix);
            }

            List<UnsafeThreat> unsafeThreats = new List<UnsafeThreat>();
            if (survivingPrefixes.Count() != 0)
            {
                var fullHashResponse = await client.FindFullHashesAsync(builder.Build(), cancellationToken)
               .ConfigureAwait(false);
                unsafeThreats.AddRange(fullHashResponse.UnsafeThreats);

                // ...
                //
                // In accordance with the Google Safe Browsing v5 specification, the cache duration the API returns
                // "applies to every hash prefix queried by the client in the request, regardless of how many full
                // hashes are returned in the response. Even if the server returns no full hashes for a particular
                // hash prefix, this fact should also be cached by the client." So we record the answer against every
                // prefix we asked about, not only against the ones that came back unsafe. Without this a URL that is
                // in the local database but safe is re-queried on every single lookup, forever.
                //
                // Throws an exception if the operation fails.
                var safeThreatsExpirationDate = fullHashResponse.SafeThreatsExpirationDate;
                foreach (var hashPrefix in survivingPrefixes)
                {
                    var putSafeCacheEntryTask = cache.PutSafeCacheEntryAsync(hashPrefix, safeThreatsExpirationDate, cancellationToken);
                    await putSafeCacheEntryTask.ConfigureAwait(false);
                }
            }
           



            
            if (unsafeThreats.Count != 0)
            {
                var unsafeThreatGroups = unsafeThreats.GroupBy(ut => ut.Sha256Hash);
                foreach (var unsafeThreatGroup in unsafeThreatGroups)
                {
                    // ...
                    //
                    // Throws an exception if the operation fails.
                    var unsafeThreatSha256Hash = unsafeThreatGroup.Key;
                    var putUnsafeCacheEntryTask = cache.PutUnsafeCacheEntryAsync(unsafeThreatSha256Hash, unsafeThreatGroup, cancellationToken);
                    await putUnsafeCacheEntryTask.ConfigureAwait(false);
                }
                foreach (var fullHash in unsafeThreats)
                {
                    if (fullHashToHashPrefixList.Keys.Contains(fullHash.Sha256Hash))
                    {
                        List<Gee.External.Browsing.ThreatListDescriptor> list = new List<Gee.External.Browsing.ThreatListDescriptor>();
                        list.Add(fullHash.AssociatedThreatListDescriptor);

                        var exp = expressionToFullHash.FirstOrDefault(x => x.Value == fullHash.Sha256Hash).Key;
                        return urlLookupResult = UrlLookupResult.Unsafe(url, urlLookupDate, exp, list);

                    }
                    
                }
            }

            // ...
            //
            // A hash prefix is removed above when the local threat list database does not hold it, so an empty or
            // out-of-date database prunes every prefix, asks the API nothing, and would fall through to safe for
            // every URL on the web. Before we conclude a URL is safe, we confirm the database was in a position to
            // answer at all. A confirmed unsafe verdict is returned above and is deliberately not masked by this.
            var databaseThreatLists = await database.GetThreatListsAsync(cancellationToken).ConfigureAwait(false);
            if (databaseThreatLists.Count == 0)
            {
                return UrlLookupResult.DatabaseStale(url, urlLookupDate);
            }

            foreach (var databaseThreatList in databaseThreatLists)
            {
                if (databaseThreatList.Expired && !databaseThreatList.AdditionalRequestPending)
                {
                    return UrlLookupResult.DatabaseStale(url, urlLookupDate);
                }
            }

            return UrlLookupResult.Safe(url, urlLookupDate);
        }
    }

}

