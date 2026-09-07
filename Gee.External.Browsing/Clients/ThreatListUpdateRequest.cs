using Gee.Common.Guards;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Gee.External.Browsing.Clients {
    /// <summary>
    ///     Threat List Update Request.
    /// </summary>
    public sealed class ThreatListUpdateRequest {

        /// <summary>
        ///     Get Queries.
        /// </summary>
        /// <remarks>
        ///     Represents the collection of <see cref="ThreatListUpdateQuery" /> indicating the collection of
        ///     <see cref="ThreatList" /> to retrieve.
        /// </remarks>
        public IEnumerable<ThreatListUpdateQuery> Queries { get; }

        /// <summary>
        ///     Build a Threat List Update Request.
        /// </summary>
        /// <returns>
        ///     A <see cref="ThreatListUpdateRequestBuilder" /> to build a threat list update request with.
        /// </returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ThreatListUpdateRequestBuilder Build() {
            return new ThreatListUpdateRequestBuilder();
        }

        /// <summary>
        ///     Create a Threat List Update Request.
        /// </summary>
        /// <param name="queries">
        ///     A collection of <see cref="ThreatListUpdateQuery" /> indicating the collection of
        ///     <see cref="ThreatList" /> to retrieve.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="queries" /> is a null reference.
        /// </exception>
        public ThreatListUpdateRequest(IEnumerable<ThreatListUpdateQuery> queries)
        {
            Guard.ThrowIf(nameof(queries), queries).Null();

            this.Queries = new HashSet<ThreatListUpdateQuery>(queries);
        }

        

        /// <summary>
        ///     Create a Threat List Update Request.
        /// </summary>
        /// <param name="builder">
        ///     A <see cref="ThreatListUpdateRequestBuilder" /> to initialize the threat list update request with.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="builder" /> is a null reference.
        /// </exception>
        internal ThreatListUpdateRequest(ThreatListUpdateRequestBuilder builder) {
            Guard.ThrowIf(nameof(builder), builder).Null();

            this.Queries = builder.Queries;
        }
    }
}