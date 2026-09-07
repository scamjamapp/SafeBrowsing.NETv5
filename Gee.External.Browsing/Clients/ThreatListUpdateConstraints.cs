using Gee.Common.Guards;
using Gee.External.Browsing.Databases;
using System.Runtime.CompilerServices;

namespace Gee.External.Browsing.Clients {
    /// <summary>
    ///     Threat List Update Constraints.
    /// </summary>
    public sealed class ThreatListUpdateConstraints {
        /// <summary>
        ///     Default Threat List Update Constraints.
        /// </summary>
        public static readonly ThreatListUpdateConstraints Default;

        /// <summary>
        ///     Get Maximum Database Entries.
        /// </summary>
        /// <remarks>
        ///     Represents the maximum number of threats associated with a <see cref="ThreatList" /> a client is
        ///     willing, or is capable, of storing in its local <see cref="IManagedBrowsingDatabase" />. A <c>0</c>
        ///     indicates there is no limit to the number of threats the client is willing to store.
        /// </remarks>
        public int MaximumDatabaseEntries { get; }

        /// <summary>
        ///     Get Maximum Response Entries.
        /// </summary>
        /// <remarks>
        ///     Represents the maximum number of threats associated with a <see cref="ThreatList" /> that will be
        ///     retrieved in a single request. A <c>0</c> indicates there is no limit to the number of threats that
        ///     will be retrieved.
        /// </remarks>
        public int MaximumResponseEntries { get; }

        /// <summary>
        ///     Create a Threat List Update Constraints.
        /// </summary>
        static ThreatListUpdateConstraints() {
            ThreatListUpdateConstraints.Default = CreateDefault();

            // <summary>
            //      Create Default Threat List Update Constraints.
            // </summary>
            ThreatListUpdateConstraints CreateDefault() {
                var cThreatListUpdateConstraints = ThreatListUpdateConstraints.Build()
                    .SetMaximumDatabaseEntries(0)
                    .SetMaximumResponseEntries(0)
                    .Build();

                return cThreatListUpdateConstraints;
            }
        }

        /// <summary>
        ///     Build a Threat List Update Constraints.
        /// </summary>
        /// <returns>
        ///     A <see cref="ThreatListUpdateConstraintsBuilder" /> to build a threat list update constraints with.
        /// </returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ThreatListUpdateConstraintsBuilder Build() {
            return new ThreatListUpdateConstraintsBuilder();
        }

        /// <summary>
        ///     Create a Threat List Update Constraints.
        /// </summary>
        /// <param name="builder">
        ///     A <see cref="ThreatListUpdateConstraintsBuilder" /> to initialize the  threat list update constraints
        ///     with.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="builder" /> is a null reference.
        /// </exception>
        internal ThreatListUpdateConstraints(ThreatListUpdateConstraintsBuilder builder) {
            Guard.ThrowIf(nameof(builder), builder).Null();

            this.MaximumDatabaseEntries = builder.MaximumDatabaseEntries;
            this.MaximumResponseEntries = builder.MaximumResponseEntries;
        }
    }
}