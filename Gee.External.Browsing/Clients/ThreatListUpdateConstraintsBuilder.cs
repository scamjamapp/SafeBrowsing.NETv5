using System;
using Gee.Common.Guards;
using Gee.External.Browsing.Databases;

namespace Gee.External.Browsing.Clients {
    /// <summary>
    ///     Threat List Update Constraints Builder.
    /// </summary>
    public sealed class ThreatListUpdateConstraintsBuilder {

        /// <summary>
        ///     Get and Set Maximum Database Entries.
        /// </summary>
        /// <remarks>
        ///     Represents the maximum number of threats associated with a <see cref="ThreatList" /> a client is
        ///     willing, or is capable, of storing in its local <see cref="IManagedBrowsingDatabase" />. A <c>0</c>
        ///     indicates there is no limit to the number of threats the client is willing to store.
        /// </remarks>
        internal int MaximumDatabaseEntries { get; private set; }

        /// <summary>
        ///     Get and Set Maximum Response Entries.
        /// </summary>
        /// <remarks>
        ///     Represents the maximum number of threats associated with a <see cref="ThreatList" /> that will be
        ///     retrieved in a single request. A <c>0</c> indicates there is no limit to the number of threats that
        ///     will be retrieved.
        /// </remarks>
        internal int MaximumResponseEntries { get; private set; }

        /// <summary>
        ///     Build a Threat List Update Constraints.
        /// </summary>
        /// <returns>
        ///     A <see cref="ThreatListUpdateConstraints" />.
        /// </returns>
        public ThreatListUpdateConstraints Build() {
            var threatListUpdateConstraints = new ThreatListUpdateConstraints(this);

            // ...
            //
            // Reinitialize the builder's state to prevent it from corrupting the immutable built object's state after
            // its built. If the object holds a reference to the builder's state, any mutation to the builder's state
            // will be reflected in the built object's state.
            this.MaximumDatabaseEntries = default;
            this.MaximumResponseEntries = default;

            return threatListUpdateConstraints;
        }

        /// <summary>
        ///     Set Maximum Database Entries.
        /// </summary>
        /// <param name="value">
        ///     The maximum number of threats associated with a <see cref="ThreatList" /> a client is willing, or is
        ///     capable, of storing in its local <see cref="IManagedBrowsingDatabase" />. A <c>0</c> indicates there is
        ///     no limit to the number of threats the client is willing to store.
        /// </param>
        /// <returns>
        ///     This threat list update constraints builder.
        /// </returns>
        /// <exception cref="System.ArgumentOutOfRangeException">
        ///     Thrown if <paramref name="value" /> is less than <c>0</c>.
        /// </exception>
        public ThreatListUpdateConstraintsBuilder SetMaximumDatabaseEntries(int value) {
            Guard.ThrowIf(nameof(value), value).LessThan(0);

            this.MaximumDatabaseEntries = value;
            return this;
        }

        /// <summary>
        ///     Set Maximum Response Entries.
        /// </summary>
        /// <param name="value">
        ///     The maximum number of threats associated with a <see cref="ThreatList" /> that will be retrieved in a
        ///     single request. A <c>0</c> indicates there is no limit to the number of threats that will be
        ///     retrieved.
        /// </param>
        /// <returns>
        ///     This threat list update constraints builder.
        /// </returns>
        /// <exception cref="System.ArgumentOutOfRangeException">
        ///     Thrown if <paramref name="value" /> is less than <c>0</c>.
        /// </exception>
        public ThreatListUpdateConstraintsBuilder SetMaximumResponseEntries(int value) {
            Guard.ThrowIf(nameof(value), value).LessThan(0);

            if (0 < value && value < 1024)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "invalid value for MaximumResponseEntries, refer to https://developers.google.com/safe-browsing/reference/rest/v5/hashList#resource:-hashlist");
            }

            this.MaximumResponseEntries = value;
            return this;
        }
    }
}