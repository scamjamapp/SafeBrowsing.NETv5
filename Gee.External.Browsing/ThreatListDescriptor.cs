namespace Gee.External.Browsing {
    /// <summary>
    ///     Threat List Descriptor.
    /// </summary>
    /// <remarks>
    ///     Identifies a threat list. A threat list is identified using a <see cref="Browsing.ThreatListName" />
    /// </remarks>
    public sealed class ThreatListDescriptor {
        /// <summary>
        ///     Determine if Threat List is a Malware List.
        /// </summary>
        /// <remarks>
        ///     Determines if the threat list is on <see cref="Browsing.ThreatListName.mw_4b" /> list.
        /// </remarks>
        public bool IsMalwareList => this.ThreatListName == ThreatListName.mw_4b;

        /// <summary>
        ///     Determine if Threat List is a Potentially Harmful Application List.
        /// </summary>
        /// <remarks>
        ///     Determines if the threat list is a <see cref="ThreatListName.pha_4b" />
        ///     (PHA) list.
        /// </remarks>
        public bool IsPotentiallyHarmfulApplicationList => this.ThreatListName == ThreatListName.pha_4b;

        /// <summary>
        ///     Determine if Threat List is a Social Engineering List.
        /// </summary>
        /// <remarks>
        ///     Determines if the threat list is a <see cref="ThreatListName.se_4b" /> list.
        /// </remarks>
        public bool IsSocialEngineeringList => this.ThreatListName == ThreatListName.se_4b;

        /// <summary>
        ///     Determine if Threat List is an Unwanted Software List.
        /// </summary>
        /// <remarks>
        ///     Determines if the threat list is an <see cref="ThreatListName.uws_4b" /> list.
        /// </remarks>
        public bool IsUnwantedSoftwareList => this.ThreatListName == ThreatListName.uws_4b;

        /// <summary>
        ///     Get Threat List's Threat Type.
        /// </summary>
        /// <remarks>
        ///     Represents the <see cref="ThreatType" /> identifying the threat list.
        /// </remarks>
        public ThreatListName ThreatListName { get; }

        /// <summary>
        ///     Create a Threat List Descriptor.
        /// </summary>
        /// <param name="threatListName">
        ///     A <see cref="ThreatListName" /> identifying the threat list.
        /// </param>
        public ThreatListDescriptor(ThreatListName threatListName) {
            this.ThreatListName = threatListName;
        }

        /// <summary>
        ///     Determine if Object is Equal to Another Object.
        /// </summary>
        /// <param name="object">
        ///     An object to compare to.
        /// </param>
        /// <returns>
        ///     A boolean true if the object is equal to <paramref name="object" />. A boolean false otherwise.
        /// </returns>
        public override bool Equals(object @object) {
            var isEqual = @object != null &&
                          @object is ThreatListDescriptor threatListDescriptor &&
                          this.ThreatListName == threatListDescriptor.ThreatListName;

            return isEqual;
        }

        /// <summary>
        ///     Get Object's Hash Code.
        /// </summary>
        /// <returns>
        ///     The object's hash code.
        /// </returns>
        public override int GetHashCode() {
            unchecked {
                var hashCode = 13;
                hashCode = hashCode * 7 + this.ThreatListName.GetHashCode();

                return hashCode;
            }
        }

        /// <summary>
        ///     Get Object's String Representation.
        /// </summary>
        /// <returns>
        ///     The object's string representation.
        /// </returns>
        public override string ToString() {
            var @string = $"{this.ThreatListName}";
            return @string;
        }
    }
}