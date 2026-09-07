namespace Gee.External.Browsing.Clients.Http {
    /// <summary>
    ///     Threat Type Extension.
    /// </summary>
    internal static class ThreatListNameExtension {
        /// <summary>
        ///     Create a Threat List Name.
        /// </summary>
        /// <param name="this">
        ///     A string identifying a <see cref="ThreatListName" />.
        /// </param>
        /// <returns>
        ///     A <see cref="ThreatListName" />.
        /// </returns>
        internal static ThreatListName AsThreatListName(this string @this) {
            ThreatListName threatListName;
            switch (@this) {
                case "se_4b":
                case "se-4b":
                    threatListName = ThreatListName.se_4b;
                    break;
                case "mw_4b":
                case "mw-4b":
                    threatListName = ThreatListName.mw_4b;
                    break;
                case "uws_4b":
                case "uws-4b":
                    threatListName = ThreatListName.uws_4b;
                    break;
                case "pha_4b":
                case "pha-4b":
                    threatListName = ThreatListName.pha_4b;
                    break;
                default:
                    threatListName = ThreatListName.unsupported;
                    break;
            }

            return threatListName;
        }

        /// <summary>
        ///     Create a Threat Type Model.
        /// </summary>
        /// <param name="this">
        ///     A <see cref="ThreatType" />.
        /// </param>
        /// <returns>
        ///     A string identifying a <see cref="ThreatType" />.
        /// </returns>
        internal static string AsThreatListNameModel(this ThreatListName @this) {
            string threatListNameModel;
            switch (@this) {
                case ThreatListName.unsupported:
                    threatListNameModel = "unsupported";
                    break;
                case ThreatListName.se_4b:
                    threatListNameModel = "se-4b";
                    break;
                case ThreatListName.mw_4b:
                    threatListNameModel = "mw-4b";
                    break;
                case ThreatListName.uws_4b:
                    threatListNameModel = "uws-4b";
                    break;
                case ThreatListName.pha_4b:
                    threatListNameModel = "pha-4b";
                    break;
                default:
                    threatListNameModel = "unsupported";
                    break;
            }

            return threatListNameModel;
        }
    }
}