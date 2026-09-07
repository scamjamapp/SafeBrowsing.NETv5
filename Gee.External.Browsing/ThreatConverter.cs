using System;
using SafeBrowsing.V5;

namespace Gee.External.Browsing {
    /// <summary>
    ///     ThreatType Converter.
    /// </summary>
    /// <remarks>
    ///     Converts v4 Style ThreatTypes to v5 threat list names. Weirdly enough,
    ///     ThreatTypes are still used when you lookup a hash via hashes.search. Trying to
    ///     keep everything consistant and using the hashlist name.
    /// </remarks>
    internal static class ThreatConverter {
        /// <summary>
        ///     Create a ThreatTypeName from the string form of a ThreatType.
        /// </summary>
        /// <param name="threatType">
        ///     The type you want to convert, need to be a valid ThreatType in
        ///     string form.
        /// </param>
        /// <returns>
        ///     A <see cref="ThreatListName" />, will return the "unsupported"
        ///     list if input is invalid.
        /// </returns>
        internal static ThreatListName ThreatTypeToThreatListName(SafeBrowsing.V5.ThreatType threatType) {
            switch (threatType) {
                case SafeBrowsing.V5.ThreatType.SocialEngineering: 
                    return ThreatListName.se_4b;
                case SafeBrowsing.V5.ThreatType.Malware:           
                    return ThreatListName.mw_4b;
                case SafeBrowsing.V5.ThreatType.UnwantedSoftware:  
                    return ThreatListName.uws_4b;
                case SafeBrowsing.V5.ThreatType.PotentiallyHarmfulApplication: 
                    return ThreatListName.pha_4b;
                default: return ThreatListName.unsupported;
            }
        }

        internal static ThreatListName StringToThreatListName(string name) {
            switch (name) {
                case "se_4b":
                case "se-4b":
                    return ThreatListName.se_4b;
                case "mw_4b":
                case "mw-4b":
                    return ThreatListName.mw_4b;
                case "uws_4b":
                case "uws-4b":
                    return ThreatListName.uws_4b;
                case "pha_4b":
                case "pha-4b":
                    return ThreatListName.pha_4b;
                default:
                    return ThreatListName.unsupported;
            }
        }

        internal static ThreatType StringToThreatType(string threatType) {
            switch (threatType) {
                case "SOCIAL_ENGINEERING":
                case "SocialEngineering":
                    return ThreatType.SocialEngineering;
                case "MALWARE":
                case "Malware":
                    return ThreatType.Malware;
                case "UNWANTED_SOFTWARE":
                case "UnwantedSoftware":
                    return ThreatType.UnwantedSoftware;
                case "POTENTIALLY_HARMFUL_APPLICATION":
                case "PotentiallyHarmfulApplication":
                    return ThreatType.PotentiallyHarmfulApplication;
                default:
                    return ThreatType.Unknown;
            }
        }

        internal static string ThreatListNameToUrlQueryString(ThreatListName threatListName) {
            switch (threatListName) {
                case ThreatListName.se_4b:
                    return "se-4b";
                case ThreatListName.mw_4b:
                    return "mw-4b";
                case ThreatListName.uws_4b:
                    return "uws-4b";
                case ThreatListName.pha_4b:
                    return "pha-4b";
                default:
                    return "unsupported";
            }
        }

    }
}
