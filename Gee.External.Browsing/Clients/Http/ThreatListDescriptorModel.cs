using Newtonsoft.Json;
using System;

namespace Gee.External.Browsing.Clients.Http {
    /// <summary>
    ///     Threat List Descriptor Model.
    /// </summary>
    [Serializable]
    internal sealed class ThreatListDescriptorModel {
        /// <summary>
        ///     Get and Set Threat Type.
        /// </summary>
        [JsonProperty(PropertyName = "threatListName", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string ThreatListName { get; set; }
    }
}