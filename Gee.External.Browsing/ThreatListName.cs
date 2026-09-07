namespace Gee.External.Browsing {
    /// <summary>
    ///     Threat Entry Type.
    /// </summary>
    /// <remarks>
    ///     Indicates how a threat is posed. A <see cref="ThreatListName" /> is also used as the name of the list.
    /// </remarks>
    public enum ThreatListName {
        /// <summary>
        ///     Indicates a threat is posed through an unknown type.
        /// </summary>
        unsupported = 0,

        /// <summary>
        ///     Indicates social engineering threat.
        /// </summary>
        se_4b = 1,

        /// <summary>
        ///     Indicates malware threat.
        /// </summary>
        mw_4b = 2,

        /// <summary>
        ///     Indicates unwanted software threat.
        /// </summary>
        uws_4b = 3,

        /// <summary>
        ///     Indicates potentially harmful app threat.
        /// </summary>
        pha_4b = 4
    }
}