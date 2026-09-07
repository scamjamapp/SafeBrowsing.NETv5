namespace Gee.External.Browsing {
    /// <summary>
    ///     Threat Type.
    /// </summary>
    /// <remarks>
    ///     Indicates the nature of a threat in a v5 hashes.search lookup (in FullHashDetail) /> 
    /// </remarks>
    public enum ThreatType {
        /// <summary>
        ///     Indicates an unknown threat.
        /// </summary>
        Unknown = 0,

        /// <summary>
        ///     Indicates a threat is malware. Malware is software that is specifically designed to disrupt, damage,
        ///     or gain unauthorized access to a computer system.
        /// </summary>
        Malware = 1,

        /// <summary>
        ///     Indicates a threat is a potentially harmful application (PHA). A PHA is one that could put users, user
        ///     data, or computer systems at risk.
        /// </summary>
        PotentiallyHarmfulApplication = 4,

        /// <summary>
        ///     Indicates a threat is social engineering content. Social engineering content tricks users into doing
        ///     something dangerous, such as revealing confidential information or downloading software.
        /// </summary>
        SocialEngineering = 2,

        /// <summary>
        ///     Indicates a threat is unwanted software. Unwanted software is one that is deceptive, trick users into
        ///     installing it or it piggybacks on the installation of another software, does not tell users about all
        ///     of its principal and significant functions, affects a user's system in unexpected ways, is difficult
        ///     to remove, collects or transmits private information without a user's knowledge, or is bundled with
        ///     other software and its presence is not disclosed.
        /// </summary>
        UnwantedSoftware = 3
    }
}