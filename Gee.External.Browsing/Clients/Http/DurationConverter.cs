using System;

namespace Gee.External.Browsing.Clients.Http
{
    static class DurationConverter
    {
        internal static TimeSpan SafeBrowsingDurationToTimespan (SafeBrowsing.V5.Duration duration)
        {
            if (duration is null)
            {
                throw new ArgumentNullException(nameof(duration), "server responded with null cacheDuration!");
            }

            TimeSpan result = TimeSpan.FromSeconds(duration.Seconds) + TimeSpan.FromTicks(duration.Nanos / 100);
            
             return result;
        }

    }
    
}