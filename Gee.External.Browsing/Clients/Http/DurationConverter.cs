using System;

namespace Gee.External.Browsing.Clients.Http
{
    static class DurationConverter
    {
        internal static TimeSpan SafeBrowsingDurationToTimespan (SafeBrowsing.V5.Duration duration)
        {
            if (duration is null)
            {
                throw new ArgumentNullException(nameof(duration), "duration is null!");
            }

            TimeSpan result = new TimeSpan(0, 0, 0, (int)duration.Seconds, duration.Nanos);
            
             return result;
        }

    }
    
}