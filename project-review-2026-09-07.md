================================================================================
FULL PROJECT REVIEW - Gee.External.Browsing
Google Safe Browsing v4 -> v5 port
Reviewed: 2026-09-07   Branch: master (working tree, uncommitted)
Scope: whole project. v5 compatibility prioritised.
No source files were modified for this review.
===

BUILD STATE: succeeds (net10.0), 0 errors.
344 warnings, all nullable-reference analysis:
140 CS8618 (non-nullable never initialised)   68 CS8625 (null literal)
36 CS8600 (null to non-nullable)             28 CS8603 (possible null return)
16 CS8765 (override nullability mismatch)    12 CS8619 / 12 CS8604 / 6 CS8601

STATUS OF THE PREVIOUS REVIEW
Closed: A1-A6, B1-B4, B5(b), B5(c), B6-B14, C1, C3 and the XML doc warnings.
Still open and re-stated below: B5(a) -> V5, D1/D2 -> D2/D3, D4 -> D5,
E1 -> E1, E5 -> E7.

HOW TO READ THIS
V = Safe Browsing v5 protocol compatibility (highest priority)
C = correctness / reliability
D = API and design
E = dead code, build hygiene
Each finding cites file:line and states the concrete failure.

================================================================================
SECTION V - SAFE BROWSING v5 COMPATIBILITY
===

~~V1. \*\*\* URL PATH CANONICALIZATION IS INCOMPLETE - THIS IS A BYPASS VECTOR \*\*\*
File: Url.cs:179-198 (CanonicalizePath), Url.cs:49, 77
Severity: HIGH. Silent fail-open.~~

&#x20;   ~~The Safe Browsing canonicalization algorithm (unchanged from v4 to v5)
    requires that "/./" and "/../" be fully resolved. The implementation applies
    each Regex exactly once, and Regex.Replace scans left-to-right without
    re-examining what it produced, so nested sequences survive. Measured:

        input                    actual output      expected
        /a/b/../../c        ->   /a/../c            /c
        /./././x            ->   /./x               /x
        /1/2/3/../../../x   ->   /1/2/../../x       /x
        /a-b/../c           ->   /a-b/../c          /c

    Two distinct defects produce this:

    (a) Single-pass replacement. CurrentDirectoryPattern (Url.cs:49) and
        ParentDirectoryPattern (Url.cs:77) must be applied in a loop until the
        string stops changing.

    (b) ParentDirectoryPattern is `/\\w+/\\.\\./?`. `\\w` is \[A-Za-z0-9\_], so any
        path segment containing a hyphen, dot, tilde, or percent-escape is not
        matched at all - see /a-b/../c above. Path segments legally contain
        many more characters than \\w. The pattern should match any segment that
        is not "." or "..", e.g. `/\[^/]+/\\.\\./?`, with a guard so that a
        leading "/../" cannot escape above root.

    Why this matters: the client hashes the canonicalized URL expression. If the
    client's canonical form differs from Google's, the SHA256 differs, no prefix
    matches, and the URL is reported SAFE. An attacker can trivially construct
    such a URL (any hyphenated directory followed by "/../"). This is the most
    serious finding in this review.

    Recommendation: replace both regex passes with an explicit segment-stack
    resolver operating on cPath.Split('/'), which is simpler to reason about,
    has no backtracking, and handles all cases in one pass. Add unit tests using
    the canonicalization examples in Google's documentation.~~


~~V2. Path expressions are wrong for paths deeper than four segments.
File: Url.cs:324-354 (ComputePathExpressions)
Severity: HIGH. Silent fail-open on deep URLs.~~

&#x20;   ~~The spec requires, in addition to the full path, "the four paths formed by
    starting at the root and successively appending path components, INCLUDING
    A TRAILING SLASH". The loop suppresses the trailing slash on its final
    iteration (`if (cI != cEndIndex - 1)`, Url.cs:346), which is correct only
    when that final iteration happens to be the complete path. Measured:

        /a/b/c       ->  \[/] \[/a/] \[/a/b/] \[/a/b/c]      correct
        /a/b/c/d/e   ->  \[/] \[/a/] \[/a/b/] \[/a/b/c]      WRONG

    For /a/b/c/d/e the fourth entry must be "/a/b/c/". The code emits "/a/b/c"
    instead: an expression Google never hashes, while omitting the one it does.
    Any threat published against the /a/b/c/ prefix is missed.

    Fix: drop the conditional and always append "/" for prefix entries; the
    complete path is already added separately at Url.cs:330.~~


~~V3. \*\*\* 61 hash prefixes are generated per expression; v5 defines exactly one \*\*\*
File: UrlExpression.cs:55-63; consumed at
Databases/UnmanagedBrowsingDatabaseExtension.cs:314-326
Severity: HIGH (performance), MEDIUM (design debt).~~

&#x20;   ~~CreateSha256HashPrefixes emits every prefix from 4 to 64 hex characters -
    61 per expression, i.e. 2 through 32 bytes. That was correct for v4, which
    permitted variable-length prefixes. In v5 the four supported threat lists
    (se-4b, mw-4b, uws-4b, pha-4b) are ALL four-byte lists, and the database
    stores only 8-hex-character prefixes. Exactly one of the 61 can ever match;
    the other 60 are guaranteed misses.

    Cost per URL lookup, worst case:
        up to  5 host expressions x 6 path expressions = 30 expressions
        x 61 prefixes                                  = 1,830 awaited DB calls
        x 4 threat lists, each a List<string>.BinarySearch
                                                       \~ 7,300 binary searches
    Every one of those calls also traverses the proxy and resilient database
    wrappers. For the JSON database each call takes the instance lock.

    Fix: emit only the 8-character prefix (Substring(0, 8)). If variable-length
    support is wanted later, drive it from the list's HashListMetadata.HashLength
    rather than generating all lengths speculatively.

    Note this also makes the length guard at HttpBrowsingClient.cs:163
    (`prefixBytes.Length != 4`) unreachable-by-construction rather than
    unreachable-by-luck, which is a real improvement in safety.~~


~~V4. Non-BMP characters can throw during canonicalization.
File: Url.cs:395-413 (Encode)
Severity: MEDIUM.~~

&#x20;   ~~The encoder iterates `char` (UTF-16 code units) and, for any unit >= 127,
    builds a one-character string and calls Uri.EscapeDataString on it. A
    non-BMP character (emoji, many CJK extension characters) is a surrogate
    PAIR; each half is encoded separately as a lone surrogate. Uri.EscapeDataString
    on a lone surrogate does not round-trip and can throw. A URL containing an
    emoji in the host or path may throw from the Url constructor rather than
    being canonicalized.

    Fix: enumerate text elements / code points rather than chars, or UTF-8
    encode the whole string once and percent-escape byte by byte, which is what
    the spec actually describes.~~


~~V5. CacheDuration is dereferenced without a null check.
File: Clients/Http/HttpBrowsingClient.cs:182
Clients/Http/DurationConverter.cs:12-15
Severity: LOW-MEDIUM. Carried over from the previous review (was B5(a)).~~

&#x20;       ~~var convertedDateTime = DateTime.UtcNow +
            DurationConverter.SafeBrowsingDurationToTimespan(cResponseMessage.CacheDuration);

    SafeBrowsingDurationToTimespan throws ArgumentNullException on null. As
    established previously, the proto does NOT document cache\_duration as
    omittable, so this is defensive rather than a spec violation - but it is a
    proto3 message field and is therefore optional on the wire, so a null is
    structurally possible. If you keep the throw, at least make the message say
    that the server omitted a cache duration; "duration is null!" naming the
    parameter tells an operator nothing.~~


V6. A zero cache duration turns every lookup into "database stale".
    SUBSUMED BY V12 (c). The re-read exists only because the verdict is not
    taken from the response; fixing the pipeline removes this by construction.
File: Services/BaseBrowsingService.cs:162-202
Severity: MEDIUM.

&#x20;   After a full-hash lookup the service writes a safe cache entry expiring at
    SafeThreatsExpirationDate, then immediately re-reads the cache (line 182).
    If the server returned cache\_duration = 0, that expiration is "now", the
    re-read misses, and the final `else` at line 201 returns
    UrlLookupResult.DatabaseStale - even though the API answered successfully
    and the URL is safe. Callers see IsDatabaseStale rather than IsSafe.

    Fix: derive the verdict from fullHashResponse directly instead of
    round-tripping through the cache; the response already answers the question.


V7. No back-off on API failure; only client-side timeouts are retried.
File: Clients/ResilientBrowsingClient.cs:222-223
Severity: MEDIUM. v5 operational requirement.

&#x20;       var cPolicyBuilder = Policy.Handle<TimeoutException>();

    BrowsingClientException - which wraps every HTTP failure including 429 Too
    Many Requests and 5xx - is not handled, so those are not retried at all,
    and nothing reads a Retry-After header. Google's protocol requires clients
    to back off on failure; hammering the endpoint every cycle risks the API key
    being throttled. Conversely, blanket-retrying a 400 or 403 would be wrong,
    so the policy needs to discriminate on BrowsingClientException.HttpStatusCode:
    retry 408/429/500/502/503/504 with exponential back-off, fail fast otherwise.


V̶8̶.̶ m̶i̶n̶i̶m̶u̶m̶W̶a̶i̶t̶ u̶s̶e̶s̶ D̶a̶t̶e̶T̶i̶m̶e̶.̶M̶i̶n̶V̶a̶l̶u̶e̶ a̶s̶ a̶ s̶e̶n̶t̶i̶n̶e̶l̶ i̶n̶s̶t̶e̶a̶d̶ o̶f̶ n̶u̶l̶l̶.̶
F̶i̶l̶e̶:̶ C̶l̶i̶e̶n̶t̶s̶/̶H̶t̶t̶p̶/̶H̶t̶t̶p̶B̶r̶o̶w̶s̶i̶n̶g̶C̶l̶i̶e̶n̶t̶.̶c̶s̶:̶4̶1̶7̶-̶4̶2̶1̶,̶ 4̶2̶7̶
S̶e̶v̶e̶r̶i̶t̶y̶:̶ L̶O̶W̶.̶

&#x20;   ~~ThreatList.WaitToDate is DateTime? precisely because null means "no need to
    wait" (ThreatList.cs:85-90). Passing DateTime.MinValue is behaviourally
    equivalent for ThreatList.Expired, but it persists into the JSON database as
    a real timestamp instead of being omitted by DefaultValueHandling.Ignore
    (Databases/Json/ThreatListModel.cs:37-38), and it makes ThreatList.Equals
    treat two otherwise identical lists as different. It is also not UTC-stable:
    DateTime.MinValue.ToUniversalTime() yields 0001-01-01T04:57:00Z on this
    machine and something else elsewhere. Use `DateTime? minimumWait = null`.~~


V9. The full-hash filter narrows on prefix collisions, not on caller intent.
    SUBSUMED BY V12 (d), and demonstrated by a failing-on-fix test in
    Gee.External.Browsing.Tests/FullHashFilterTests.cs. Confirmed still live
    2026-09-08.
File: Clients/Http/HttpBrowsingClient.cs:201-204
Clients/BrowsingClientExtension.cs:114-133
Services/BaseBrowsingService.cs:155-157
Severity: MEDIUM. Narrow fail-open.

&#x20;   The filter added for the previous review's A7 drops any FullHashDetail whose
    list is not named in cRequest.Queries. But BaseBrowsingService builds those
    queries from databaseLookResult.ThreatLists - the lists in which the
    four-byte prefix HAPPENED TO MATCH LOCALLY - not from the lists the caller
    configured.

    Failure case: the local mw-4b list is slightly behind. A URL's prefix
    matches only se-4b locally. hashes:search correctly reports the full hash as
    MALWARE. Because mw-4b is not in Queries, the detail is dropped and the URL
    is reported safe.

    Fix: pass the caller's configured list set (BrowsingDatabaseManager's
    \_updateConstraints keys, or all synced lists) rather than the prefix-match
    set. Keeping the filter is still right - it is the source of the query set
    that is wrong.


V̶1̶0̶.̶ O̶n̶e̶ h̶a̶s̶h̶ p̶r̶e̶f̶i̶x̶ i̶s̶ s̶e̶n̶t̶ p̶e̶r̶ r̶e̶q̶u̶e̶s̶t̶;̶ t̶h̶e̶ A̶P̶I̶ a̶c̶c̶e̶p̶t̶s̶ 1̶0̶0̶0̶.̶
F̶i̶l̶e̶:̶ S̶e̶r̶v̶i̶c̶e̶s̶/̶B̶a̶s̶e̶B̶r̶o̶w̶s̶i̶n̶g̶S̶e̶r̶v̶i̶c̶e̶.̶c̶s̶:̶1̶5̶6̶
S̶e̶v̶e̶r̶i̶t̶y̶:̶ L̶O̶W̶ (̶e̶f̶f̶i̶c̶i̶e̶n̶c̶y̶)̶.̶
E̶a̶c̶h̶ l̶o̶o̶k̶u̶p̶ i̶s̶s̶u̶e̶s̶ i̶t̶s̶ o̶w̶n̶ h̶a̶s̶h̶e̶s̶:̶s̶e̶a̶r̶c̶h̶ c̶a̶l̶l̶ f̶o̶r̶ a̶ s̶i̶n̶g̶l̶e̶ p̶r̶e̶f̶i̶x̶.̶ T̶h̶e̶
g̶u̶a̶r̶d̶ a̶t̶ H̶t̶t̶p̶B̶r̶o̶w̶s̶i̶n̶g̶C̶l̶i̶e̶n̶t̶.̶c̶s̶:̶1̶7̶0̶ c̶o̶r̶r̶e̶c̶t̶l̶y̶ e̶n̶f̶o̶r̶c̶e̶s̶ t̶h̶e̶ d̶o̶c̶u̶m̶e̶n̶t̶e̶d̶ 1̶0̶0̶0̶
c̶a̶p̶,̶ s̶o̶ t̶h̶e̶ c̶l̶i̶e̶n̶t̶ s̶i̶d̶e̶ i̶s̶ r̶e̶a̶d̶y̶ f̶o̶r̶ b̶a̶t̶c̶h̶i̶n̶g̶ w̶h̶e̶n̶e̶v̶e̶r̶ t̶h̶e̶ s̶e̶r̶v̶i̶c̶e̶ l̶a̶y̶e̶r̶
w̶a̶n̶t̶s̶ t̶o̶ g̶r̶o̶u̶p̶ c̶o̶n̶c̶u̶r̶r̶e̶n̶t̶ l̶o̶o̶k̶u̶p̶s̶.̶

V̶1̶1̶.̶ s̶i̶z̶e̶C̶o̶n̶s̶t̶r̶a̶i̶n̶t̶s̶ a̶r̶e̶ a̶l̶w̶a̶y̶s̶ s̶e̶n̶t̶,̶ e̶v̶e̶n̶ w̶h̶e̶n̶ u̶n̶s̶e̶t̶.̶
F̶i̶l̶e̶:̶ C̶l̶i̶e̶n̶t̶s̶/̶H̶t̶t̶p̶/̶H̶t̶t̶p̶B̶r̶o̶w̶s̶i̶n̶g̶C̶l̶i̶e̶n̶t̶.̶c̶s̶:̶3̶7̶6̶-̶3̶7̶7̶
S̶e̶v̶e̶r̶i̶t̶y̶:̶ L̶O̶W̶.̶
W̶h̶e̶n̶ n̶o̶ q̶u̶e̶r̶y̶ c̶a̶r̶r̶i̶e̶s̶ U̶p̶d̶a̶t̶e̶C̶o̶n̶s̶t̶r̶a̶i̶n̶t̶s̶,̶ b̶o̶t̶h̶ v̶a̶l̶u̶e̶s̶ a̶r̶e̶ 0̶ a̶n̶d̶ a̶r̶e̶ s̶t̶i̶l̶l̶
a̶p̶p̶e̶n̶d̶e̶d̶.̶ T̶h̶e̶ p̶r̶o̶t̶o̶ t̶r̶e̶a̶t̶s̶ 0̶ a̶s̶ "̶n̶o̶ l̶i̶m̶i̶t̶"̶,̶ s̶o̶ t̶h̶i̶s̶ i̶s̶ h̶a̶r̶m̶l̶e̶s̶s̶,̶ b̶u̶t̶
o̶m̶i̶t̶t̶i̶n̶g̶ t̶h̶e̶ p̶a̶r̶a̶m̶e̶t̶e̶r̶s̶ e̶n̶t̶i̶r̶e̶l̶y̶ i̶s̶ c̶l̶o̶s̶e̶r̶ t̶o̶ t̶h̶e̶ d̶o̶c̶u̶m̶e̶n̶t̶e̶d̶ i̶n̶t̶e̶n̶t̶ a̶n̶d̶
k̶e̶e̶p̶s̶ t̶h̶e̶ U̶R̶L̶ s̶h̶o̶r̶t̶e̶r̶.̶ N̶o̶t̶e̶ a̶l̶s̶o̶ t̶h̶a̶t̶ i̶f̶ e̶v̶e̶r̶y̶ q̶u̶e̶r̶y̶ i̶s̶ s̶k̶i̶p̶p̶e̶d̶ b̶y̶ t̶h̶e̶
`̶u̶n̶s̶u̶p̶p̶o̶r̶t̶e̶d̶`̶ g̶u̶a̶r̶d̶ a̶t̶ l̶i̶n̶e̶ 3̶3̶4̶,̶ t̶h̶e̶ r̶e̶q̶u̶e̶s̶t̶ i̶s̶ s̶e̶n̶t̶ w̶i̶t̶h̶ s̶i̶z̶e̶C̶o̶n̶s̶t̶r̶a̶i̶n̶t̶s̶
a̶n̶d̶ n̶o̶ `̶n̶a̶m̶e̶s̶`̶ a̶t̶ a̶l̶l̶,̶ w̶h̶i̶c̶h̶ t̶h̶e̶ s̶e̶r̶v̶e̶r̶ w̶i̶l̶l̶ r̶e̶j̶e̶c̶t̶;̶ s̶h̶o̶r̶t̶-̶c̶i̶r̶c̶u̶i̶t̶ a̶n̶d̶
r̶e̶t̶u̶r̶n̶ a̶n̶ e̶m̶p̶t̶y̶ r̶e̶s̶p̶o̶n̶s̶e̶ i̶n̶s̶t̶e̶a̶d̶.̶

V12. *** THE LOOKUP PIPELINE STILL HAS v4's SHAPE ***
     File: Services/BaseBrowsingService.cs:104-205 (LookupAsync)
           Databases/UnmanagedBrowsingDatabaseExtension.cs:313-353 (LookupAsync)
           Clients/Http/HttpBrowsingClient.cs:178-212
     Severity: HIGH. Two independent silent fail-opens.
     Added 2026-09-08. SUBSUMES V6 and V9, and re-opens the premise of V10.

     v5 Local List Mode defines the check as an ordered procedure over a SET of
     hash prefixes. Quoting the published steps:

       4. "For each expressionHashPrefix of expressionHashPrefixes: Look up
          expressionHashPrefix in the local cache." If found and not expired,
          check the full hash against the cached entry and return UNSAFE on a
          match. Remove expired entries and continue.
       5. "Look up expressionHashPrefix in the local threat list database. If
          the expressionHashPrefix cannot be found in the local threat list
          database, remove it."
       6. "Send expressionHashPrefixes to the Google Safe Browsing v5 server
          using RPC SearchHashes or the REST method hashes.search." If an error
          occurred, return SAFE.
       7-9. Insert the returned full hashes into the local cache with their
          expiration times, check each full hash against the original
          expressions, and return UNSAFE on a match, otherwise SAFE.

       Source: developers.google.com/safe-browsing/reference/Local.List.Mode

     BaseBrowsingService.cs:107 opens with "First, lookup the URL in the local
     database" and consults the cache only inside the database-hit branch. That
     is the v4 ordering. Four consequences, in descending severity:

     (a) THE CACHE IS UNREACHABLE ON A DATABASE MISS. BaseBrowsingService.cs:112

             if (databaseLookResult.IsDatabaseMiss) {
                 urlLookupResult = UrlLookupResult.Safe(url, urlLookupDate);
             }

         returns SAFE without ever reading the cache, and the IsDatabaseStale
         branch below it does the same. An UNSAFE verdict cached minutes earlier
         from a confirmed hashes.search response is therefore discarded whenever
         the prefix is not in the local database right now - which is exactly
         the stale, empty, or mid-resync database the cache exists to cover.
         Ordering the cache first, per step 4, is what prevents this.

     (b) ONLY ONE PREFIX EVER SURVIVES. The specification carries a set through
         steps 4-6 and prunes it at step 5. UnmanagedBrowsingDatabaseExtension
         breaks out of both loops on the first expression that hits:

             if (cThreatLists.Count != 0) {
                 cDatabaseLookupResult = DatabaseLookupResult.DatabaseHit(...);
                 break;
             }

         A URL generates up to 30 expressions. If the first one to hit does so
         on a four-byte collision and the server confirms it safe, expressions
         2..30 are never checked - including whichever one is genuinely listed.

     (c) THE VERDICT IS READ BACK OUT OF THE CACHE. Steps 7-9 insert into the
         cache AND separately compare the returned full hashes against the
         expressions. BaseBrowsingService.cs:163-201 writes to the cache and
         then re-reads it at line 182 to decide. This is V6: a cache_duration of
         0 makes the re-read miss and yields DatabaseStale for a URL the API
         just answered for. Deriving the verdict from the response, as step 8
         describes, removes V6 by construction.

     (d) THERE IS NO FILTER-BY-LIST STEP IN THE PROCEDURE AT ALL. Step 8 is a
         full-hash equality check against the expressions. Nothing discards a
         verdict because the prefix matched a different list locally, which is
         what HttpBrowsingClient.cs:194 does today. V9 called the source of the
         query set wrong; against the published steps the filter has no
         counterpart in the hot path. If list filtering is wanted it is caller
         policy and belongs at the configured-list level.

     V9 is demonstrated by Gee.External.Browsing.Tests/FullHashFilterTests.cs.
     FindFullHashes_ServerAnswersForAnUnqueriedList_DropsTheThreat asserts the
     current behaviour: queried se-4b, server answered MALWARE, UnsafeThreats
     came back empty. That assertion inverts when this is fixed, deliberately,
     so the fix cannot land silently.

     Note on V10, which is struck through as closed: the 1000-prefix cap in
     HttpBrowsingClient is indeed ready for batching, but while (b) stands the
     service layer can never hand it more than one prefix. Restoring the prefix
     set makes step 6 batch naturally and closes V10 for real.

     Note on step 6's error handling: the specification says to return SAFE when
     the request fails. This client propagates the exception instead. Failing
     loudly is defensible for a library, but it is a divergence and should be a
     documented decision rather than an accident.

     Recommended fix: restructure BaseBrowsingService.LookupAsync to follow
     steps 4-9 directly, over the full prefix set, and reduce
     IUnmanagedBrowsingDatabase's role to step 5 - "is this prefix present" -
     rather than having it pick a single winner. This is the largest remaining
     change in the review and it closes V6, V9 and V10 together.


================================================================================
SECTION C - CORRECTNESS AND RELIABILITY
===

C1. ReleaseMutex in a finally block that may not own the mutex.
File: Databases/Json/JsonFileManager.cs:100-117, 159-171, 136-138
Severity: MEDIUM.

&#x20;   LockFile() is called INSIDE the try. If WaitOne() throws anything other than
    AbandonedMutexException (ObjectDisposedException, for instance), the finally
    still runs UnlockFile() -> ReleaseMutex() on a mutex this thread never
    acquired. Verified behaviour:

        ReleaseMutex w/o WaitOne -> ApplicationException:
          Object synchronization method was called from an unsynchronized block of code.

    That exception replaces the original one, so the real cause is lost.
    Fix: acquire before the try, or track acquisition in a bool and release only
    when set.

    (I also verified named mutexes work correctly on macOS - "Global\\..." ,
    "Local\\..." and bare names all succeed - so the Global\\ prefix is NOT a
    cross-platform problem here.)


C2. Database writes are not atomic.
File: Databases/Json/JsonFileManager.cs:163
File.WriteAllText(this.\_filePath, fileContents, Encoding.ASCII);
Severity: MEDIUM.
A crash, power loss, or disk-full condition partway through leaves a
truncated JSON file. On next start the load fails, is silently swallowed
(C3), and the client begins from an empty database - fail-open until the
first successful sync completes.
Fix: write to a sibling temp file, flush, then File.Move(temp, path, true).

C3. Three silent catch-all blocks hide operational failures.
Files: Databases/Json/BaseJsonBrowsingDatabase.cs:78-82   (database load)
Databases/Json/ManagedJsonBrowsingDatabase.cs:119-124 (file sync)
Services/BrowsingDatabaseManager.cs:\~284-286        (update fetch)
Severity: MEDIUM-HIGH for operability.

&#x20;   Each swallows every exception with no logging, no event, and no state
    change. Concretely: an invalid API key produces a 400 on every
    hashLists:batchGet, the manager returns (null, delayToDate), and the service
    retries silently every 30 minutes forever. The database never populates,
    every lookup returns safe, and nothing anywhere reports a problem.

    BrowsingDatabaseManager already exposes ThreatListSynchronizationFailed but
    only raises it for per-list failures, never for the fetch itself. Raising it
    there - and adding an equivalent signal for the JSON load/sync paths - would
    make these conditions visible without changing the retry behaviour.


C4. MemoryBrowsingCache grows without bound.
File: Cache/MemoryBrowsingCache.cs:20-25, 145-190
Severity: MEDIUM. Memory leak in exactly the scenario the library targets.

&#x20;   Both ConcurrentDictionaries are only ever added to. Expiry is evaluated on
    read (SafeCacheEntry.Expired / UnsafeCacheEntry.Expired) but no expired
    entry is ever evicted, and there is no size cap, no LRU, and no sweep. A
    long-running ManagedBrowsingService accumulates one safe-cache entry per
    distinct hash prefix looked up, forever.

    Fix: a periodic sweep task (mirroring ManagedJsonBrowsingDatabase's sync
    task), or eviction on read when found expired, plus an optional capacity
    bound.


C5. The whole database is re-serialised to disk every 60 seconds regardless of
whether anything changed.
File: Databases/Json/ManagedJsonBrowsingDatabase.cs:86-129, 35
Severity: MEDIUM (I/O, CPU, GC).

&#x20;   SyncDatabaseFileAsync unconditionally reads every threat list, materialises
    every hash prefix into a List<string>, builds ThreatListModels and
    JsonConvert.SerializeObject's the lot, once a minute. With four lists at a
    few hundred thousand prefixes each this is millions of strings serialised
    per minute for, usually, no change at all.

    Fix: set a dirty flag in StoreThreatListAsync / ModifyThreatListAsync and
    skip the write when clean. That alone removes almost all of the cost, since
    real updates arrive far less often than once a minute.


C6. Database retry back-off can stall a lookup for a minute.
File: Databases/BaseResilientBrowsingDatabase.cs:48-58
Severity: MEDIUM.
Policy.Handle<BrowsingDatabaseException>() with Math.Pow(2, attempt) seconds
over the default 5 attempts is 2+4+8+16+32 = 62 seconds of sleeping. This
policy wraps the database used on the LOOKUP path, so a caller asking "is
this URL safe?" can block for over a minute before failing. Cap the total
delay, or use a much shorter schedule for read operations.



C7. Sync-over-async in a constructor.
File: Databases/Json/BaseJsonBrowsingDatabase.cs:73-74
cStoreThreatListTask.Wait();
Severity: LOW in practice.
MemoryBrowsingDatabase returns already-completed tasks so this does not
currently deadlock, but it is a latent hazard if the in-memory database ever
becomes genuinely asynchronous, and .Wait() wraps failures in
AggregateException which the surrounding bare catch then hides.



C8. Blocking wait during Dispose.
File: Databases/Json/ManagedJsonBrowsingDatabase.cs:70
this.\_syncTask.Wait();
Severity: LOW.
Dispose blocks until the sync iteration finishes. If cancellation arrives
while a large SerializeObject/WriteAllText is in flight, Dispose blocks for
its duration. Consider a bounded Wait(timeout) so shutdown cannot hang.



C9. Read() has a write side effect.
File: Databases/Json/JsonFileManager.cs:103-105
Severity: LOW.
Read() creates the file with "{}" when missing. Surprising for a method
named Read, and it throws if the directory does not exist or is read-only -
which then surfaces as a BrowsingDatabaseException from a read.



C10. Encoding.ASCII for the database file.
File: Databases/Json/JsonFileManager.cs:104, 107, 163
Severity: LOW.
Content is hex strings and fixed enum names today, so this is safe. But
ASCII silently substitutes '?' for anything above 0x7F, so if a future
field carries non-ASCII the corruption is silent and irreversible. UTF-8
costs nothing here.

================================================================================
SECTION D - API AND DESIGN
===

D1. GetThreatListDescriptors returns Task but is not named ...Async.
File: Clients/IBrowsingClient.cs:61, Clients/Http/HttpBrowsingClient.cs:257
Its two siblings on the same interface are FindFullHashesAsync and
GetThreatListUpdatesAsync. The XML doc still says "Get Threat List
Descriptors Asynchronously". Rename to GetThreatListDescriptorsAsync;
this is a public interface, so it is cheaper to fix now than later.
(Note the implementation is also an `async` method with no `await`;
Task.FromResult is the honest form, as the remarks already promise the
operation completes synchronously.)



D2. HttpBrowsingClient mutates process-global Flurl state and leaks the API key.
File: Clients/Http/HttpBrowsingClient.cs:87-104
Severity: MEDIUM (credential exposure).
FlurlHttp.Configure sets global settings, and the BeforeCall closure appends
the Safe Browsing API key to EVERY Flurl request made anywhere in the host
process - including calls that have nothing to do with Safe Browsing, i.e.
the key is sent to unrelated third-party hosts. Constructing two clients
also means the last one wins for both.
Fix: a per-instance IFlurlClient. Flurl 4.x makes this straightforward; on
2.4.2 it is still possible via FlurlClient with its own Settings.



D3. Dispose() releases nothing.
File: Clients/Http/HttpBrowsingClient.cs:110-114
It only flips \_disposed. The global configuration and the captured key
outlive the object. Follows from D2.



D4. isEncoded:true on the API key query parameter.
File: Clients/Http/HttpBrowsingClient.cs:103
Tells Flurl the value is already URL-encoded and passes it through verbatim.
Google keys are \[A-Za-z0-9\_-] so this is safe today, but it will silently
corrupt any key containing a reserved character.



D5. Decode failures escape as the wrong exception type.
File: Clients/Http/HttpBrowsingClient.cs:222-234, 468-476
Both methods document BrowsingClientException as the failure mode and
callers (BaseBrowsingService, BrowsingDatabaseManager) catch accordingly.
But InvalidProtocolBufferException (malformed or non-protobuf body - e.g. a
captive portal or proxy returning HTML), FormatException (the hex
validators), and InvalidDataException / EndOfStreamException (the Rice
decoder) all propagate unwrapped past both catch blocks.
Fix: add a catch for these and wrap them in BrowsingClientException.



D6. 344 nullable warnings after enabling <Nullable>enable</Nullable>.
140 of them are CS8618 on DTO classes, a large share of which live in the
dead v4 model layer (E1). Deleting E1 first and re-measuring will make the
remaining set tractable. Worth doing before hand-annotating anything.
Note the analyser did NOT catch V5 - DurationConverter's parameter is
unannotated, so annotating that file is a cheap, high-value first step.



D7. ThreatType is public but nothing public consumes it.
Files: ThreatType.cs, ThreatConverter.cs:58-75
After B8, StringToThreatType has no live callers and the enum is used only
by the dead Clients/Http/ThreatTypeExtension.cs. Delete both with E1, or
keep the enum deliberately as public surface and document it.



D8. Duplicate conversion helpers with overlapping responsibilities.
ThreatConverter.StringToThreatListName / ThreatListNameToUrlQueryString
vs ThreatListNameExtension.AsThreatListName / AsThreatListNameModel
- two producers and two parsers for the same four names.
DurationConverter.SafeBrowsingDurationToTimespan
vs DurationExtension.AsTimeSpan - the former is a thin wrapper over the
latter that only adds a null check.
They agree today; two copies is how they stop agreeing. Collapse each pair.
DurationExtension.AsTimeSpan's XML doc is still wrong, incidentally - it
promises "a null reference if @this is a null reference", which is
impossible for a TimeSpan return.



D̶9̶.̶ P̶u̶b̶l̶i̶c̶ T̶h̶r̶e̶a̶t̶L̶i̶s̶t̶N̶a̶m̶e̶ e̶n̶u̶m̶ h̶a̶s̶ a̶ n̶u̶m̶b̶e̶r̶i̶n̶g̶ g̶a̶p̶ (̶p̶h̶a̶\_̶4̶b̶ =̶ 5̶)̶.̶
F̶i̶l̶e̶:̶ T̶h̶r̶e̶a̶t̶L̶i̶s̶t̶N̶a̶m̶e̶.̶c̶s̶:̶3̶2̶
D̶o̶ N̶O̶T̶ r̶e̶n̶u̶m̶b̶e̶r̶:̶ D̶a̶t̶a̶b̶a̶s̶e̶s̶/̶J̶s̶o̶n̶/̶T̶h̶r̶e̶a̶t̶L̶i̶s̶t̶M̶o̶d̶e̶l̶.̶c̶s̶:̶3̶2̶-̶3̶3̶ p̶e̶r̶s̶i̶s̶t̶s̶ t̶h̶i̶s̶ e̶n̶u̶m̶
a̶n̶d̶ N̶e̶w̶t̶o̶n̶s̶o̶f̶t̶ w̶r̶i̶t̶e̶s̶ i̶t̶ a̶s̶ a̶n̶ i̶n̶t̶e̶g̶e̶r̶,̶ s̶o̶ c̶h̶a̶n̶g̶i̶n̶g̶ 5̶ t̶o̶ 4̶ s̶i̶l̶e̶n̶t̶l̶y̶ r̶e̶m̶a̶p̶s̶
e̶v̶e̶r̶y̶ s̶t̶o̶r̶e̶d̶ P̶H̶A̶ l̶i̶s̶t̶ i̶n̶ e̶x̶i̶s̶t̶i̶n̶g̶ d̶a̶t̶a̶b̶a̶s̶e̶ f̶i̶l̶e̶s̶.̶ I̶f̶ y̶o̶u̶ w̶a̶n̶t̶ t̶h̶e̶ g̶a̶p̶ g̶o̶n̶e̶,̶
f̶i̶r̶s̶t̶ a̶d̶d̶ \[̶J̶s̶o̶n̶C̶o̶n̶v̶e̶r̶t̶e̶r̶(̶t̶y̶p̶e̶o̶f̶(̶S̶t̶r̶i̶n̶g̶E̶n̶u̶m̶C̶o̶n̶v̶e̶r̶t̶e̶r̶)̶)̶]̶ t̶o̶ t̶h̶a̶t̶ p̶r̶o̶p̶e̶r̶t̶y̶ s̶o̶
t̶h̶e̶ n̶u̶m̶b̶e̶r̶s̶ s̶t̶o̶p̶ b̶e̶i̶n̶g̶ l̶o̶a̶d̶-̶b̶e̶a̶r̶i̶n̶g̶ o̶n̶ d̶i̶s̶k̶.̶

================================================================================
~~SECTION E - DEAD CODE AND BUILD HYGIENE~~
===

~~E1. The entire v4 JSON model layer is orphaned - 30 files.
Verified: none of the following is referenced from anywhere outside
Clients/Http/, and within that directory they reference only each other.
HttpBrowsingClient does not touch any of them.~~

&#x20;     ~~CompressionTypeExtension          ThreatListUpdateChecksumModel
      FullHashQueryModel                ThreatListUpdateConstraintsExtension
      FullHashRequestExtension          ThreatListUpdateConstraintsModel
      FullHashRequestModel              ThreatListUpdateHashModel
      FullHashResponseModel             ThreatListUpdateIndexModel
      FullHashResponseModelExtension    ThreatListUpdateQueryExtension
      ThreatEntryMetadataEntryModel     ThreatListUpdateQueryModel
      ThreatEntryMetadataModel          ThreatListUpdateRequestExtension
      ThreatEntryModel                  ThreatListUpdateRequestModel
      ThreatEntrySetModel               ThreatListUpdateResponseModel
      ThreatListDescriptorModel         ThreatListUpdateResponseModelExtension
      ThreatListDescriptorModelExtension ThreatListUpdateResultModel
      ThreatListDescriptorResponseModel ThreatListUpdateResultModelExtension
      ThreatTypeExtension               ThreatListUpdateTypeExtension
      UnsafeThreatModel                 UnsafeThreatModelExtension

    Plus Clients/CompressionType.cs, which exists only to serve them.
    Several still encode v4 concepts that do not exist in v5 (PlatformTypes,
    ThreatEntryTypes in FullHashRequestExtension.cs:52-54).
    Deleting these removes a large share of the D6 nullable warnings for free
    and is the single cheapest cleanup available.~~


~~E2. Eight unused using directives in HttpBrowsingClient.cs.
Lines 4, 15, 16, 17, 18, 19, 20, 21: Flurl.Util, Newtonsoft.Json.Linq,
Polly, System.Buffers.Binary, System.Text, System.Net.NetworkInformation,
Gee.External.Browsing.Services, Google.Protobuf.WellKnownTypes.
Zero references to any of them remain. System.Net.NetworkInformation and
Gee.External.Browsing.Services in particular look like accidental IDE
auto-imports and imply dependencies the file does not have.~~



~~E3. Stray using in DurationConverter.cs:4
using Microsoft.VisualBasic;
Compiles only because that assembly ships in the .NET 10 shared framework.
Almost certainly an accidental auto-import.~~



E4. DurationConverter duplicates DurationExtension - see D8.



E5. ThreatConverter's class-level XML remark is stale.
File: ThreatConverter.cs:8-11
"Converts v4 Style ThreatTypes to v5 threat list names" no longer describes
the class after B8; also "consistant" -> "consistent". The summary on
ThreatTypeToThreatListName (lines 14-23) documents a string parameter the
method no longer takes.



E6. TODO left in place.
File: Databases/Json/BaseJsonBrowsingDatabase.cs:61-63
var cThreatType = cThreatListModel.ThreatListName;
.SetDescriptor(cThreatType) // TODO: rename from cThreatType



E7. Gee.External.Browsing.xml is still tracked and still regenerating.
Verified: `git check-ignore` reports NOT ignored, and the file is still in
the index. .gitignore was modified but does not cover it. Every Debug build
rewrites it, producing \~2,500 lines of diff noise per commit.
Fix: `git rm --cached Gee.External.Browsing.xml`, add it to .gitignore, and
replace the six <DocumentationFile> entries (csproj lines 12, 19, 26, 34,
39, 46) with a single <GenerateDocumentationFile>true</GenerateDocumentationFile>
in the main PropertyGroup so it is emitted into bin/ instead of the project
root.



E8. Flurl.Http 2.4.2 is the oldest dependency and blocks D2/D3.
Its global-static configuration model is why the API key leaks. Flurl 4.x
has per-instance FlurlClient. The upgrade is breaking for this file
(HttpCall, DefaultHttpClientFactory, cEx.Call.HttpStatus at lines 231 and
473 all change shape), so do it as its own commit.



~~E9. No tests exist anywhere in the repository.
Given V1 and V2 are canonicalization bugs that produce silently wrong
hashes, and V3 is a spec-shape mismatch, the highest-value test suite is a
table-driven canonicalization test using the worked examples from Google's
documentation, plus one end-to-end assertion that a known-bad URL
(https://testsafebrowsing.appspot.com/phishing.html) returns IsUnsafe. A
fail-open regression currently cannot be detected by anything.~~

================================================================================
SUGGESTED ORDER OF WORK
===

1. ~~V1 - fix path canonicalization (segment-stack resolver). Highest security
value; it is an exploitable bypass today.~~
2. ~~V2 - always append the trailing slash on path prefixes.~~
3. ~~E9 - add canonicalization tests from Google's documented examples, so 1 and
2 stay fixed.~~
4. ~~V3 - emit only the 4-byte prefix. Large performance win, removes \~1,800
wasted database round-trips per lookup.~~
5. ~~E1 - delete the 30 orphaned v4 files; re-measure D6 afterwards.~~
6. V9 - source the full-hash filter from configured lists, not prefix matches.
7. C3 - surface the three swallowed exception paths through the existing
ThreatListSynchronizationFailed event.
8. C1, C2 - mutex acquisition ordering and atomic file replace.
9. C4, C5 - cache eviction and dirty-flag-driven persistence.
10. V6, V7 - lookup verdict without the cache round-trip; retry policy that
discriminates on HTTP status.
11. D2/D3 + E8 - per-instance Flurl client, real Dispose, Flurl upgrade.
12. E2, E3, E5, E6, E7, D1, D8 - cleanup pass.

================================================================================
END OF REPORT
===

