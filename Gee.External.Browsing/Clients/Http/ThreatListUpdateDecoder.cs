using System;
using System.IO;
using SafeBrowsing.V5;

namespace Gee.External.Browsing.Clients.Http {
    /// <summary>
    ///     Golomb-Rice Decoder.
    /// </summary>
    /// <remarks>
    ///     Decodes the <see cref="RiceDeltaEncoded32Bit" /> data the Google Safe Browsing API returns in a
    ///     <see cref="HashList" />, both for the four byte SHA256 hash prefixes a client should add to its locally
    ///     stored copy of a threat list and for the indices of the threats a client should remove from it.
    ///
    ///     The encoded data is a stream of bits that is read one byte at a time, least significant bit first. Each
    ///     entry is encoded as a quotient, in unary and terminated by a zero bit, followed by a remainder in
    ///     <see cref="RiceDeltaEncoded32Bit.RiceParameter" /> bits, also read least significant bit first. An entry
    ///     is <c>(quotient &lt;&lt; riceParameter) + remainder</c> and is the difference between the value it
    ///     encodes and the value preceding it, so the values are recovered by accumulating the differences starting
    ///     from <see cref="RiceDeltaEncoded32Bit.FirstValue" />. The first value is never itself encoded in the
    ///     encoded data, which is why a message encoding N values has an
    ///     <see cref="RiceDeltaEncoded32Bit.EntriesCount" /> of N - 1.
    ///
    ///     Unlike V4, V5 treats the decoded values as big-endian, so a decoded value is serialized to a SHA256 hash
    ///     prefix most significant byte first. Lexicographically sorting the hash prefixes is therefore equivalent
    ///     to numerically sorting the decoded values and a client does not need to sort them itself.
    /// </remarks>
    public static class GolombRiceDecoder32Bit {
        /// <summary>
        ///     Maximum Rice Parameter.
        /// </summary>
        /// <remarks>
        ///     The Google Safe Browsing API guarantees the Rice parameter of a <see cref="RiceDeltaEncoded32Bit" />
        ///     is between <see cref="MinimumRiceParameter" /> and <see cref="MaximumRiceParameter" />, inclusive.
        /// </remarks>
        public const int MaximumRiceParameter = 30;

        /// <summary>
        ///     Minimum Rice Parameter.
        /// </summary>
        /// <remarks>
        ///     The Google Safe Browsing API guarantees the Rice parameter of a <see cref="RiceDeltaEncoded32Bit" />
        ///     is between <see cref="MinimumRiceParameter" /> and <see cref="MaximumRiceParameter" />, inclusive.
        /// </remarks>
        public const int MinimumRiceParameter = 3;

        /// <summary>
        ///     Decode Rice-Delta Encoded Data.
        /// </summary>
        /// <param name="riceDelta">
        ///     A <see cref="RiceDeltaEncoded32Bit" /> to decode. A message that is omitted by the Google Safe
        ///     Browsing API, and is consequently a null reference, indicates there is nothing to decode and must not
        ///     be passed. A message that is present but has an <see cref="RiceDeltaEncoded32Bit.EntriesCount" /> of
        ///     zero encodes exactly one value, <see cref="RiceDeltaEncoded32Bit.FirstValue" />.
        /// </param>
        /// <returns>
        ///     The decoded values, in ascending order. When the message encodes removals, the values are the
        ///     zero-based indices of the threats to remove from the lexicographically sorted threat list. When it
        ///     encodes additions, the values are the four byte SHA256 hash prefixes to add, which you can serialize
        ///     with <see cref="DecodeHashPrefixes" /> instead.
        /// </returns>
        /// <exception cref="System.ArgumentException">
        ///     Thrown if <paramref name="riceDelta" /> has a negative entries count, or has a Rice parameter that is
        ///     not between <see cref="MinimumRiceParameter" /> and <see cref="MaximumRiceParameter" />, inclusive.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="riceDelta" /> is a null reference.
        /// </exception>
        /// <exception cref="System.IO.EndOfStreamException">
        ///     Thrown if the encoded data is exhausted before the indicated number of entries is decoded.
        /// </exception>
        /// <exception cref="System.IO.InvalidDataException">
        ///     Thrown if the encoded data is malformed.
        /// </exception>
        public static uint[] Decode(RiceDeltaEncoded32Bit riceDelta) {
            if (riceDelta is null) {
                throw new ArgumentNullException(nameof(riceDelta), "parameter is null");
            }

            if (riceDelta.EntriesCount < 0) {
                var detailMessage = $"An entries count ({riceDelta.EntriesCount}) is invalid (must not be negative).";
                throw new ArgumentException(detailMessage, nameof(riceDelta));
            }

            // ...
            //
            // The first value is not encoded in the encoded data, so a message encoding N values has an entries
            // count of N - 1. If it encodes a single value, the encoded data is empty and the Rice parameter is
            // meaningless, so we deliberately don't validate it.
            var values = new uint[riceDelta.EntriesCount + 1];
            values[0] = riceDelta.FirstValue;
            if (riceDelta.EntriesCount == 0) {
                return values;
            }

            var riceDecoder = new RiceDecoder32Bit(riceDelta.EncodedData.ToByteArray(), riceDelta.RiceParameter);
            var value = values[0];
            for (var i = 1; i < values.Length; i += 1) {
                // ...
                //
                // The decoded values are ascending 32-bit values, so an entry that takes the running value beyond
                // the range of a 32-bit value indicates the encoded data is malformed.
                var delta = riceDecoder.ReadValue();
                if (delta > uint.MaxValue - value) {
                    const string cDetailMessage = "Rice encoded data is malformed (a decoded value overflowed).";
                    throw new InvalidDataException(cDetailMessage);
                }

                value += delta;
                values[i] = value;
            }

            // ...
            //
            // The encoded data is padded to a byte boundary, so there should be fewer than 8 bits left over once
            // every entry is decoded. Anything more indicates we decoded fewer entries than the data holds.
            if (riceDecoder.BitReader.BitsRemaining() >= 8) {
                const string detailMessage = "Rice encoded data is malformed (it was not fully consumed).";
                throw new InvalidDataException(detailMessage);
            }

            return values;
        }

        /// <summary>
        ///     Decode Rice-Delta Encoded SHA256 Hash Prefixes.
        /// </summary>
        /// <param name="riceDelta">
        ///     A <see cref="RiceDeltaEncoded32Bit" /> encoding four byte SHA256 hash prefixes to decode. A message
        ///     that is omitted by the Google Safe Browsing API, and is consequently a null reference, indicates
        ///     there are no hash prefixes to decode and must not be passed.
        /// </param>
        /// <returns>
        ///     The four byte SHA256 hash prefixes, in lexicographical order. Each hash prefix is a decoded value
        ///     serialized most significant byte first, which is the byte order the Google Safe Browsing API's
        ///     threats are identified by.
        /// </returns>
        /// <exception cref="System.ArgumentException">
        ///     Thrown if <paramref name="riceDelta" /> has a negative entries count, or has a Rice parameter that is
        ///     not between <see cref="MinimumRiceParameter" /> and <see cref="MaximumRiceParameter" />, inclusive.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="riceDelta" /> is a null reference.
        /// </exception>
        /// <exception cref="System.IO.EndOfStreamException">
        ///     Thrown if the encoded data is exhausted before the indicated number of entries is decoded.
        /// </exception>
        /// <exception cref="System.IO.InvalidDataException">
        ///     Thrown if the encoded data is malformed.
        /// </exception>
        public static byte[][] DecodeHashPrefixes(RiceDeltaEncoded32Bit riceDelta) {
            var values = GolombRiceDecoder32Bit.Decode(riceDelta);
            var sha256HashPrefixes = new byte[values.Length][];
            for (var i = 0; i < values.Length; i += 1) {
                // ...
                //
                // Serialize most significant byte first. We deliberately don't use BitConverter here, since it
                // serializes in the byte order of the host and would only be correct on a little-endian host.
                var value = values[i];
                sha256HashPrefixes[i] = new[] {
                    (byte) (value >> 24),
                    (byte) (value >> 16),
                    (byte) (value >> 8),
                    (byte) value
                };
            }

            return sha256HashPrefixes;
        }
    }

    /// <summary>
    ///     Bit Reader.
    /// </summary>
    /// <remarks>
    ///     Reads a Rice-delta encoded stream of bits one byte at a time, least significant bit first.
    /// </remarks>
    public sealed class BitReader32Bit {
        /// <summary>
        ///     Buffer.
        /// </summary>
        private readonly byte[] _buffer;

        /// <summary>
        ///     Index of the Next Bit to Read in the Current Byte.
        /// </summary>
        private int _bitIndex;

        /// <summary>
        ///     Index of the Byte Currently Being Read.
        /// </summary>
        private int _byteIndex;

        /// <summary>
        ///     Create a Bit Reader.
        /// </summary>
        /// <param name="buffer">
        ///     The Rice-delta encoded data to read.
        /// </param>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="buffer" /> is a null reference.
        /// </exception>
        public BitReader32Bit(byte[] buffer) {
            if (buffer is null) {
                throw new ArgumentNullException(nameof(buffer), "parameter is null");
            }

            this._bitIndex = 0;
            this._buffer = buffer;
            this._byteIndex = 0;
        }

        /// <summary>
        ///     Get the Number of Bits Remaining.
        /// </summary>
        /// <returns>
        ///     The number of bits that have not been read yet.
        /// </returns>
        public int BitsRemaining() {
            return (this._buffer.Length - this._byteIndex) * 8 - this._bitIndex;
        }

        /// <summary>
        ///     Read Bits.
        /// </summary>
        /// <param name="n">
        ///     The number of bits to read, between 0 and 32, inclusive.
        /// </param>
        /// <returns>
        ///     The bits that were read. The first bit that was read is the least significant bit of the value.
        /// </returns>
        /// <exception cref="System.ArgumentException">
        ///     Thrown if <paramref name="n" /> is not between 0 and 32, inclusive.
        /// </exception>
        /// <exception cref="System.IO.EndOfStreamException">
        ///     Thrown if there are fewer than <paramref name="n" /> bits remaining.
        /// </exception>
        public uint ReadBits(int n) {
            if (n < 0 || n > 32) {
                const string detailMessage = "An invalid number of bits was passed to the bit reader.";
                throw new ArgumentException(detailMessage, nameof(n));
            }

            uint v = 0;
            for (var i = 0; i < n; i += 1) {
                if (this._byteIndex >= this._buffer.Length) {
                    const string cDetailMessage = "Rice encoded data is exhausted.";
                    throw new EndOfStreamException(cDetailMessage);
                }

                var bit = (uint) ((this._buffer[this._byteIndex] >> this._bitIndex) & 1);
                v |= bit << i;

                this._bitIndex += 1;
                if (this._bitIndex == 8) {
                    this._bitIndex = 0;
                    this._byteIndex += 1;
                }
            }

            return v;
        }
    }

    /// <summary>
    ///     Rice Decoder.
    /// </summary>
    /// <remarks>
    ///     Reads the entries a Rice-delta encoded stream of bits holds. Each entry is the difference between the
    ///     value it encodes and the value preceding it, not the value itself.
    /// </remarks>
    public sealed class RiceDecoder32Bit {
        /// <summary>
        ///     Maximum Quotient.
        /// </summary>
        /// <remarks>
        ///     A quotient beyond this shifts an entry beyond the range of a 32-bit value, so it indicates the
        ///     encoded data is malformed. Bounding it also stops a run of one bits from being read indefinitely.
        /// </remarks>
        private readonly uint _maximumQuotient;

        /// <summary>
        ///     Get Bit Reader.
        /// </summary>
        public BitReader32Bit BitReader { get; }

        /// <summary>
        ///     Get Rice Parameter.
        /// </summary>
        public int RiceParameter { get; }

        /// <summary>
        ///     Create a Rice Decoder.
        /// </summary>
        /// <param name="encodedData">
        ///     The Rice-delta encoded data to read.
        /// </param>
        /// <param name="riceParameter">
        ///     The Golomb-Rice parameter the data was encoded with, between
        ///     <see cref="GolombRiceDecoder32Bit.MinimumRiceParameter" /> and
        ///     <see cref="GolombRiceDecoder32Bit.MaximumRiceParameter" />, inclusive.
        /// </param>
        /// <exception cref="System.ArgumentException">
        ///     Thrown if <paramref name="riceParameter" /> is not between
        ///     <see cref="GolombRiceDecoder32Bit.MinimumRiceParameter" /> and
        ///     <see cref="GolombRiceDecoder32Bit.MaximumRiceParameter" />, inclusive.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        ///     Thrown if <paramref name="encodedData" /> is a null reference.
        /// </exception>
        public RiceDecoder32Bit(byte[] encodedData, int riceParameter) {
            var isRiceParameterValid = riceParameter >= GolombRiceDecoder32Bit.MinimumRiceParameter &&
                                       riceParameter <= GolombRiceDecoder32Bit.MaximumRiceParameter;
            if (!isRiceParameterValid) {
                var detailMessage = $"A Rice parameter ({riceParameter}) is invalid (must be between " +
                                    $"{GolombRiceDecoder32Bit.MinimumRiceParameter} and " +
                                    $"{GolombRiceDecoder32Bit.MaximumRiceParameter}).";

                throw new ArgumentException(detailMessage, nameof(riceParameter));
            }

            this.BitReader = new BitReader32Bit(encodedData);
            this.RiceParameter = riceParameter;
            this._maximumQuotient = (1U << (32 - riceParameter)) - 1;
        }

        /// <summary>
        ///     Read an Entry.
        /// </summary>
        /// <returns>
        ///     The entry that was read, which is the difference between the value it encodes and the value
        ///     preceding it.
        /// </returns>
        /// <exception cref="System.IO.EndOfStreamException">
        ///     Thrown if the encoded data is exhausted before the entry is read.
        /// </exception>
        /// <exception cref="System.IO.InvalidDataException">
        ///     Thrown if the entry does not fit in a 32-bit value.
        /// </exception>
        public uint ReadValue() {
            // ...
            //
            // The quotient is unary encoded as a run of one bits terminated by a zero bit.
            uint q = 0;
            while (this.BitReader.ReadBits(1) == 1) {
                q += 1;
                if (q > this._maximumQuotient) {
                    const string cDetailMessage = "Rice encoded data is malformed (a quotient is too large).";
                    throw new InvalidDataException(cDetailMessage);
                }
            }

            var r = this.BitReader.ReadBits(this.RiceParameter);
            return (q << this.RiceParameter) + r;
        }
    }
}
