// -----------------------------------------------------------------------------
// (c) balarabe@protonmail.com                                      License: MIT
// :v: 2019-05-11 04:38:16 BBC65A                             zr-whirl/[hash.go]
// -----------------------------------------------------------------------------

package whirl

// # Contents:
//
// # Public Functions
//   HashOfBytes(ar []byte, salt []byte) []byte
//   HashOfString(s string, salt []byte) []byte
//   Sum512(data []byte) [cDigestBytes]byte
//
// # Hash Structure and Methods
//   Hash struct
//   New() Hash
//   (ob *Hash) Write(data []byte) (n int, err error)
//
// # Internal Functions
//   appendBytes(source []byte, sourceBits uint64, ob *Hash)
//   finalize(ob *Hash, result []byte)
//   processBuffer(ob *Hash)
//
// -----------------------------------------------------------------------------
// This Go language implementation was made by balarabe@protonmail.com
// based on original public domain C source code. See details below.
//
// Summary of changes from the reference C implementation:
// - Added a Go-friendly interface: e.g. Sum512(), New(), Write()
// - A standard Go test loop is used for ISO tests
// - 'go vet' runs without warnings
// - 'golint' utility passes without warnings
// - Added printStruct() function to dump Hash contents
// - Renamed 'NESSIEstruct' to 'Hash', etc.
// - Reduced source width to 80-columns
//
// -----------------------------------------------------------------------------
// The Whirlpool hashing function.
//
// <p>
// <b>References</b>
//
// <p>
// The Whirlpool algorithm was developed by
// <a href="mailto:pbarreto@scopus.com.br">Paulo S. L. M. Barreto</a> and
// <a href="mailto:vincent.rijmen@cryptomathic.com">Vincent Rijmen</a>.
//
// See
//      P.S.L.M. Barreto, V. Rijmen,
//      ''The Whirlpool hashing function,''
//      NESSIE submission, 2000 (tweaked version, 2001),
/*
https://www.cosic.esat.kuleuven.ac.be/nessie/workshop/submissions/whirlpool.zip
*/
//
// @author  Paulo S.L.M. Barreto
// @author  Vincent Rijmen.
//
// @version 3.0 (2003.03.12)
//
// -----------------------------------------------------------------------------
// Differences from version 2.1:
// - Suboptimal diffusion matrix replaced by cir(1, 1, 4, 1, 8, 5, 2, 9).
//
// -----------------------------------------------------------------------------
// Differences from version 2.0:
// - Generation of ISO/IEC 10118-3 test vectors.
// - Bug fix: nonzero carry was ignored when tallying the data length
//      (this bug apparently only manifested itself when feeding data
//      in pieces rather than in a single chunk at once).
// - Support for MS Visual C++ 64-bit integer arithmetic.
//
// Differences from version 1.0:
// - Original S-box replaced by the tweaked, hardware-efficient version.
//
// -----------------------------------------------------------------------------
// THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
// BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import (
	"fmt"

	"github.com/balacode/zr"
)

// -----------------------------------------------------------------------------
// # Public Functions

// HashOfBytes returns the Whirlpool hash of a byte slice.
// It also requires a 'salt' argument.
func HashOfBytes(ar []byte, salt []byte) []byte {
	var input []byte
	input = append(input, salt[:]...)
	input = append(input, ar...)
	hash := Sum512(input)
	return hash[:]
} //                                                                 HashOfBytes

// HashOfString returns the Whirlpool hash of a string.
// It also requires a 'salt' argument.
func HashOfString(s string, salt []byte) []byte {
	var input []byte
	input = append(input, salt[:]...)
	input = append(input, []byte(s)...)
	hash := Sum512(input)
	return hash[:]
} //                                                                HashOfString

// Sum512 __
func Sum512(data []byte) [cDigestBytes]byte {
	hash := New()
	appendBytes(data, uint64(8*len(data)), &hash)
	var digest [cDigestBytes]byte
	finalize(&hash, digest[:])
	return digest
} //                                                                      Sum512

// -----------------------------------------------------------------------------
// # Hash Structure and Methods

// Hash __
type Hash struct {
	// global number of hashed bits (256-bit counter)
	bitLength [cLengthBytes]byte
	// buffer of data to hash
	buffer [cWBlockBytes]byte
	// current number of bits on the buffer
	bufferBits int
	// current (possibly incomplete) byte slot on the buffer
	bufferPos int
	// the hashing state
	hash [cDigestBytes / 8]uint64
} //                                                                        Hash

// -----------------------------------------------------------------------------
// # Public Methods

// New initialize the hashing state.
// (Same as the original implementation's NESSIEinit() function.)
func New() Hash {
	var ret Hash
	// it's only necessary to cleanup buffer[bufferPos]
	if cTraceIntermediateValues {
		fmt.Printf("Initial hash value:\r\n")
		for i := 0; i < cDigestBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
				byte(ret.hash[i]>>56),
				byte(ret.hash[i]>>48),
				byte(ret.hash[i]>>40),
				byte(ret.hash[i]>>32),
				byte(ret.hash[i]>>24),
				byte(ret.hash[i]>>16),
				byte(ret.hash[i]>>8),
				byte(ret.hash[i]))
		}
		fmt.Printf("\r\n")
	}
	return ret
} //                                                                         New

// Write __
func (ob *Hash) Write(data []byte) (n int, err error) {
	if ob == nil {
		return 0, zr.Error(zr.ENilReceiver)
	}
	appendBytes(data, uint64(8*len(data)), ob)
	return len(data), nil
} //                                                                       Write

// -----------------------------------------------------------------------------
// # Internal Functions

// appendBytes delivers input data to the hashing algorithm.
//
// @param    source        plaintext data to hash.
// @param    sourceBits    how many bits of plaintext to process.
//
// This method maintains the invariant: bufferBits < cDigestBits
func appendBytes(source []byte, sourceBits uint64, ob *Hash) {
	var (
		//                    sourcePos
		//                    |
		//                    +-------+-------+-------
		//                       ||||||||||||||||||||| source
		//                    +-------+-------+-------
		// +-------+-------+-------+-------+-------+-------
		// ||||||||||||||||||||||                           buffer
		// +-------+-------+-------+-------+-------+-------
		//                 |
		//                 bufferPos
		// index of leftmost source byte containing data (1 to 8 bits).
		sourcePos = 0
		//
		// space on source[sourcePos].
		sourceGap = (8 - int(sourceBits)&7) & 7
		//
		// occupied bits on buffer[bufferPos].
		bufferRem  = ob.bufferBits & 7
		buffer     = ob.buffer[:]
		bitLength  = &ob.bitLength
		bufferBits = ob.bufferBits
		bufferPos  = ob.bufferPos
		b          uint32
	)
	// tally the length of the added data:
	{
		carry := uint32(0)
		val := uint64(sourceBits)
		for i := 31; i >= 0 && (carry != 0 || val != 0); i-- {
			carry += uint32(bitLength[i]) + (uint32(val) & 0xff)
			bitLength[i] = byte(carry)
			carry >>= 8
			val >>= 8
		}
	}
	// process data in chunks of 8 bits
	// (a more efficient approach would be to take whole-word chunks):
	for sourceBits > 8 {
		// N.B. at least source[sourcePos] and source[sourcePos+1] contain data
		// take a byte from the source:
		b = uint32((source[sourcePos]<<uint32(sourceGap))&0xff) |
			uint32((source[sourcePos+1]&0xff)>>uint32(8-sourceGap))
		// process this byte:
		buffer[bufferPos] |= byte(b >> uint32(bufferRem))
		bufferPos++
		bufferBits += 8 - bufferRem // bufferBits = 8*bufferPos
		if bufferBits == cDigestBits {
			// process data block:
			processBuffer(ob)
			// reset buffer:
			bufferBits = 0
			bufferPos = 0
		}
		buffer[bufferPos] = byte(b << uint32(8-bufferRem))
		bufferBits += bufferRem
		// proceed to remaining data:
		sourceBits -= 8
		sourcePos++
	}
	// now 0 <= sourceBits <= 8
	// furthermore, all data (if any is left) is in source[sourcePos].
	if sourceBits > 0 {
		b = uint32(source[sourcePos]<<uint32(sourceGap)) & 0xff
		// bits are left-justified on b.
		// process the remaining bits:
		buffer[bufferPos] |= byte(b) >> uint32(bufferRem)
	} else {
		b = 0
	}
	if uint64(bufferRem)+sourceBits < 8 {
		// all remaining data fits on buffer[bufferPos],
		// and there still remains some space.
		bufferBits += int(sourceBits)
	} else {
		// buffer[bufferPos] is full:
		bufferPos++
		bufferBits += 8 - bufferRem // bufferBits = 8*bufferPos
		sourceBits -= uint64(8 - bufferRem)
		// now 0 <= sourceBits < 8
		// furthermore, all data (if any is left) is in source[sourcePos].
		if bufferBits == cDigestBits {
			// process data block:
			processBuffer(ob)
			// reset buffer:
			bufferBits = 0
			bufferPos = 0
		}
		buffer[bufferPos] = byte(b << uint32(8-bufferRem))
		bufferBits += int(sourceBits)
	}
	ob.bufferBits = bufferBits
	ob.bufferPos = bufferPos
} //                                                                 appendBytes

// finalize gets the hash value from the hashing state.
// This method uses the invariant: bufferBits < cDigestBits
func finalize(ob *Hash, result []byte) {
	if ob == nil {
		zr.Error(zr.ENilReceiver)
		return
	}
	var (
		buffer     = ob.buffer[:]
		bufferBits = ob.bufferBits
		bufferPos  = ob.bufferPos
		digest     = result
	)
	// append a '1'-bit:
	buffer[bufferPos] |= 0x80 >> uint32(bufferBits&7)
	bufferPos++ // all remaining bits on the current byte are set to zero.
	// pad with zero bits to complete (N*cWBlockBits - cLengthBits) bits:
	if bufferPos > cWBlockBytes-cLengthBytes {
		if bufferPos < cWBlockBytes {
			for i := bufferPos; i < cWBlockBytes; i++ {
				buffer[i] = 0
			}
		}
		processBuffer(ob) // process data block
		bufferPos = 0     // reset buffer
	}
	if bufferPos < cWBlockBytes-cLengthBytes {
		for i := bufferPos; i < cWBlockBytes-cLengthBytes; i++ {
			buffer[i] = 0
		}
	}
	bufferPos = cWBlockBytes - cLengthBytes
	// append bit length of hashed data
	bitLength := ob.bitLength[:]
	copy(buffer[cWBlockBytes-cLengthBytes:], bitLength[:cLengthBytes])
	//
	// process data block
	processBuffer(ob)
	//
	// return the completed message digest:
	for i, b := 0, 0; i < cDigestBytes/8; i++ {
		digest[b+0] = byte(ob.hash[i] >> 56)
		digest[b+1] = byte(ob.hash[i] >> 48)
		digest[b+2] = byte(ob.hash[i] >> 40)
		digest[b+3] = byte(ob.hash[i] >> 32)
		digest[b+4] = byte(ob.hash[i] >> 24)
		digest[b+5] = byte(ob.hash[i] >> 16)
		digest[b+6] = byte(ob.hash[i] >> 8)
		digest[b+7] = byte(ob.hash[i])
		b += 8
	}
	ob.bufferBits = bufferBits
	ob.bufferPos = bufferPos
} //                                                                    finalize

// The core Whirlpool transform.
func processBuffer(ob *Hash) {
	if ob == nil {
		zr.Error(zr.ENilReceiver)
		return
	}
	var (
		K      [8]uint64 // the round key
		block  [8]uint64 // mu(buffer)
		state  [8]uint64 // the cipher state
		L      [8]uint64
		buffer = ob.buffer[:]
	)
	if cTraceIntermediateValues {
		fmt.Printf("The 8x8 matrix Z' derived from the" +
			" data-string is as follows.\r\n")
		for i, b := 0, 0; i < cWBlockBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
				buffer[b+0], buffer[b+1], buffer[b+2], buffer[b+3],
				buffer[b+4], buffer[b+5], buffer[b+6], buffer[b+7])
			b += 8
		}
		fmt.Printf("\r\n")
		buffer = ob.buffer[:]
	}
	// map the buffer to a block:
	for i, b := 0, 0; i < 8; i++ {
		block[i] = ((uint64(buffer[b+0])) << 56) ^
			((uint64(buffer[b+1]) & 0xff) << 48) ^
			((uint64(buffer[b+2]) & 0xff) << 40) ^
			((uint64(buffer[b+3]) & 0xff) << 32) ^
			((uint64(buffer[b+4]) & 0xff) << 24) ^
			((uint64(buffer[b+5]) & 0xff) << 16) ^
			((uint64(buffer[b+6]) & 0xff) << 8) ^
			(uint64(buffer[b+7]) & 0xff)
		b += 8
	}
	// compute and apply K^0 to the cipher state:
	for i := 0; i < 8; i++ {
		K[i] = ob.hash[i]
		state[i] = block[i] ^ K[i]
	}
	if cTraceIntermediateValues {
		fmt.Printf("The K_0 matrix (from the initialization value IV)" +
			" and X'' matrix are as follows.\r\n")
		for i := 0; i < cDigestBytes/8; i++ {
			fmt.Printf(
				"    %02X %02X %02X %02X %02X %02X %02X %02X    "+
					"    %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
				byte(K[i]>>56),
				byte(K[i]>>48),
				byte(K[i]>>40),
				byte(K[i]>>32),
				byte(K[i]>>24),
				byte(K[i]>>16),
				byte(K[i]>>8),
				byte(K[i]),
				byte(state[i]>>56),
				byte(state[i]>>48),
				byte(state[i]>>40),
				byte(state[i]>>32),
				byte(state[i]>>24),
				byte(state[i]>>16),
				byte(state[i]>>8),
				byte(state[i]),
			)
		}
		fmt.Printf("\r\n" +
			"The following are (hexadecimal representations of) the" +
			" successive values of the variables" +
			" K_i for i = 1 to 10 and W'.\r\n\r\n")
	}
	// iterate over all rounds:
	for r := 1; r <= cRounds; r++ {
		// compute K^r from K^{r-1}:
		L[0] = cC0[int(K[0]>>56)] ^
			cC1[int(K[7]>>48)&0xff] ^
			cC2[int(K[6]>>40)&0xff] ^
			cC3[int(K[5]>>32)&0xff] ^
			cC4[int(K[4]>>24)&0xff] ^
			cC5[int(K[3]>>16)&0xff] ^
			cC6[int(K[2]>>8)&0xff] ^
			cC7[int(K[1])&0xff] ^
			rc[r]
		L[1] = cC0[int(K[1]>>56)] ^
			cC1[int(K[0]>>48)&0xff] ^
			cC2[int(K[7]>>40)&0xff] ^
			cC3[int(K[6]>>32)&0xff] ^
			cC4[int(K[5]>>24)&0xff] ^
			cC5[int(K[4]>>16)&0xff] ^
			cC6[int(K[3]>>8)&0xff] ^
			cC7[int(K[2])&0xff]
		L[2] = cC0[int(K[2]>>56)] ^
			cC1[int(K[1]>>48)&0xff] ^
			cC2[int(K[0]>>40)&0xff] ^
			cC3[int(K[7]>>32)&0xff] ^
			cC4[int(K[6]>>24)&0xff] ^
			cC5[int(K[5]>>16)&0xff] ^
			cC6[int(K[4]>>8)&0xff] ^
			cC7[int(K[3])&0xff]
		L[3] = cC0[int(K[3]>>56)] ^
			cC1[int(K[2]>>48)&0xff] ^
			cC2[int(K[1]>>40)&0xff] ^
			cC3[int(K[0]>>32)&0xff] ^
			cC4[int(K[7]>>24)&0xff] ^
			cC5[int(K[6]>>16)&0xff] ^
			cC6[int(K[5]>>8)&0xff] ^
			cC7[int(K[4])&0xff]
		L[4] = cC0[int(K[4]>>56)] ^
			cC1[int(K[3]>>48)&0xff] ^
			cC2[int(K[2]>>40)&0xff] ^
			cC3[int(K[1]>>32)&0xff] ^
			cC4[int(K[0]>>24)&0xff] ^
			cC5[int(K[7]>>16)&0xff] ^
			cC6[int(K[6]>>8)&0xff] ^
			cC7[int(K[5])&0xff]
		L[5] = cC0[int(K[5]>>56)] ^
			cC1[int(K[4]>>48)&0xff] ^
			cC2[int(K[3]>>40)&0xff] ^
			cC3[int(K[2]>>32)&0xff] ^
			cC4[int(K[1]>>24)&0xff] ^
			cC5[int(K[0]>>16)&0xff] ^
			cC6[int(K[7]>>8)&0xff] ^
			cC7[int(K[6])&0xff]
		L[6] = cC0[int(K[6]>>56)] ^
			cC1[int(K[5]>>48)&0xff] ^
			cC2[int(K[4]>>40)&0xff] ^
			cC3[int(K[3]>>32)&0xff] ^
			cC4[int(K[2]>>24)&0xff] ^
			cC5[int(K[1]>>16)&0xff] ^
			cC6[int(K[0]>>8)&0xff] ^
			cC7[int(K[7])&0xff]
		L[7] = cC0[int(K[7]>>56)] ^
			cC1[int(K[6]>>48)&0xff] ^
			cC2[int(K[5]>>40)&0xff] ^
			cC3[int(K[4]>>32)&0xff] ^
			cC4[int(K[3]>>24)&0xff] ^
			cC5[int(K[2]>>16)&0xff] ^
			cC6[int(K[1]>>8)&0xff] ^
			cC7[int(K[0])&0xff]
		K[0] = L[0]
		K[1] = L[1]
		K[2] = L[2]
		K[3] = L[3]
		K[4] = L[4]
		K[5] = L[5]
		K[6] = L[6]
		K[7] = L[7]
		// apply the r-th round transformation:
		L[0] = cC0[int(state[0]>>56)] ^
			cC1[int(state[7]>>48)&0xff] ^
			cC2[int(state[6]>>40)&0xff] ^
			cC3[int(state[5]>>32)&0xff] ^
			cC4[int(state[4]>>24)&0xff] ^
			cC5[int(state[3]>>16)&0xff] ^
			cC6[int(state[2]>>8)&0xff] ^
			cC7[int(state[1])&0xff] ^
			K[0]
		L[1] = cC0[int(state[1]>>56)] ^
			cC1[int(state[0]>>48)&0xff] ^
			cC2[int(state[7]>>40)&0xff] ^
			cC3[int(state[6]>>32)&0xff] ^
			cC4[int(state[5]>>24)&0xff] ^
			cC5[int(state[4]>>16)&0xff] ^
			cC6[int(state[3]>>8)&0xff] ^
			cC7[int(state[2])&0xff] ^
			K[1]
		L[2] = cC0[int(state[2]>>56)] ^
			cC1[int(state[1]>>48)&0xff] ^
			cC2[int(state[0]>>40)&0xff] ^
			cC3[int(state[7]>>32)&0xff] ^
			cC4[int(state[6]>>24)&0xff] ^
			cC5[int(state[5]>>16)&0xff] ^
			cC6[int(state[4]>>8)&0xff] ^
			cC7[int(state[3])&0xff] ^
			K[2]
		L[3] = cC0[int(state[3]>>56)] ^
			cC1[int(state[2]>>48)&0xff] ^
			cC2[int(state[1]>>40)&0xff] ^
			cC3[int(state[0]>>32)&0xff] ^
			cC4[int(state[7]>>24)&0xff] ^
			cC5[int(state[6]>>16)&0xff] ^
			cC6[int(state[5]>>8)&0xff] ^
			cC7[int(state[4])&0xff] ^
			K[3]
		L[4] = cC0[int(state[4]>>56)] ^
			cC1[int(state[3]>>48)&0xff] ^
			cC2[int(state[2]>>40)&0xff] ^
			cC3[int(state[1]>>32)&0xff] ^
			cC4[int(state[0]>>24)&0xff] ^
			cC5[int(state[7]>>16)&0xff] ^
			cC6[int(state[6]>>8)&0xff] ^
			cC7[int(state[5])&0xff] ^
			K[4]
		L[5] = cC0[int(state[5]>>56)] ^
			cC1[int(state[4]>>48)&0xff] ^
			cC2[int(state[3]>>40)&0xff] ^
			cC3[int(state[2]>>32)&0xff] ^
			cC4[int(state[1]>>24)&0xff] ^
			cC5[int(state[0]>>16)&0xff] ^
			cC6[int(state[7]>>8)&0xff] ^
			cC7[int(state[6])&0xff] ^
			K[5]
		L[6] = cC0[int(state[6]>>56)] ^
			cC1[int(state[5]>>48)&0xff] ^
			cC2[int(state[4]>>40)&0xff] ^
			cC3[int(state[3]>>32)&0xff] ^
			cC4[int(state[2]>>24)&0xff] ^
			cC5[int(state[1]>>16)&0xff] ^
			cC6[int(state[0]>>8)&0xff] ^
			cC7[int(state[7])&0xff] ^
			K[6]
		L[7] = cC0[int(state[7]>>56)] ^
			cC1[int(state[6]>>48)&0xff] ^
			cC2[int(state[5]>>40)&0xff] ^
			cC3[int(state[4]>>32)&0xff] ^
			cC4[int(state[3]>>24)&0xff] ^
			cC5[int(state[2]>>16)&0xff] ^
			cC6[int(state[1]>>8)&0xff] ^
			cC7[int(state[0])&0xff] ^
			K[7]
		state[0] = L[0]
		state[1] = L[1]
		state[2] = L[2]
		state[3] = L[3]
		state[4] = L[4]
		state[5] = L[5]
		state[6] = L[6]
		state[7] = L[7]
		if cTraceIntermediateValues {
			fmt.Printf("i = %d:\r\n", r)
			for i := 0; i < cDigestBytes/8; i++ {
				fmt.Printf(
					"    %02X %02X %02X %02X %02X %02X %02X %02X        "+
						"%02X %02X %02X %02X %02X %02X %02X %02X\r\n",
					byte(K[i]>>56),
					byte(K[i]>>48),
					byte(K[i]>>40),
					byte(K[i]>>32),
					byte(K[i]>>24),
					byte(K[i]>>16),
					byte(K[i]>>8),
					byte(K[i]),
					byte(state[i]>>56),
					byte(state[i]>>48),
					byte(state[i]>>40),
					byte(state[i]>>32),
					byte(state[i]>>24),
					byte(state[i]>>16),
					byte(state[i]>>8),
					byte(state[i]),
				)
			}
			fmt.Printf("\r\n")
		}
	}
	// apply the Miyaguchi-Preneel compression function:
	ob.hash[0] ^= state[0] ^ block[0]
	ob.hash[1] ^= state[1] ^ block[1]
	ob.hash[2] ^= state[2] ^ block[2]
	ob.hash[3] ^= state[3] ^ block[3]
	ob.hash[4] ^= state[4] ^ block[4]
	ob.hash[5] ^= state[5] ^ block[5]
	ob.hash[6] ^= state[6] ^ block[6]
	ob.hash[7] ^= state[7] ^ block[7]
	if cTraceIntermediateValues {
		fmt.Printf("The value of Y' output from the" +
			" round-function is as follows.\r\n")
		for i := 0; i < cDigestBytes/8; i++ {
			fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
				byte(ob.hash[i]>>56),
				byte(ob.hash[i]>>48),
				byte(ob.hash[i]>>40),
				byte(ob.hash[i]>>32),
				byte(ob.hash[i]>>24),
				byte(ob.hash[i]>>16),
				byte(ob.hash[i]>>8),
				byte(ob.hash[i]))
		}
		fmt.Printf("\r\n")
	}
} //                                                               processBuffer

//end
