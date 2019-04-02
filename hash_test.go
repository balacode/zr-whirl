// -----------------------------------------------------------------------------
// (c) balarabe@protonmail.com                                      License: MIT
// :v: 2019-04-02 18:21:02 E7284E                        zr-whirl/[hash_test.go]
// -----------------------------------------------------------------------------

package whirl

import (
	"bytes"
	"fmt"
	str "strings"
	"testing"

	"github.com/balacode/zr"
)

/*
to test all items in hash.go use:
    go test --run Test_hash_

to generate a test coverage report for the whole module use:
    go test -coverprofile cover.out
    go tool cover -html=cover.out
*/

// go test --run Test_hash_ISO_
func Test_hash_ISO_(t *testing.T) {
	tests := []struct {
		note   string
		input  string
		expect string
	}{
		{
			note: "1. In this example the data-string is the empty" +
				" string, i.e. the string of length zero.",
			input: "",
			expect: "19FA61D75522A466 9B44E39C1D2E1726" +
				" C530232130D407F8 9AFEE0964997F7A7" + LF +
				" 3E83BE698B288FEB CF88E3E03C4F0757" +
				" EA8964E59B63D937 08B138CC42A66EB3",
		},
		{
			note: "2. In this example the data-string consists of a single" +
				" byte, namely the ASCII-coded version of the letter 'a'.",
			input: "a",
			expect: "8ACA2602792AEC6F 11A67206531FB7D7" +
				" F0DFF59413145E69 73C45001D0087B42" + LF +
				" D11BC645413AEFF6 3A42391A39145A59" +
				" 1A92200D560195E5 3B478584FDAE231A",
		},
		{
			note: "3. In this example the data-string is the three-byte" +
				" string consisting of the ASCII-coded version of 'abc'.",
			input: "abc",
			expect: "4E2448A4C6F486BB 16B6562C73B4020B" +
				" F3043E3A731BCE72 1AE1B303D97E6D4C" + LF +
				" 7181EEBDB6C57E27 7D0E34957114CBD6" +
				" C797FC9D95D8B582 D225292076D4EEF5",
		},
		{
			note: "4. In this example the data-string is the 14-byte string" +
				" consisting of the ASCII-coded version of 'message digest'.",
			input: "message digest",
			expect: "378C84A4126E2DC6 E56DCC7458377AAC" +
				" 838D00032230F53C E1F5700C0FFB4D3B" + LF +
				" 8421557659EF55C1 06B4B52AC5A4AAA6" +
				" 92ED920052838F33 62E86DBD37A8903E",
		},
		{
			note: "5. In this example the data-string is the 26-byte string" +
				" consisting of the ASCII-coded version of" +
				" 'abcdefghijklmnopqrstuvwxyz'.",
			input: "abcdefghijklmnopqrstuvwxyz",
			expect: "F1D754662636FFE9 2C82EBB9212A484A" +
				" 8D38631EAD4238F5 442EE13B8054E41B" + LF +
				" 08BF2A9251C30B6A 0B8AAE86177AB4A6" +
				" F68F673E7207865D 5D9819A3DBA4EB3B",
		},
		{
			note: "6. In this example the data-string is the 62-byte string" +
				" consisting of the ASCII-coded version of" +
				" 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
				"0123456789'.",
			input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
				"0123456789",
			expect: "DC37E008CF9EE69B F11F00ED9ABA2690" +
				" 1DD7C28CDEC066CC 6AF42E40F82F3A1E" + LF +
				" 08EBA26629129D8F B7CB57211B9281A6" +
				" 5517CC879D7B9621 42C65F5A7AF01467",
		},
		{
			note: "7. In this example the data-string is the 80-byte string" +
				" consisting of the ASCII-coded version of eight" +
				" repetitions of '1234567890'.",
			input: str.Repeat("1234567890", 8),
			expect: "466EF18BABB0154D 25B9D38A6414F5C0" +
				" 8784372BCCB204D6 549C4AFADB601429" + LF +
				" 4D5BD8DF2A6C44E5 38CD047B2681A51A" +
				" 2C60481E88C5A20B 2C2A80CF3A9A083B",
		},
		{
			note: "8. In this example the data-string is the 32-byte string" +
				" consisting of the ASCII-coded version of" +
				" 'abcdbcdecdefdefgefghfghighijhijk'.",
			input: "abcdbcdecdefdefgefghfghighijhijk",
			expect: "2A987EA40F917061 F5D6F0A0E4644F48" +
				" 8A7A5A52DEEE6562 07C562F988E95C69" + LF +
				" 16BDC8031BC5BE1B 7B947639FE050B56" +
				" 939BAAA0ADFF9AE6 745B7B181C3BE3FD",
		},
		{
			note: "9. In this example the data-string is the 1000000-byte" +
				" string consisting of the ASCII-coded version of 'a'" +
				" repeated 10^6 times.",
			input: str.Repeat("a", 1000000),
			expect: "0C99005BEB57EFF5 0A7CF005560DDF5D" +
				" 29057FD86B20BFD6 2DECA0F1CCEA4AF5" + LF +
				" 1FC15490EDDC47AF 32BB2B66C34FF9AD" +
				" 8C6008AD677F7712 6953B226E4ED8B01",
		},
	}
	for i, test := range tests {
		digest := Sum512([]byte(test.input))
		if false {
			fmt.Printf(test.note + LF + LF +
				"The hash-code is the following 512-bit string." + LF + LF)
			display(digest[:], cDigestBytes)
		}
		got := str.Trim(format(digest[:]), " \a\b\f\n\r\t\v")
		expect := str.Trim(test.expect, " \a\b\f\n\r\t\v")
		if got != expect {
			fmt.Printf("TEST %d FAILED!"+LF, i+1)
			fmt.Println("EXPECTED:")
			fmt.Println(expect)
			fmt.Println("RETURNED:")
			fmt.Println(got)
			fmt.Printf(LF + LF)
			t.Fail()
		}
	}
	fmt.Println()
} //                                                              Test_hash_ISO_

// Generate the test vector set for Whirlpool.
// The test consists of:
// 1. hashing all bit strings containing only zero bits
//    for all lengths from 0 to 1023
// 2. hashing all 512-bit strings containing a single set bit
// 3. the iterated hashing of the 512-bit string of
//    zero bits a large number of times.
func makeNESSIETestVectors() {
	var digest [cDigestBytes]byte
	var data [128]byte
	fmt.Println("Message digests of strings of 0-bits and length L:")
	for i := 0; i < 1024; i++ {
		w := New()
		appendBytes(data[:], uint64(i), &w)
		finalize(&w, digest[:])
		fmt.Printf("    L = %4d: ", i)
		display(digest[:], cDigestBytes)
		fmt.Println()
	}
	fmt.Println("Message digests of all 512-bit strings S" +
		" containing a single 1-bit:")
	data = [128]byte{}
	for i := 0; i < 512; i++ {
		// set bit i:
		data[i/8] |= 0x80 >> uint32(i%8)
		w := New()
		appendBytes(data[:], 512, &w)
		finalize(&w, digest[:])
		fmt.Printf("    S = ")
		display(data[:], 512/8)
		fmt.Printf(": ")
		display(digest[:], cDigestBytes)
		fmt.Println()
		// reset bit i
		data[i/8] = 0
	}
	const LONGITERATION = 100000000
	digest = [cDigestBytes]byte{}
	for i := 0; i < LONGITERATION; i++ {
		w := New()
		appendBytes(digest[:], 512, &w)
		finalize(&w, digest[:])
	}
	fmt.Printf("Iterated message digest computation (%d times): ",
		LONGITERATION)
	display(digest[:], cDigestBytes)
	fmt.Println()
} //                                                       makeNESSIETestVectors

// testAPI __
func testAPI(t *testing.T) {
	var pieceLen, totalLen, dataLen uint32
	var dataBuf [512]byte
	var expectedDigest [cDigestBytes]byte
	var computedDigest [cDigestBytes]byte
	//
	for dataLen = 0; int(dataLen) <= len(dataBuf); dataLen++ {
		if (dataLen & 0xff) == 0 {
			//todo: fmt.Printf(stderr, ".")
			//todo: flush stderr
		}
		// do the hashing in pieces of variable length:
		w := New()
		appendBytes(dataBuf[:], uint64(8*dataLen), &w)
		finalize(&w, expectedDigest[:])
		if dataLen > 0 {
			for pieceLen = 1; pieceLen <= dataLen; pieceLen++ {
				w := New()
				for totalLen = 0; totalLen+pieceLen <=
					dataLen; totalLen += pieceLen {
					appendBytes(dataBuf[totalLen:], uint64(8*pieceLen), &w)
				}
				if totalLen < dataLen {
					appendBytes(dataBuf[totalLen:],
						uint64(8*(dataLen-totalLen)), &w)
				}
				finalize(&w, computedDigest[:])
				if bytes.Compare(computedDigest[:], expectedDigest[:]) != 0 {
					fmt.Printf("API error @ pieceLen = %v"+LF, pieceLen)
					display(computedDigest[:], cDigestBytes)
					fmt.Printf(LF + LF)
					display(expectedDigest[:], cDigestBytes)
					fmt.Printf(LF + LF)
					t.Fail()
					return
				}
			}
		} else {
			w := New()
			finalize(&w, computedDigest[:])
			if bytes.Compare(computedDigest[:], expectedDigest[:]) != 0 {
				fmt.Println("API error @ pieceLen = 0")
				t.Fail()
				return
			}
		}
	}
	fmt.Println("No error detected.")
} //                                                                     testAPI

//  timing __
func timing() {
	const TIMINGITERATIONS = 100000
	var digest [cDigestBytes]byte
	var data [1024]byte
	//todo: clock_t elapsed
	var sec float32
	fmt.Printf("Overall timing...")
	elapsed := 0 //todo: -clock()
	for i := 0; i < TIMINGITERATIONS; i++ {
		w := New()
		appendBytes(data[:], uint64(8*len(data)), &w)
		finalize(&w, digest[:])
	}
	elapsed += 0               //todo: clock()
	sec = float32(elapsed) / 1 //todo: CLOCKS_PER_SEC
	fmt.Printf(" %.1f s, %.1f Mbit/s, %.1f cycles/byte."+LF,
		sec,
		float32(8)*float32(len(data))*TIMINGITERATIONS/sec/1000000,
		float32(550e6)*sec/(float32(len(data))*TIMINGITERATIONS))
	fmt.Printf("Compression function timing...")
	w := New()
	elapsed = 0 //todo: -clock()
	for i := 0; i < TIMINGITERATIONS; i++ {
		processBuffer(&w)
	}
	elapsed += 0 //todo: clock()
	finalize(&w, digest[:])
	sec = float32(elapsed) / 0 //todo: CLOCKS_PER_SEC
	fmt.Printf(" %.1f s, %.1f Mbit/s, %.1f cycles/byte."+LF,
		sec,
		float32(512)*TIMINGITERATIONS/sec/1000000,
		float32(550e6)*sec/(64*TIMINGITERATIONS))
} //                                                                      timing

// makeIntermediateValues __
func makeIntermediateValues() {
	if !cTraceIntermediateValues {
		return
	}
	var digest [cDigestBytes]byte
	fmt.Printf("3. In this example the data-string is the three-byte" +
		" string consisting of the ASCII-coded version of 'abc'." + LF + LF)
	w := New()
	appendBytes([]byte("abc"), 8*3, &w)
	finalize(&w, digest[:])
	fmt.Printf("The hash-code is the following 512-bit string." + LF)
	display(digest[:], cDigestBytes)
	fmt.Printf(LF + LF)
	fmt.Printf("8. In this example the data-string is the 32-byte string" +
		" consisting of the ASCII-coded version of" +
		" 'abcdbcdecdefdefgefghfghighijhijk'." + LF + LF)
	w = New()
	appendBytes([]byte("abcdbcdecdefdefgefghfghighijhijk"), 8*32, &w)
	finalize(&w, digest[:])
	fmt.Printf("The hash-code is the following 512-bit string." + LF + LF)
	display(digest[:], cDigestBytes)
	fmt.Printf(LF + LF)
} //                                                      makeIntermediateValues

// display __
func display(ar []byte, length int) {
	for i := 0; i < length; i++ {
		if i%32 == 0 {
			fmt.Println()
		}
		if i%8 == 0 {
			fmt.Printf(" ")
		}
		fmt.Printf("%02X", ar[i])
	}
} //                                                                     display

// format __
func format(ar []byte) (ret string) {
	for i := 0; i < len(ar); i++ {
		if i%32 == 0 {
			ret += LF
		}
		if i%8 == 0 {
			ret += " "
		}
		ret += fmt.Sprintf("%02X", ar[i])
	}
	return ret
} //                                                                      format

// printStruct __
func (ob *Hash) printStruct(title string) {
	if ob == nil {
		zr.Error(zr.ENilReceiver)
		return
	}
	fmt.Printf("Hash: %s"+LF, title)
	buf := ob.buffer[:]
	for i, b := 0, 0; i < cWBlockBytes/8; i++ {
		fmt.Printf("    %02X %02X %02X %02X %02X %02X %02X %02X"+LF,
			buf[b+0], buf[b+1], buf[b+2], buf[b+3],
			buf[b+4], buf[b+5], buf[b+6], buf[b+7])
		b += 8
	}
	fmt.Println()
} //                                                                 printStruct

// go test --run Test_hash_Whirlpool_
func Test_hash_Whirlpool_(t *testing.T) {
	// testAPI()
	// makeNESSIETestVectors()
	// makeISOTestVectors()
	// if cTraceIntermediateValues {
	//     makeIntermediateValues()
	// }
	// timing()
} //                                                        Test_hash_Whirlpool_

//end
