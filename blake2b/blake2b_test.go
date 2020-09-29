package blake2b

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

const (
	// Source: BLAKE2 Section 2.8
	DemoParamBytes = "402001010000000000000000000000000000000000000000000000000000000055555555555555555555555555555555eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func TestParameterBlockInit(t *testing.T) {
	params := &parameterBlock{
		fanout:          1,
		depth:           1,
		KeyLength:       32,
		DigestSize:      64,
		Salt:            []byte{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
		Personalization: []byte{0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee},
	}

	packedBytes := params.Marshal()
	expectedBytes, _ := hex.DecodeString(DemoParamBytes)

	if !bytes.Equal(packedBytes, expectedBytes) {
		t.Errorf("packed bytes mismatch: %x %x", packedBytes, expectedBytes)
	}

	digest := initFromParams(params)
	if digest.h[0] != (IV0 ^ 0x01012040) {
		t.Errorf("first u32 of parameter block was wrong: %x", digest.h[0])
	}
}

func TestNewDigest(t *testing.T) {
	_, err := NewDigest(nil, nil, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
}

// These come from the BLAKE2b reference implementation.
type ReferenceTestVector struct {
	Hash    string `json:"hash"`
	Input   string `json:"in"`
	Key     string `json:"key"`
	Persona string `json:"persona,omitempty"`
	Salt    string `json:"salt,omitempty"`
	Output  string `json:"out"`
}

func TestStandardVectors(t *testing.T) {
	jsonTestData, err := ioutil.ReadFile("../testdata/blake2b-kat.json")
	if err != nil {
		t.Skip()
	}
	var tests []ReferenceTestVector
	err = json.Unmarshal(jsonTestData, &tests)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		if test.Hash != "blake2b" {
			t.Errorf("Got a test for the wrong hash: %s", test.Hash)
			continue
		}
		decodedInput, _ := hex.DecodeString(test.Input)
		if len(decodedInput) == 0 {
			decodedInput = nil
		}
		decodedKey, _ := hex.DecodeString(test.Key)
		if len(decodedKey) == 0 {
			decodedKey = nil
		}
		decodedOutput, _ := hex.DecodeString(test.Output)
		d, err := NewDigest(decodedKey, nil, nil, 64)
		if err != nil {
			t.Error(err)
			continue
		}
		if decodedInput != nil {
			d.Write(decodedInput)
		}
		if !bytes.Equal(decodedOutput, d.Sum(nil)) {
			t.Errorf("Failed test: %v", test.Output)
			break
		}
	}
}

func TestExtrasVectors(t *testing.T) {
	jsonTestData, err := ioutil.ReadFile("../testdata/blake2b-extras.json")
	if err != nil {
		t.Skip()
	}
	var tests []ReferenceTestVector
	err = json.Unmarshal(jsonTestData, &tests)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		if test.Hash != "blake2b" {
			t.Errorf("Got a test for the wrong hash: %s", test.Hash)
			continue
		}
		decodedInput, _ := hex.DecodeString(test.Input)
		if len(decodedInput) == 0 {
			decodedInput = nil
		}
		decodedKey, _ := hex.DecodeString(test.Key)
		if len(decodedKey) == 0 {
			decodedKey = nil
		}
		decodedSalt, _ := hex.DecodeString(test.Salt)
		if len(decodedSalt) == 0 {
			decodedSalt = nil
		}
		decodedPersona, _ := hex.DecodeString(test.Persona)
		if len(decodedPersona) == 0 {
			decodedPersona = nil
		}
		decodedOutput, _ := hex.DecodeString(test.Output)

		d, err := NewDigest(decodedKey, decodedSalt, decodedPersona, 64)
		if err != nil {
			t.Error(err)
			continue
		}

		if decodedInput != nil {
			d.Write(decodedInput)
		}

		if !bytes.Equal(decodedOutput, d.Sum(nil)) {
			t.Errorf("Failed test: %v", test.Output)
			break
		}
	}
}

var emptyBuf = make([]byte, 16384)

func benchmarkHashSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		digest, _ := NewDigest(nil, nil, nil, 64)
		digest.Write(emptyBuf[:size])
		digest.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkHashSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkHashSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkHashSize(b, 8192)
}
