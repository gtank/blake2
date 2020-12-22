// Package blake2b implements the BLAKE2b secure hashing algorithm with support
// for salting and personalization. BLAKE2b is optimized for 64-bit platforms
// and produces digests of any size between 1 and 64 bytes
package blake2b

import (
	"errors"
)

// The constant values will be different for other BLAKE2 variants. These are
// appropriate for BLAKE2b.
const (
	// The length of the key field.
	KeyLength = 64
	// The maximum number of bytes to produce.
	MaxOutput = 64
	// Max size of the salt, in bytes
	SaltLength = 16
	// Max size of the personalization string, in bytes
	SeparatorLength = 16
	// Number of G function rounds for BLAKE2b.
	RoundCount = 12
	// Size of a block buffer in bytes
	BlockSize = 128

	// Initialization vector for BLAKE2b
	IV0 uint64 = 0x6a09e667f3bcc908
	IV1 uint64 = 0xbb67ae8584caa73b
	IV2 uint64 = 0x3c6ef372fe94f82b
	IV3 uint64 = 0xa54ff53a5f1d36f1
	IV4 uint64 = 0x510e527fade682d1
	IV5 uint64 = 0x9b05688c2b3e6c1f
	IV6 uint64 = 0x1f83d9abfb41bd6b
	IV7 uint64 = 0x5be0cd19137e2179
)

// These are the user-visible parameters of a BLAKE2 hash instance. The
// parameter block is XOR'd with the IV at the beginning of the hash.
// Currently we only support sequential mode, so many of these values will be
// hardcoded to a default. They are nevertheless defined for clarity.
type parameterBlock struct {
	DigestSize      byte   // 0
	KeyLength       byte   // 1
	fanout          byte   // 2
	depth           byte   // 3
	leafLength      uint32 // 4-7
	nodeOffset      uint32 // 8-11
	xofLength       uint32 // 12-16
	nodeDepth       byte   // 17
	innerLength     byte   // 18
	reserved        []byte // 14 bytes
	Salt            []byte // 32-48
	Personalization []byte // 48-64
}

// Packs a BLAKE2 parameter block.
func (p *parameterBlock) Marshal() []byte {
	buf := make([]byte, 64)
	buf[0] = p.DigestSize
	buf[1] = p.KeyLength
	buf[2] = p.fanout
	buf[3] = p.depth
	putU32LE(buf[4:], p.leafLength)
	putU32LE(buf[8:], p.nodeOffset)
	putU32LE(buf[12:], p.xofLength)
	buf[17] = p.nodeDepth
	buf[18] = p.innerLength
	// 14 bytes implicitly zero
	copy(buf[32:], p.Salt)
	copy(buf[48:], p.Personalization)
	return buf
}

// Digest represents the internal state of the BLAKE2b algorithm.
type Digest struct {
	h      [8]uint64
	t0, t1 uint64
	f0, f1 uint64

	buf    [BlockSize]byte
	offset int // current offset inside the block

	// size is definted in hash.Hash, and returns the number of bytes Sum will
	// return. Since BLAKE2 output length is dynamic, so is this.
	size int
}

// After this function is called, the ParameterBlock can be discarded.
func initFromParams(p *parameterBlock) *Digest {
	paramBytes := p.Marshal()

	h0 := IV0 ^ u64LE(paramBytes[0:8])
	h1 := IV1 ^ u64LE(paramBytes[8:16])
	h2 := IV2 ^ u64LE(paramBytes[16:24])
	h3 := IV3 ^ u64LE(paramBytes[24:32])
	h4 := IV4 ^ u64LE(paramBytes[32:40])
	h5 := IV5 ^ u64LE(paramBytes[40:48])
	h6 := IV6 ^ u64LE(paramBytes[48:56])
	h7 := IV7 ^ u64LE(paramBytes[56:64])

	d := &Digest{
		h:    [8]uint64{h0, h1, h2, h3, h4, h5, h6, h7},
		buf:  [BlockSize]byte{},
		size: int(p.DigestSize),
	}

	return d
}

func (d *Digest) compress() {
	// Create the internal round state. Copy the current hash state to the top,
	// then the tweaked IVs to the bottom. Use local variables to avoid
	// allocating another slice.
	v0, v1, v2, v3 := d.h[0], d.h[1], d.h[2], d.h[3]
	v4, v5, v6, v7 := d.h[4], d.h[5], d.h[6], d.h[7]
	v8, v9, v10, v11 := IV0, IV1, IV2, IV3
	v12 := IV4 ^ d.t0
	v13 := IV5 ^ d.t1
	v14 := IV6 ^ d.f0
	v15 := IV7 ^ d.f1

	// This round structure is several steps removed from the spec and
	// reference implementation. We unrolled the loops and calculated the
	// offsets from the permutation table entry for each round, then directly
	// mapped it to the correct word of the input block. This is a tradeoff:
	// the doubly-indirect lookups were horrible for performance, but it's not
	// at all obvious what this code is doing anymore.
	//
	// We also split the message buffer into 16x64-bit words (m0..m15) as late
	// as possible before they're needed. The small decrease in liveness scope
	// matters ever-so-slightly.

	// Round 0 w/ precomputed permutation offsets
	m0 := u64LE(d.buf[0*8 : 0*4+8])
	m1 := u64LE(d.buf[1*8 : 1*8+8])
	v0, v4, v8, v12 = g(v0+v4+m0, v4, v8, v12, m1)
	m2 := u64LE(d.buf[2*8 : 2*8+8])
	m3 := u64LE(d.buf[3*8 : 3*8+8])
	v1, v5, v9, v13 = g(v1+v5+m2, v5, v9, v13, m3)
	m4 := u64LE(d.buf[4*8 : 4*8+8])
	m5 := u64LE(d.buf[5*8 : 5*8+8])
	v2, v6, v10, v14 = g(v2+v6+m4, v6, v10, v14, m5)
	m6 := u64LE(d.buf[6*8 : 6*8+8])
	m7 := u64LE(d.buf[7*8 : 7*8+8])
	v3, v7, v11, v15 = g(v3+v7+m6, v7, v11, v15, m7)
	m8 := u64LE(d.buf[8*8 : 8*8+8])
	m9 := u64LE(d.buf[9*8 : 9*8+8])
	v0, v5, v10, v15 = g(v0+v5+m8, v5, v10, v15, m9)
	m10 := u64LE(d.buf[10*8 : 10*8+8])
	m11 := u64LE(d.buf[11*8 : 11*8+8])
	v1, v6, v11, v12 = g(v1+v6+m10, v6, v11, v12, m11)
	m12 := u64LE(d.buf[12*8 : 12*8+8])
	m13 := u64LE(d.buf[13*8 : 13*8+8])
	v2, v7, v8, v13 = g(v2+v7+m12, v7, v8, v13, m13)
	m14 := u64LE(d.buf[14*8 : 14*8+8])
	m15 := u64LE(d.buf[15*8 : 15*8+8])
	v3, v4, v9, v14 = g(v3+v4+m14, v4, v9, v14, m15)

	// Round 1
	v0, v4, v8, v12 = g(v0+v4+m14, v4, v8, v12, m10)
	v1, v5, v9, v13 = g(v1+v5+m4, v5, v9, v13, m8)
	v2, v6, v10, v14 = g(v2+v6+m9, v6, v10, v14, m15)
	v3, v7, v11, v15 = g(v3+v7+m13, v7, v11, v15, m6)

	v0, v5, v10, v15 = g(v0+v5+m1, v5, v10, v15, m12)
	v1, v6, v11, v12 = g(v1+v6+m0, v6, v11, v12, m2)
	v2, v7, v8, v13 = g(v2+v7+m11, v7, v8, v13, m7)
	v3, v4, v9, v14 = g(v3+v4+m5, v4, v9, v14, m3)

	// Round 2
	v0, v4, v8, v12 = g(v0+v4+m11, v4, v8, v12, m8)
	v1, v5, v9, v13 = g(v1+v5+m12, v5, v9, v13, m0)
	v2, v6, v10, v14 = g(v2+v6+m5, v6, v10, v14, m2)
	v3, v7, v11, v15 = g(v3+v7+m15, v7, v11, v15, m13)

	v0, v5, v10, v15 = g(v0+v5+m10, v5, v10, v15, m14)
	v1, v6, v11, v12 = g(v1+v6+m3, v6, v11, v12, m6)
	v2, v7, v8, v13 = g(v2+v7+m7, v7, v8, v13, m1)
	v3, v4, v9, v14 = g(v3+v4+m9, v4, v9, v14, m4)

	// Round 3
	v0, v4, v8, v12 = g(v0+v4+m7, v4, v8, v12, m9)
	v1, v5, v9, v13 = g(v1+v5+m3, v5, v9, v13, m1)
	v2, v6, v10, v14 = g(v2+v6+m13, v6, v10, v14, m12)
	v3, v7, v11, v15 = g(v3+v7+m11, v7, v11, v15, m14)

	v0, v5, v10, v15 = g(v0+v5+m2, v5, v10, v15, m6)
	v1, v6, v11, v12 = g(v1+v6+m5, v6, v11, v12, m10)
	v2, v7, v8, v13 = g(v2+v7+m4, v7, v8, v13, m0)
	v3, v4, v9, v14 = g(v3+v4+m15, v4, v9, v14, m8)

	// Round 4
	v0, v4, v8, v12 = g(v0+v4+m9, v4, v8, v12, m0)
	v1, v5, v9, v13 = g(v1+v5+m5, v5, v9, v13, m7)
	v2, v6, v10, v14 = g(v2+v6+m2, v6, v10, v14, m4)
	v3, v7, v11, v15 = g(v3+v7+m10, v7, v11, v15, m15)

	v0, v5, v10, v15 = g(v0+v5+m14, v5, v10, v15, m1)
	v1, v6, v11, v12 = g(v1+v6+m11, v6, v11, v12, m12)
	v2, v7, v8, v13 = g(v2+v7+m6, v7, v8, v13, m8)
	v3, v4, v9, v14 = g(v3+v4+m3, v4, v9, v14, m13)

	// Round 5
	v0, v4, v8, v12 = g(v0+v4+m2, v4, v8, v12, m12)
	v1, v5, v9, v13 = g(v1+v5+m6, v5, v9, v13, m10)
	v2, v6, v10, v14 = g(v2+v6+m0, v6, v10, v14, m11)
	v3, v7, v11, v15 = g(v3+v7+m8, v7, v11, v15, m3)

	v0, v5, v10, v15 = g(v0+v5+m4, v5, v10, v15, m13)
	v1, v6, v11, v12 = g(v1+v6+m7, v6, v11, v12, m5)
	v2, v7, v8, v13 = g(v2+v7+m15, v7, v8, v13, m14)
	v3, v4, v9, v14 = g(v3+v4+m1, v4, v9, v14, m9)

	// Round 6
	v0, v4, v8, v12 = g(v0+v4+m12, v4, v8, v12, m5)
	v1, v5, v9, v13 = g(v1+v5+m1, v5, v9, v13, m15)
	v2, v6, v10, v14 = g(v2+v6+m14, v6, v10, v14, m13)
	v3, v7, v11, v15 = g(v3+v7+m4, v7, v11, v15, m10)

	v0, v5, v10, v15 = g(v0+v5+m0, v5, v10, v15, m7)
	v1, v6, v11, v12 = g(v1+v6+m6, v6, v11, v12, m3)
	v2, v7, v8, v13 = g(v2+v7+m9, v7, v8, v13, m2)
	v3, v4, v9, v14 = g(v3+v4+m8, v4, v9, v14, m11)

	// Round 7
	v0, v4, v8, v12 = g(v0+v4+m13, v4, v8, v12, m11)
	v1, v5, v9, v13 = g(v1+v5+m7, v5, v9, v13, m14)
	v2, v6, v10, v14 = g(v2+v6+m12, v6, v10, v14, m1)
	v3, v7, v11, v15 = g(v3+v7+m3, v7, v11, v15, m9)

	v0, v5, v10, v15 = g(v0+v5+m5, v5, v10, v15, m0)
	v1, v6, v11, v12 = g(v1+v6+m15, v6, v11, v12, m4)
	v2, v7, v8, v13 = g(v2+v7+m8, v7, v8, v13, m6)
	v3, v4, v9, v14 = g(v3+v4+m2, v4, v9, v14, m10)

	// Round 8
	v0, v4, v8, v12 = g(v0+v4+m6, v4, v8, v12, m15)
	v1, v5, v9, v13 = g(v1+v5+m14, v5, v9, v13, m9)
	v2, v6, v10, v14 = g(v2+v6+m11, v6, v10, v14, m3)
	v3, v7, v11, v15 = g(v3+v7+m0, v7, v11, v15, m8)

	v0, v5, v10, v15 = g(v0+v5+m12, v5, v10, v15, m2)
	v1, v6, v11, v12 = g(v1+v6+m13, v6, v11, v12, m7)
	v2, v7, v8, v13 = g(v2+v7+m1, v7, v8, v13, m4)
	v3, v4, v9, v14 = g(v3+v4+m10, v4, v9, v14, m5)

	// Round 9
	v0, v4, v8, v12 = g(v0+v4+m10, v4, v8, v12, m2)
	v1, v5, v9, v13 = g(v1+v5+m8, v5, v9, v13, m4)
	v2, v6, v10, v14 = g(v2+v6+m7, v6, v10, v14, m6)
	v3, v7, v11, v15 = g(v3+v7+m1, v7, v11, v15, m5)

	v0, v5, v10, v15 = g(v0+v5+m15, v5, v10, v15, m11)
	v1, v6, v11, v12 = g(v1+v6+m9, v6, v11, v12, m14)
	v2, v7, v8, v13 = g(v2+v7+m3, v7, v8, v13, m12)
	v3, v4, v9, v14 = g(v3+v4+m13, v4, v9, v14, m0)

	// Round 10 is round 0 again
	v0, v4, v8, v12 = g(v0+v4+m0, v4, v8, v12, m1)
	v1, v5, v9, v13 = g(v1+v5+m2, v5, v9, v13, m3)
	v2, v6, v10, v14 = g(v2+v6+m4, v6, v10, v14, m5)
	v3, v7, v11, v15 = g(v3+v7+m6, v7, v11, v15, m7)

	v0, v5, v10, v15 = g(v0+v5+m8, v5, v10, v15, m9)
	v1, v6, v11, v12 = g(v1+v6+m10, v6, v11, v12, m11)
	v2, v7, v8, v13 = g(v2+v7+m12, v7, v8, v13, m13)
	v3, v4, v9, v14 = g(v3+v4+m14, v4, v9, v14, m15)

	// Round 11 is round 1 again
	v0, v4, v8, v12 = g(v0+v4+m14, v4, v8, v12, m10)
	v1, v5, v9, v13 = g(v1+v5+m4, v5, v9, v13, m8)
	v2, v6, v10, v14 = g(v2+v6+m9, v6, v10, v14, m15)
	v3, v7, v11, v15 = g(v3+v7+m13, v7, v11, v15, m6)

	v0, v5, v10, v15 = g(v0+v5+m1, v5, v10, v15, m12)
	v1, v6, v11, v12 = g(v1+v6+m0, v6, v11, v12, m2)
	v2, v7, v8, v13 = g(v2+v7+m11, v7, v8, v13, m7)
	v3, v4, v9, v14 = g(v3+v4+m5, v4, v9, v14, m3)

	d.h[0] = d.h[0] ^ v0 ^ v8
	d.h[1] = d.h[1] ^ v1 ^ v9
	d.h[2] = d.h[2] ^ v2 ^ v10
	d.h[3] = d.h[3] ^ v3 ^ v11
	d.h[4] = d.h[4] ^ v4 ^ v12
	d.h[5] = d.h[5] ^ v5 ^ v13
	d.h[6] = d.h[6] ^ v6 ^ v14
	d.h[7] = d.h[7] ^ v7 ^ v15
}

// The internal BLAKE2b round function.
func g(a, b, c, d, m1 uint64) (uint64, uint64, uint64, uint64) {
	// We lift the table lookups and the initial triple addition into the
	// caller so this function has a better chance of inlining.
	// TODO: The compiler bug that made this necessary has been fixed.

	// a = a + b + m0
	d = ((d ^ a) >> 32) | ((d ^ a) << (64 - 32))
	c = c + d
	b = ((b ^ c) >> 24) | ((b ^ c) << (64 - 24))
	a = a + b + m1
	d = ((d ^ a) >> 16) | ((d ^ a) << (64 - 16))
	c = c + d
	b = ((b ^ c) >> 63) | ((b ^ c) << (64 - 63))

	return a, b, c, d
}

// Note that due to the nature of the hash.Hash interface, calling finalize
// WILL NOT permanently update the underlying hash state. Instead it will
// simulate what would happen if the current block were the final block.
func (d *Digest) finalize(out []byte) error {
	if d.f0 != 0 {
		return errors.New("blake2b: tried to finalize but last flag already set")
	}

	// make copies of everything
	dCopy := *d

	// Zero the unused portion of the buffer. This triggers a specific
	// optimization for memset, see https://codereview.appspot.com/137880043
	memclrBuf := dCopy.buf[dCopy.offset:BlockSize]
	for i := range memclrBuf {
		memclrBuf[i] = 0
	}

	// increment counter by size of pending input before padding
	dCopy.t0 += uint64(d.offset)
	if dCopy.t0 < uint64(d.offset) {
		dCopy.t1++
	}
	// set last block flag
	dCopy.f0 = 0xFFFFFFFFFFFFFFFF

	dCopy.compress()

	var shift uint
	var mask uint64

	for offset := 0; offset < len(out); offset++ {
		shift = 8 * (uint(offset) % 8)
		mask = uint64(0xFF << shift)
		out[offset] = byte((dCopy.h[offset/8] & mask) >> shift)
	}

	return nil
}

// NewDigest constructs a new instance of a BLAKE2b hash with the provided configuration.
func NewDigest(key, salt, personalization []byte, outputBytes int) (*Digest, error) {
	params := &parameterBlock{
		fanout: 1, // sequential mode
		depth:  1, // sequential mode
	}

	if outputBytes <= 0 {
		return nil, errors.New("blake2b: asked for negative or zero output")
	}
	if outputBytes > MaxOutput {
		return nil, errors.New("blake2b: asked for too much output")
	}
	params.DigestSize = byte(outputBytes & 0xFF)

	if key != nil {
		if len(key) > KeyLength {
			return nil, errors.New("blake2b: key too large")
		}
		params.KeyLength = byte(len(key) & 0xFF)
	}

	params.Salt = make([]byte, SaltLength)
	if salt != nil {
		if len(salt) > SaltLength {
			return nil, errors.New("blake2b: salt too large")
		}
		// If salt is too short, this will implicitly right-pad with zero.
		copy(params.Salt, salt)
	}

	params.Personalization = make([]byte, SeparatorLength)
	if personalization != nil {
		if len(personalization) > SeparatorLength {
			return nil, errors.New("blake2b: personalization string too large")
		}
		// If personalization string is short, this will implicitly right-pad with zero.
		copy(params.Personalization, personalization)
	}

	// Initialize the internal state
	digest := initFromParams(params)

	if key != nil {
		// Write key to entire first block and compress
		if len(key) < BlockSize {
			keyBuf := make([]byte, BlockSize)
			copy(keyBuf, key)
			digest.Write(keyBuf)
		}
	}

	return digest, nil
}

// Write adds more data to the running hash.
func (d *Digest) Write(input []byte) (n int, err error) {
	bytesWritten := 0

	// If we have capacity, just copy and wait for a full block. If we don't
	// have capacity, we'll need to take a full block and compress.
	for bytesWritten < len(input) {
		// How much space do we have left in the block?
		freeBytes := BlockSize - d.offset
		inputLeft := len(input) - bytesWritten

		if inputLeft <= freeBytes {
			newOffset := d.offset + inputLeft
			copy(d.buf[d.offset:newOffset], input[bytesWritten:])
			d.offset = newOffset
			return bytesWritten + inputLeft, nil
		}

		copy(d.buf[d.offset:], input[bytesWritten:bytesWritten+freeBytes])

		// increment counter, preserving overflow behavior
		d.t0 += BlockSize
		if d.t0 < BlockSize {
			d.t1++
		}

		d.compress()

		// advance pointers
		bytesWritten += freeBytes
		d.offset = 0

		// loop until we can't fill another buffer
	}

	return bytesWritten, nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *Digest) Sum(b []byte) (out []byte) {
	// if there's space, reuse the b slice
	if n := len(b) + d.size; cap(b) >= n {
		out = b[:n]
	} else {
		out = make([]byte, n)
		copy(out, b)
	}

	err := d.finalize(out[len(b):])

	if err != nil {
		return out[:len(b)]
	}

	return out
}

// Reset resets the Hash to its initial state.
func (d *Digest) Reset() {
	// TODO: not this
	panic("BLAKE2 cannot be reset without storing the key")
}

// Size returns the digest output size in bytes.
func (d *Digest) Size() int { return d.size }

// BlockSize returns the hash's underlying block size. The Write method must be
// able to accept any amount of data, but it may operate more efficiently if
// all writes are a multiple of the block size.
func (d *Digest) BlockSize() int { return BlockSize }
