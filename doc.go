// Package blake2 implements the BLAKE2s and BLAKE2b secure hashing algorithms
// with support for salting and personalization. BLAKE2s is optimized for 8- to
// 32-bit platforms and produces digests of any size between 1 and 32 bytes.
// BLAKE2b is optimized for 64-bit platforms and produces digests of any size
// between 1 and 64 bytes.
package blake2

//go:generate python3 gen_vectors.py testdata/blake2s-extras.json testdata/blake2b-extras.json
