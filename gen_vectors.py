#!/bin/env python3

import json
import sys

from pyblake2 import blake2s, blake2b

def write_blake2s_tests(output_fn):
    fd = open(output_fn, 'w')

    key_bytes = bytearray(range(32))

    fd.write('[\n')
    for i in range(8):
        salt_bytes = bytearray(range(i+1))
        test = {
                "hash": "blake2s",
                "in": "",
                "key": key_bytes.hex(),
                "persona": "",
                "salt": salt_bytes.hex(),
                "out": blake2s(key=key_bytes, salt=salt_bytes).hexdigest()
               }
        fd.write(json.dumps(test, indent=True)+',\n')

    for i in range(8):
        persona_bytes = bytearray(range(i+1))
        test = {
                "hash": "blake2s",
                "in": "",
                "key": key_bytes.hex(),
                "persona": persona_bytes.hex(),
                "salt": "",
                "out": blake2s(key=key_bytes, person=persona_bytes).hexdigest()
               }
        fd.write(json.dumps(test, indent=True)+',\n')

    for i in range(32):
        salt_bytes = bytearray(range(8))
        persona_bytes = bytearray(range(8))
        length = i+1
        test = {
                "hash": "blake2s",
                "in": "",
                "key": "",
                "persona": "",
                "salt": "",
                "length": length,
                "out": blake2s(digest_size=length).hexdigest(),
               }
        fd.write(json.dumps(test, indent=True)+(',' if i<31 else '')+'\n')

    fd.write(']')
    fd.close()

def write_blake2b_tests(output_fn):
    fd = open(output_fn, 'w')

    key_bytes = bytearray(range(32))

    fd.write('[\n')
    for i in range(8):
        salt_bytes = bytearray(range(i+1))
        test = {
                "hash": "blake2b",
                "in": "",
                "key": key_bytes.hex(),
                "persona": "",
                "salt": salt_bytes.hex(),
                "out": blake2b(key=key_bytes, salt=salt_bytes).hexdigest()
               }
        fd.write(json.dumps(test, indent=True)+',\n')

    for i in range(8):
        persona_bytes = bytearray(range(i+1))
        test = {
                "hash": "blake2b",
                "in": "",
                "key": key_bytes.hex(),
                "persona": persona_bytes.hex(),
                "salt": "",
                "out": blake2b(key=key_bytes, person=persona_bytes).hexdigest()
               }
        fd.write(json.dumps(test, indent=True)+(',' if i<7 else '')+'\n')

    fd.write(']')
    fd.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: gen_vectors.py <path to blake2s output file> <path to blake2b output file>")
        sys.exit(1)
    write_blake2s_tests(sys.argv[1])
    write_blake2b_tests(sys.argv[2])


