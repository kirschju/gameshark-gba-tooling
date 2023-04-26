#!/usr/bin/env python3

import sys

# Helper script to get past the "Please move the switch to the right" message
# displayed by the Action Replay ROM. Tested against versions 3.3 and 3.6 only.

def patch(dat):
    # Patch return value of function checking switch state
    BYTES = b"\x00\x23\x06\x48\x02\x88\xf0\x21"
    assert BYTES in dat, "magic sequence not found"
    assert dat.count(BYTES) == 1, "magic sequence found more than once"

    # mov r3, 0x00 -> mov r3, 0x01
    dat = bytearray(dat)
    off = dat.find(BYTES)
    dat[off:off+2] = int.to_bytes(0x2301, 2, "little")
    return bytes(dat)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ar-rom>")
        sys.exit(-1)

    out = patch(open(sys.argv[1], "rb").read())
    open("action_replay_patched.gba", "wb").write(out)
