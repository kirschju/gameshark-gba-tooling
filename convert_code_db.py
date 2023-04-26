#!/usr/bin/env python3

import os
import sys
import json
import struct
import pprint
import arcrypt

u = lambda f, x: struct.unpack(f, x)
p = lambda f, *args: struct.pack(f, *args)

u32 = lambda x: u("<I", x)[0]
p32 = lambda x: p("<I", x)

def from_blob(dat):
    res = {}
    num_games, num_cheats = u("<II", dat[:8])
    ptr = 8
    res['games'] = []
    for i in range(num_games):
        gam = {'id': None, 'm': None}
        num_cheats = u32(dat[ptr:ptr+4])
        ptr += 4
        gam['name'] = dat[ptr:ptr+0x14].decode('latin-1').strip()
        ptr += 0x14
        gam['cheats'] = []
        for j in range(num_cheats):
            cht = {}
            tmp = u32(dat[ptr:ptr+4])
            cht['flags'], num_codes = tmp >> 30, tmp & 0x7ffffff
            ptr += 4
            cht['name'] = dat[ptr:ptr+0x14].decode('latin-1').strip()
            ptr += 0x14
            codes = u("<{}I".format(num_codes), dat[ptr:ptr+num_codes*4])
            codes = map(lambda x: "{:08x}".format(x), codes)
            codes = list(codes)
            cht['codes'] = [" ".join(codes[i:i+2]) for i in range(0, len(codes), 2)]
            seeds = arcrypt.seed(0)
            dec = []
            for c in cht['codes']:
                a, v = arcrypt.decrypt(seeds, (int(c.split(" ")[0], 16), int(c.split(" ")[1], 16)))
                if a == 0xdeadface:
                    arcrypt.seed(v)
                    continue
                if v == 0x001dc0de:
                    gam['id'] = p32(a).decode()
                if a & 0xff000000 == 0xc4000000 and cht['name'].lower() == "(m)":
                    gam['m'] = "{:08x} {:08x}".format(a, v)
                    cht['name'] = '(m)'
                dec.append("{:08x} {:08x}".format(a, v))
            cht['decrypted'] = dec
            ptr += num_codes * 4
            gam['cheats'].append(cht)
        if gam['id'] and gam['m'] is not None:
            res['games'].append(gam)
    return res

def to_blob(d):
    num_games = len(d["games"])
    num_cheats = 0
    res = b""
    for g in d["games"]:
        num_cheats += len(g["cheats"])
    res += p("<II", num_games, num_cheats)

    for g in d["games"]:
        num_cheats = 0
        res += p32(len(g["cheats"]))
        res += g["name"].encode("latin-1").ljust(0x14, b" ")[:0x14]
        for cht in g["cheats"]:
            res += p32((len(cht["codes"]) * 2) | (cht["flags"] << 30))
            res += cht["name"].encode("latin-1").ljust(0x14, b" ")[:0x14]
            for c in cht["codes"]:
                res += p("<II", *map(lambda x: int(x, 16), c.split(" ")))

    return res

def print_usage():
    print("Usage: {} [-j|-b] <file>".format(sys.argv[0]))
    print("  -j Convert to JSON")
    print("  -b Convert to flashable blob")
    sys.exit(-1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print_usage()

    if sys.argv[1] == "-j":
        d = from_blob(open(sys.argv[2], 'rb').read())
        if not sys.argv[2].endswith(".ardb"):
            sys.argv[2] += ".ardb"
        open(sys.argv[2].replace(".ardb", ".json"), "w").write(json.dumps(d))
        pprint.pprint(d)
    elif sys.argv[1] == "-b":
        d = json.loads(open(sys.argv[2], "r").read())
        if not sys.argv[2].endswith(".json"):
            sys.argv[2] += ".json"
        dat = to_blob(d)
        open(sys.argv[2].replace(".json", ".ardb"), "wb").write(dat)
    else:
        print("Unknown operation {}".format(sys.argv[1]))
        print_usage()
