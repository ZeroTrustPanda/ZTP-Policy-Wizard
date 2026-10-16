#!/usr/bin/env python3
"""
Ad-hoc code-sign a thin 64-bit Mach-O executable from any OS (no Apple tools needed).

Why: Bun's cross-compiled macOS binaries carry a signature that no longer matches the
final file (arm64: last page hash stale; x64: Bun's original Developer ID signature).
Apple Silicon refuses to run code whose signature doesn't match, so we replace it with a
fresh ad-hoc signature - the same thing `codesign --force --sign - <file>` produces.
This is NOT a Developer ID signature: Gatekeeper still asks the user to confirm on
first launch (right-click -> Open).

Usage: python3 adhoc-sign.py <binary> [identifier]
"""
import hashlib
import struct
import sys

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
PAGE = 4096
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CS_ADHOC = 0x2
CS_EXECSEG_MAIN_BINARY = 0x1


def sign(path, ident):
    b = bytearray(open(path, 'rb').read())
    magic, cputype = struct.unpack_from('<Ii', b, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit(f'{path}: not a thin 64-bit Mach-O (magic {magic:#x})')
    ncmds, sizeofcmds = struct.unpack_from('<II', b, 16)
    off = 32
    sig_cmd = linkedit = text = None
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from('<II', b, off)
        if cmd == LC_CODE_SIGNATURE:
            sig_cmd = off
        elif cmd == LC_SEGMENT_64:
            name = bytes(b[off + 8:off + 24]).rstrip(b'\0')
            if name == b'__LINKEDIT':
                linkedit = off
            elif name == b'__TEXT':
                text = off
        off += cs
    if sig_cmd is None or linkedit is None or text is None:
        raise SystemExit(f'{path}: missing LC_CODE_SIGNATURE / __LINKEDIT / __TEXT')

    code_limit = struct.unpack_from('<I', b, sig_cmd + 8)[0]  # signature starts here; everything before is code
    if code_limit % 16:
        raise SystemExit('signature offset not 16-byte aligned')
    n_code = (code_limit + PAGE - 1) // PAGE
    ident_b = ident.encode() + b'\0'
    n_special = 2  # -1 Info.plist (none), -2 requirements
    cd_header = 88  # CodeDirectory version 0x20400
    hash_offset = cd_header + len(ident_b) + n_special * 32
    cd_len = hash_offset + n_code * 32
    req_blob = struct.pack('>III', CSMAGIC_REQUIREMENTS, 12, 0)
    cms_blob = struct.pack('>II', CSMAGIC_BLOBWRAPPER, 8)
    sb_header = 12 + 3 * 8
    sig_len = sb_header + cd_len + len(req_blob) + len(cms_blob)
    sig_len_padded = (sig_len + 15) // 16 * 16

    # Point the load commands at the new signature size before hashing (page 0 holds them)
    struct.pack_into('<I', b, sig_cmd + 12, sig_len_padded)
    le_fileoff = struct.unpack_from('<Q', b, linkedit + 40)[0]
    le_filesize = code_limit + sig_len_padded - le_fileoff
    struct.pack_into('<Q', b, linkedit + 48, le_filesize)  # filesize
    seg_align = 0x4000
    struct.pack_into('<Q', b, linkedit + 32, (le_filesize + seg_align - 1) // seg_align * seg_align)  # vmsize
    del b[code_limit:]

    text_fileoff, text_filesize = struct.unpack_from('<QQ', b, text + 40)
    code_hashes = b''.join(hashlib.sha256(bytes(b[i * PAGE:min((i + 1) * PAGE, code_limit)])).digest() for i in range(n_code))
    # Special slots are stored from the most negative index up to -1:
    # slot -2 = hash of the requirements blob, slot -1 = Info.plist (none -> zeros)
    special = hashlib.sha256(req_blob).digest() + b'\0' * 32
    cd = struct.pack('>IIIIIIIII', CSMAGIC_CODEDIRECTORY, cd_len, 0x20400, CS_ADHOC, hash_offset, cd_header,
                     n_special, n_code, code_limit)
    cd += struct.pack('>BBBB', 32, 2, 0, 12)          # hashSize, hashType sha256, platform, pageSize 2^12
    cd += struct.pack('>IIII', 0, 0, 0, 0)             # spare2, scatterOffset, teamOffset, spare3
    cd += struct.pack('>Q', 0)                         # codeLimit64
    cd += struct.pack('>QQQ', text_fileoff, text_filesize, CS_EXECSEG_MAIN_BINARY)
    assert len(cd) == cd_header
    cd += ident_b + special + code_hashes
    assert len(cd) == cd_len

    idx = [(0, sb_header), (2, sb_header + cd_len), (0x10000, sb_header + cd_len + len(req_blob))]
    sb = struct.pack('>III', CSMAGIC_EMBEDDED_SIGNATURE, sig_len, 3) + b''.join(struct.pack('>II', t, o) for t, o in idx)
    sb += cd + req_blob + cms_blob
    sb += b'\0' * (sig_len_padded - len(sb))
    b += sb
    open(path, 'wb').write(b)
    print(f'[adhoc-sign] {path}: {n_code} pages, identifier {ident}, signature {sig_len} bytes')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    sign(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'com.zerotrustpanda.ztp-wizard')
