#!/usr/bin/env python3
"""
Generate a minimal Windows Boot Configuration Data (BCD) registry hive
for WinToGo UEFI boot. The BCD uses a 'locate' device type that
finds the Windows partition automatically.

Windows Registry Hive format (MS-RRF):
  - 512-byte "regf" file header
  - One or more 4096-byte "hbin" pages
  - Cells in pages: nk (key), vk (value), sk (security), lh (hash leaf)
  - All cell offsets are relative to START OF HIVE BINS DATA (incl. hbin headers)
"""
import struct, sys, uuid
from datetime import datetime, timezone

BOOTMGR_GUID = uuid.UUID("{9dea862c-5cdd-4e70-acc1-f32b344d4795}")
WINTOGO_GUID  = uuid.UUID("{b2721d73-1db4-4c62-bf78-c548a880142d}")

REGF_HDR_SIZE = 512
HBIN_HDR_SIZE = 32
HBIN_PAGE     = 4096
CELL_ALIGN    = 8
NOHIVE        = 0xFFFFFFFF  # null / not-present offset

REG_SZ     = 1
REG_BINARY = 3
REG_DWORD  = 4
REG_QWORD  = 11

FIXED_FILETIME = 0x01DA6745_79C0C000  # 2024-01-01 00:00 UTC


class Heap:
    """Allocates cells; tracks them relative to start of hive bins data."""
    def __init__(self):
        self.buf = bytearray()

    def _pos(self):
        """Current heap position as a hive-bins offset (HBIN_HDR_SIZE already added)."""
        return HBIN_HDR_SIZE + len(self.buf)

    def alloc(self, data: bytes) -> int:
        """Allocate a cell. Returns hive-bins offset (includes HBIN_HDR_SIZE)."""
        size = 4 + len(data)
        size = (size + CELL_ALIGN - 1) & ~(CELL_ALIGN - 1)
        off = self._pos()
        self.buf += struct.pack("<i", -size)           # negative = allocated
        self.buf += data
        self.buf += b"\x00" * (size - 4 - len(data))
        return off

    def patch_u32(self, hive_off: int, value: int):
        """Patch a uint32 at a hive-bins offset."""
        buf_off = hive_off - HBIN_HDR_SIZE
        struct.pack_into("<I", self.buf, buf_off, value)

    def build_pages(self) -> bytes:
        """Wrap buf in hbin pages and return complete hive-bins data."""
        page_data_size = HBIN_PAGE - HBIN_HDR_SIZE   # 4064 bytes per page
        # Pad heap to a multiple of page_data_size
        n = len(self.buf)
        remainder = n % page_data_size
        if remainder:
            pad = page_data_size - remainder
            if pad >= 8:
                # Free cell: size (positive) = pad, then zero body
                self.buf += struct.pack("<i", pad) + b"\x00" * (pad - 4)
            else:
                # Extend last cell: the last allocated cell's size field
                # is at the start of buf at the last alloc boundary.
                # Simpler: just add a minimum 8-byte free cell and overflow to next page.
                self.buf += b"\x00" * pad   # raw zero padding (not ideal but safe)
        cells = bytes(self.buf)
        pages = bytearray()
        num_pages = max(1, (len(cells) + page_data_size - 1) // page_data_size)
        for page_idx in range(num_pages):
            start = page_idx * page_data_size
            chunk = cells[start : start + page_data_size]
            if len(chunk) < page_data_size:
                chunk += b"\x00" * (page_data_size - len(chunk))
            hdr = struct.pack("<4sIIIIII",
                              b"hbin",
                              page_idx * HBIN_PAGE,
                              HBIN_PAGE,
                              0, 0,
                              FIXED_FILETIME & 0xFFFFFFFF,
                              FIXED_FILETIME >> 32)
            pages += hdr + chunk
        return bytes(pages)


# ─── Cell builders ────────────────────────────────────────────────────────────

def alloc_sk(h: Heap) -> int:
    """Minimal security descriptor shared by all keys."""
    # SECURITY_DESCRIPTOR: SE_SELF_RELATIVE, no owner/group/sacl/dacl
    sd = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 0)  # 20 bytes
    off = h.alloc(
        struct.pack("<HHII IH",
                    0x6b73,   # 'sk'
                    0,        # flags
                    NOHIVE,   # fwd_sk (filled below)
                    NOHIVE,   # bwd_sk
                    1,        # refcount
                    len(sd))  # security_descriptor_size
        + b"\x00\x02"         # spare
        + sd)
    # Patch fwd/bwd to point to self (circular list of one)
    h.patch_u32(off + 4,  off)   # fwd
    h.patch_u32(off + 8,  off)   # bwd
    return off


def alloc_vk(h: Heap, name: str, dtype: int, data: bytes) -> int:
    nb = name.encode("ascii")
    if len(data) <= 4:
        # inline: data stored in data_offset field, MSB of data_size set
        d32 = int.from_bytes(data.ljust(4, b"\x00"), "little")
        data_off  = d32
        data_size = len(data) | 0x80000000
    else:
        data_off  = h.alloc(data)
        data_size = len(data)
    flags = 0x0001 if name else 0x0000
    body = (struct.pack("<HHIIIHH", 0x6b76, len(nb), data_size, data_off, dtype, flags, 0)
            + nb)
    return h.alloc(body)


def alloc_lh(h: Heap, entries: list) -> int:
    """entries = [(child_nk_off, key_name_str), ...]"""
    body = struct.pack("<HH", 0x686c, len(entries))
    for off, name in entries:
        # Hash: XOR name chars shifted
        hv = 0
        for i, c in enumerate(name[:4].upper().encode("ascii", errors="replace")):
            hv ^= c << (i * 8)
        body += struct.pack("<II", off, hv)
    return h.alloc(body)


def alloc_vl(h: Heap, vk_offsets: list) -> int:
    """Value list: array of vk offsets."""
    return h.alloc(struct.pack("<" + "I" * len(vk_offsets), *vk_offsets))


def alloc_nk(h: Heap, name: str, sk_off: int, parent: int,
             subkeys: list, values: list, is_root=False) -> int:
    """
    Build and allocate a key node cell.
    subkeys = [(child_off, child_name), ...] or []
    values  = [vk_off, ...]
    Returns the hive-bins offset of this nk.
    """
    nb = name.encode("ascii")
    flags = 0x0020 if is_root else 0x0004

    lh_off = alloc_lh(h, subkeys) if subkeys else NOHIVE
    vl_off = alloc_vl(h, values)  if values  else NOHIVE

    body = struct.pack("<HHQIIIIIIIIIIIIIIIHH",
                       0x6b6e,            # 'nk'
                       flags,
                       FIXED_FILETIME,    # last_written (8 bytes = Q)
                       0,                 # virtualization_control
                       NOHIVE if is_root else parent,
                       len(subkeys),      # subkeys_count
                       0,                 # volatile_subkeys_count
                       lh_off,
                       NOHIVE,            # volatile lh
                       len(values),       # values_count
                       vl_off,
                       sk_off,
                       NOHIVE,            # class_name offset
                       0, 0, 0, 0,        # max name/data tracking × 4
                       0,                 # work_var
                       len(nb),
                       0)                 # class_name size
    return h.alloc(body + nb)


# ─── Device descriptors ──────────────────────────────────────────────────────

def dev_boot() -> bytes:
    """BCD device = 'boot' (the current boot device = the ESP)."""
    # type=0 (boot), no additional data
    return struct.pack("<II", 0, 0)


def dev_locate() -> bytes:
    """BCD device = 'locate' (find the Windows OS partition automatically).
    type=6, locate_type=0 (by element ID), element=0x21000001 (osdevice)."""
    return struct.pack("<IIII", 6, 0, 0, 0x21000001)


def guid_data(g: uuid.UUID) -> bytes:
    return g.bytes_le


def guid_list(*gs) -> bytes:
    return b"".join(g.bytes_le for g in gs)


def sz_data(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


# ─── Build the BCD hive ──────────────────────────────────────────────────────

def build_bcd():
    h = Heap()
    sk = alloc_sk(h)

    # ── Windows OS Loader ({WINTOGO_GUID}) ────────────────────────────────────
    vk_dev    = alloc_vk(h, "Element", REG_BINARY, dev_locate())
    vk_osdev  = alloc_vk(h, "Element", REG_BINARY, dev_locate())
    vk_path   = alloc_vk(h, "Element", REG_SZ, sz_data("\\Windows\\System32\\winload.efi"))
    vk_root   = alloc_vk(h, "Element", REG_SZ, sz_data("\\Windows"))
    vk_dhal   = alloc_vk(h, "Element", REG_BINARY, b"\x01")
    vk_winpe  = alloc_vk(h, "Element", REG_BINARY, b"\x00")

    nk_e_11 = alloc_nk(h, "11000001", sk, NOHIVE, [], [vk_dev])
    nk_e_21 = alloc_nk(h, "21000001", sk, NOHIVE, [], [vk_osdev])
    nk_e_2a = alloc_nk(h, "22000001", sk, NOHIVE, [], [vk_path])
    nk_e_2b = alloc_nk(h, "22000002", sk, NOHIVE, [], [vk_root])
    nk_e_dh = alloc_nk(h, "26000010", sk, NOHIVE, [], [vk_dhal])
    nk_e_wp = alloc_nk(h, "26000022", sk, NOHIVE, [], [vk_winpe])

    vk_type_w = alloc_vk(h, "Type", REG_DWORD, struct.pack("<I", 0x10200003))

    nk_desc_w = alloc_nk(h, "Description", sk, NOHIVE, [], [vk_type_w])
    nk_elem_w = alloc_nk(h, "Elements",    sk, NOHIVE,
                          [(nk_e_11, "11000001"), (nk_e_21, "21000001"),
                           (nk_e_2a, "22000001"), (nk_e_2b, "22000002"),
                           (nk_e_dh, "26000010"), (nk_e_wp, "26000022")], [])

    wintogo_name = "{" + str(WINTOGO_GUID).upper() + "}"
    nk_wintogo   = alloc_nk(h, wintogo_name, sk, NOHIVE,
                             [(nk_desc_w, "Description"), (nk_elem_w, "Elements")], [])

    # Patch parent refs for wintogo subtree
    for child in [nk_e_11, nk_e_21, nk_e_2a, nk_e_2b, nk_e_dh, nk_e_wp]:
        h.patch_u32(child + 4 + 2 + 2 + 8 + 4, nk_elem_w)   # parent field
    h.patch_u32(nk_desc_w + 4 + 2 + 2 + 8 + 4, nk_wintogo)
    h.patch_u32(nk_elem_w + 4 + 2 + 2 + 8 + 4, nk_wintogo)

    # ── Boot Manager ({BOOTMGR_GUID}) ─────────────────────────────────────────
    vk_bm_dev  = alloc_vk(h, "Element", REG_BINARY, dev_boot())
    vk_bm_path = alloc_vk(h, "Element", REG_SZ,
                           sz_data("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"))
    vk_bm_dord = alloc_vk(h, "Element", REG_BINARY, guid_list(WINTOGO_GUID))
    vk_bm_def  = alloc_vk(h, "Element", REG_BINARY, guid_data(WINTOGO_GUID))
    vk_bm_to   = alloc_vk(h, "Element", REG_QWORD,  struct.pack("<Q", 30))

    nk_m_11 = alloc_nk(h, "11000001", sk, NOHIVE, [], [vk_bm_dev])
    nk_m_12 = alloc_nk(h, "12000002", sk, NOHIVE, [], [vk_bm_path])
    nk_m_24 = alloc_nk(h, "24000001", sk, NOHIVE, [], [vk_bm_dord])
    nk_m_25 = alloc_nk(h, "25000004", sk, NOHIVE, [], [vk_bm_def])
    nk_m_45 = alloc_nk(h, "45000001", sk, NOHIVE, [], [vk_bm_to])

    vk_type_m = alloc_vk(h, "Type", REG_DWORD, struct.pack("<I", 0x10100002))

    nk_desc_m = alloc_nk(h, "Description", sk, NOHIVE, [], [vk_type_m])
    nk_elem_m = alloc_nk(h, "Elements",    sk, NOHIVE,
                          [(nk_m_11, "11000001"), (nk_m_12, "12000002"),
                           (nk_m_24, "24000001"), (nk_m_25, "25000004"),
                           (nk_m_45, "45000001")], [])

    bootmgr_name = "{" + str(BOOTMGR_GUID).upper() + "}"
    nk_bootmgr   = alloc_nk(h, bootmgr_name, sk, NOHIVE,
                             [(nk_desc_m, "Description"), (nk_elem_m, "Elements")], [])

    for child in [nk_m_11, nk_m_12, nk_m_24, nk_m_25, nk_m_45]:
        h.patch_u32(child + 4 + 2 + 2 + 8 + 4, nk_elem_m)
    h.patch_u32(nk_desc_m + 4 + 2 + 2 + 8 + 4, nk_bootmgr)
    h.patch_u32(nk_elem_m + 4 + 2 + 2 + 8 + 4, nk_bootmgr)

    # ── Objects key ───────────────────────────────────────────────────────────
    nk_objects = alloc_nk(h, "Objects", sk, NOHIVE,
                           [(nk_bootmgr, bootmgr_name), (nk_wintogo, wintogo_name)], [])
    h.patch_u32(nk_bootmgr + 4 + 2 + 2 + 8 + 4, nk_objects)
    h.patch_u32(nk_wintogo + 4 + 2 + 2 + 8 + 4, nk_objects)

    # ── Root key BCD00000000 ──────────────────────────────────────────────────
    nk_root = alloc_nk(h, "BCD00000000", sk, NOHIVE,
                        [(nk_objects, "Objects")], [], is_root=True)
    h.patch_u32(nk_objects + 4 + 2 + 2 + 8 + 4, nk_root)

    # ── Assemble the file ─────────────────────────────────────────────────────
    hbins = h.build_pages()

    # regf header
    hdr = bytearray(REGF_HDR_SIZE)
    struct.pack_into("<4sIIQIIII", hdr, 0,
                     b"regf", 1, 1, FIXED_FILETIME, 1, 6, 0, 0)
    struct.pack_into("<I", hdr, 36, nk_root)          # root cell offset
    struct.pack_into("<I", hdr, 40, len(hbins))       # hbins data size
    # checksum = XOR of first 127 DWORDs
    ck = 0
    for i in range(127):
        ck ^= struct.unpack_from("<I", hdr, i*4)[0]
    struct.pack_into("<I", hdr, 508, ck)

    return bytes(hdr) + hbins


def emit_c(data: bytes) -> str:
    lines = [
        "/* Minimal WinToGo BCD template — generated by gen_bcd_template.py */",
        "/* DO NOT EDIT MANUALLY */",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "const uint8_t wintogo_bcd_template[] = {",
    ]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    lines.append(f"const size_t wintogo_bcd_template_len = {len(data)};")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    hive = build_bcd()
    assert hive[:4] == b"regf", "regf sig missing"
    assert hive[REGF_HDR_SIZE:REGF_HDR_SIZE+4] == b"hbin", "hbin sig missing"
    root_off = struct.unpack_from("<I", hive, 36)[0]
    root_cell = REGF_HDR_SIZE + root_off
    assert hive[root_cell:root_cell+2] == b"nk", f"root nk body not at {root_cell}"
    print(f"Generated BCD hive: {len(hive)} bytes", file=sys.stderr)
    if "--binary" in sys.argv:
        sys.stdout.buffer.write(hive)
    else:
        print(emit_c(hive))
