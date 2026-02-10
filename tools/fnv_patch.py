#!/usr/bin/env python3
"""
Fallout New Vegas Binary Patch Tool v3
Handles the full pipeline: Steam DRM removal, LAA, and stability patches.
Based on community research from NVTF, NVAC, JIP LN NVSE.

Compatibility: All patches are designed to coexist with NVSE, NVAC, NVTF,
JIP LN NVSE. Hash table patches will be safely overridden by NVTF at runtime
if installed. Code cave patches use addresses not hooked by community mods.
"""

import struct
import shutil
import subprocess
import sys
import os
import platform


class FNVPatcher:
    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.data = None
        self.image_base = 0x00400000
        self.sections = []
        self.section_headers_offset = 0
        self.pe_offset = 0
        self.patches_applied = []
        self.patches_skipped = []
        # Code cave pointer (VA in .reloc section zeroes)
        self.cave_va = 0x013F36A8
        self.cave_used = 0

    def load(self):
        with open(self.exe_path, 'rb') as f:
            self.data = bytearray(f.read())
        self._parse_pe()
        print(f"Loaded: {self.exe_path} ({len(self.data)} bytes)")
        print(f"Image base: 0x{self.image_base:08X}")
        print(f"Sections: {len(self.sections)}")
        print()

    def _parse_pe(self):
        self.pe_offset = struct.unpack_from('<I', self.data, 0x3C)[0]
        assert self.data[self.pe_offset:self.pe_offset+4] == b'PE\x00\x00'

        num_sections = struct.unpack_from('<H', self.data, self.pe_offset + 6)[0]
        opt_header_size = struct.unpack_from('<H', self.data, self.pe_offset + 20)[0]
        self.image_base = struct.unpack_from('<I', self.data, self.pe_offset + 52)[0]

        self.section_headers_offset = self.pe_offset + 24 + opt_header_size
        for i in range(num_sections):
            off = self.section_headers_offset + i * 40
            name = self.data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            virt_size = struct.unpack_from('<I', self.data, off + 8)[0]
            virt_addr = struct.unpack_from('<I', self.data, off + 12)[0]
            raw_size = struct.unpack_from('<I', self.data, off + 16)[0]
            raw_offset = struct.unpack_from('<I', self.data, off + 20)[0]
            chars = struct.unpack_from('<I', self.data, off + 36)[0]
            self.sections.append({
                'name': name, 'virt_addr': virt_addr, 'virt_size': virt_size,
                'raw_offset': raw_offset, 'raw_size': raw_size,
                'chars': chars, 'header_offset': off
            })

    def va_to_offset(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s['virt_addr'] <= rva < s['virt_addr'] + s['raw_size']:
                return rva - s['virt_addr'] + s['raw_offset']
        raise ValueError(f"VA 0x{va:08X} not found in any section")

    def read_u8(self, va):
        return self.data[self.va_to_offset(va)]

    def read_u32(self, va):
        return struct.unpack_from('<I', self.data, self.va_to_offset(va))[0]

    def read_bytes(self, va, length):
        off = self.va_to_offset(va)
        return bytes(self.data[off:off+length])

    def write_u8(self, va, value):
        self.data[self.va_to_offset(va)] = value & 0xFF

    def write_u32(self, va, value):
        struct.pack_into('<I', self.data, self.va_to_offset(va), value)

    def write_bytes(self, va, data):
        off = self.va_to_offset(va)
        for i, b in enumerate(data):
            self.data[off + i] = b

    def write_bytes_at_offset(self, file_offset, data):
        for i, b in enumerate(data):
            self.data[file_offset + i] = b

    def cave_alloc(self, size):
        """Allocate bytes from the code cave, returns the VA."""
        va = self.cave_va + self.cave_used
        self.cave_used += size
        return va

    def make_jmp_rel32(self, from_va, to_va):
        """Create a 5-byte JMP rel32 instruction."""
        next_va = from_va + 5
        rel = (to_va - next_va) & 0xFFFFFFFF
        return bytes([0xE9]) + struct.pack('<I', rel)

    def make_jcc_rel32(self, opcode_byte, from_va, to_va):
        """Create a 6-byte conditional jump (0F 8x rel32)."""
        next_va = from_va + 6
        rel = (to_va - next_va) & 0xFFFFFFFF
        return bytes([0x0F, opcode_byte]) + struct.pack('<I', rel)

    # ================================================================
    # PATCH METHODS
    # ================================================================

    def patch_laa(self):
        """Set the Large Address Aware flag in the PE header.

        Allows the 32-bit process to use up to 4GB of address space on 64-bit
        Windows, dramatically reducing out-of-memory crashes.
        """
        chars_offset = self.pe_offset + 0x16
        chars = struct.unpack_from('<H', self.data, chars_offset)[0]
        if chars & 0x0020:
            self.patches_skipped.append(
                f"  SKIP: LAA - already set (characteristics: 0x{chars:04X})")
            return False
        new_chars = chars | 0x0020
        struct.pack_into('<H', self.data, chars_offset, new_chars)
        self.patches_applied.append(
            f"  [OK] Large Address Aware: 0x{chars:04X} -> 0x{new_chars:04X}")
        return True

    def patch_hash_table(self, va, new_size, description):
        """Patch a hash table initial bucket count."""
        try:
            opcode = self.read_u8(va - 1)
            if opcode == 0x68:
                old_value = self.read_u32(va)
                if old_value >= new_size:
                    self.patches_skipped.append(
                        f"  SKIP: {description} @ 0x{va:08X} - already >= {new_size}")
                    return False
                self.write_u32(va, new_size)
                self.patches_applied.append(
                    f"  [OK] {description} @ 0x{va:08X}: {old_value} -> {new_size}")
                return True
            elif opcode == 0x6A:
                old_value = self.read_u8(va)
                if old_value & 0x80:
                    old_value = old_value - 256
                if new_size <= 127:
                    if old_value >= new_size:
                        self.patches_skipped.append(
                            f"  SKIP: {description} @ 0x{va:08X} - already >= {new_size}")
                        return False
                    self.write_u8(va, new_size & 0xFF)
                    self.patches_applied.append(
                        f"  [OK] {description} @ 0x{va:08X}: {old_value} -> {new_size} (imm8)")
                    return True
                else:
                    self.patches_skipped.append(
                        f"  SKIP: {description} @ 0x{va:08X} - imm8->imm32 needs runtime patch")
                    return False
            else:
                self.patches_skipped.append(
                    f"  SKIP: {description} @ 0x{va:08X} - opcode 0x{opcode:02X} not push")
                return False
        except Exception as e:
            self.patches_skipped.append(f"  SKIP: {description} @ 0x{va:08X} - {e}")
            return False

    def patch_reloc_executable(self):
        """Make .reloc section executable for code caves."""
        for s in self.sections:
            if '.reloc' in s['name']:
                chars_offset = s['header_offset'] + 36
                old_chars = struct.unpack_from('<I', self.data, chars_offset)[0]
                if old_chars & 0x20000000:
                    self.patches_skipped.append(
                        "  SKIP: .reloc already executable")
                    return True
                new_chars = old_chars | 0x20000000  # IMAGE_SCN_MEM_EXECUTE
                struct.pack_into('<I', self.data, chars_offset, new_chars)
                self.patches_applied.append(
                    f"  [OK] .reloc section executable @ file offset 0x{chars_offset:X}: "
                    f"0x{old_chars:08X} -> 0x{new_chars:08X}")
                return True
        self.patches_skipped.append("  SKIP: .reloc section not found")
        return False

    def patch_getbytype_loop_safety(self):
        """Add pointer validation to ExtraDataList::GetByType linked list traversal.

        ExtraDataList::GetByType (0x00410220) traverses BSExtraData linked list.
        The main crash vector: corrupt next pointers lead to access violations.

        Patch: Redirect the loop-back path through a code cave that validates
        the BSExtraData node before the next iteration:
        - Null check (original)
        - Alignment check (BSExtraData is always 4-byte aligned)
        - Type field range check (must be 0x00-0x92)
        - Next pointer alignment pre-check

        Compatibility: No community mod hooks 0x004102B6. NVAC uses SEH
        (doesn't modify this code). NVTF/JIP don't touch GetByType.
        """
        # Verify original bytes at patch point
        expected = bytes([0x89, 0x45, 0xF8, 0xEB, 0xC2])  # MOV [EBP-8],EAX; JMP -0x3E
        actual = self.read_bytes(0x004102B6, 5)
        if actual != expected:
            self.patches_skipped.append(
                f"  SKIP: GetByType loop @ 0x004102B6 - bytes mismatch "
                f"(expected {expected.hex()}, got {actual.hex()})")
            return False

        # Allocate code cave space
        cave_va = self.cave_alloc(48)  # 46 bytes needed, round up

        # Build code cave routine
        cave = bytearray()

        # MOV [EBP-0x8], EAX  (save next node - original instruction)
        cave += bytes([0x89, 0x45, 0xF8])          # offset 0x00 (3 bytes)

        # TEST EAX, EAX  (null check)
        cave += bytes([0x85, 0xC0])                 # offset 0x03 (2 bytes)

        # JZ exit_loop (offset 0x22 from cave start)
        # From next_instr (0x07) to exit_loop (0x22) = +0x1B
        cave += bytes([0x74, 0x1B])                 # offset 0x05 (2 bytes)

        # TEST AL, 3  (4-byte alignment check)
        cave += bytes([0xA8, 0x03])                 # offset 0x07 (2 bytes)

        # JNZ exit_loop
        # From next_instr (0x0B) to exit_loop (0x22) = +0x17
        cave += bytes([0x75, 0x17])                 # offset 0x09 (2 bytes)

        # CMP byte [EAX+4], 0x93  (type field must be < 0x93)
        cave += bytes([0x80, 0x78, 0x04, 0x93])     # offset 0x0B (4 bytes)

        # JAE exit_loop
        # From next_instr (0x11) to exit_loop (0x22) = +0x11
        cave += bytes([0x73, 0x11])                 # offset 0x0F (2 bytes)

        # MOV ECX, [EAX+8]  (peek at next pointer for pre-validation)
        cave += bytes([0x8B, 0x48, 0x08])           # offset 0x11 (3 bytes)

        # TEST ECX, ECX  (next pointer null?)
        cave += bytes([0x85, 0xC9])                 # offset 0x14 (2 bytes)

        # JZ continue_loop (null next is fine - end of list)
        # From next_instr (0x18) to continue_loop (0x1D) = +0x05
        cave += bytes([0x74, 0x05])                 # offset 0x16 (2 bytes)

        # TEST CL, 3  (next pointer alignment)
        cave += bytes([0xF6, 0xC1, 0x03])           # offset 0x18 (3 bytes)

        # JNZ exit_loop (unaligned next = corrupt)
        # From next_instr (0x1D) to exit_loop (0x22) = +0x05
        cave += bytes([0x75, 0x05])                 # offset 0x1B (2 bytes)

        # continue_loop: JMP 0x0041027D (back to original loop start)
        jmp_loopback = self.make_jmp_rel32(cave_va + 0x1D, 0x0041027D)
        cave += jmp_loopback                        # offset 0x1D (5 bytes)

        # exit_loop: MOV dword [EBP-8], 0 (clear corrupt node)
        cave += bytes([0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00])  # offset 0x22 (7 bytes)

        # JMP 0x004102BB (exit to Unlock and return)
        jmp_exit = self.make_jmp_rel32(cave_va + 0x29, 0x004102BB)
        cave += jmp_exit                            # offset 0x29 (5 bytes)

        assert len(cave) == 46, f"Cave code is {len(cave)} bytes, expected 46"

        # Write code cave
        self.write_bytes(cave_va, cave)

        # Write redirect at original code: replace 5 bytes at 0x004102B6
        redirect = self.make_jmp_rel32(0x004102B6, cave_va)
        self.write_bytes(0x004102B6, redirect)

        self.patches_applied.append(
            f"  [OK] ExtraDataList::GetByType loop safety @ 0x004102B6 -> cave 0x{cave_va:08X}")
        self.patches_applied.append(
            f"       Validates: null, alignment, type range (0-0x92), next ptr alignment")
        return True

    def patch_getbytype_frame_extension(self):
        """Extend GetByType stack frame for future counter support.

        Changes SUB ESP,0xC to SUB ESP,0x10 to add a spare local variable
        at [EBP-0x10]. This is a 1-byte change and fully safe.
        Compatible with all mods (no mod hooks the function prologue).
        """
        expected = self.read_u8(0x00410225)  # The 0x0C operand
        if expected != 0x0C:
            self.patches_skipped.append(
                f"  SKIP: GetByType frame extension - SUB ESP operand is 0x{expected:02X}, not 0x0C")
            return False
        self.write_u8(0x00410225, 0x10)
        self.patches_applied.append(
            f"  [OK] GetByType stack frame: SUB ESP,0xC -> SUB ESP,0x10 (spare local at EBP-0x10)")
        return True

    def patch_copylist_null_check(self):
        """Add null source check to ExtraDataList::CopyList.

        CopyList (0x00411EC0) dereferences param_2+4 to get the source head.
        If param_2 is null or invalid, it crashes. The decompiled code shows:
          if (param_2 != 0) { iStack_8 = *(param_2 + 4); ... }
        This is actually already null-checked, so this is a no-op verification.
        """
        self.patches_skipped.append(
            "  SKIP: CopyList null check - already has null check in vanilla code")
        return False

    def patch_lock_spincount_limit(self):
        """Reduce ExtraDataList::Lock spin count from 10001 to 2000.

        The Lock function at 0x0040FBF0 spins up to 0x2711 (10001) times
        before switching to a longer sleep. Reducing to 0x7D0 (2000) reduces
        CPU waste on contention while still being responsive.

        Compatibility: NVTF patches spin locks at BSSpinlock::Lock (0x40FC63),
        not at ExtraDataList::Lock, so this is compatible.
        """
        # The constant 0x2711 is at the CMP instruction in the lock loop
        # 0040FBF0 function: "if (uStack_64 < 0x2711)"
        # Search for the CMP instruction with 0x2711
        # CMP reg, 0x2711 would be 81 F? 11 27 00 00
        # Looking at the disassembly, it's likely CMP [EBP-offset], 0x2711
        try:
            # Search for 0x2711 as a 32-bit value near the Lock function
            for offset in range(0x0040FBF0, 0x0040FC50):
                try:
                    val = self.read_u32(offset)
                    if val == 0x00002711:
                        prev = self.read_u8(offset - 1)
                        # Should be part of a CMP instruction
                        if prev in (0x3D, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF):
                            # 81 Fx imm32 encoding
                            self.write_u32(offset, 0x000007D0)  # 2000
                            self.patches_applied.append(
                                f"  [OK] Lock spin count @ 0x{offset:08X}: 10001 -> 2000")
                            return True
                        # Also check for CMP EAX, imm32 (3D imm32)
                        if self.read_u8(offset - 1) == 0x00 and self.read_u8(offset - 2) in range(0x3D, 0x40):
                            pass  # not a match
                except:
                    pass
            self.patches_skipped.append(
                "  SKIP: Lock spin count - could not find 0x2711 constant in Lock function")
            return False
        except Exception as e:
            self.patches_skipped.append(f"  SKIP: Lock spin count - {e}")
            return False

    # ================================================================
    # MAIN PATCH ORCHESTRATOR
    # ================================================================

    def apply_all_patches(self):
        # ============================================================
        # 0. PE HEADER FIXES (LAA + code cave setup)
        # ============================================================
        print("[0] PE HEADER FIXES")
        print("-" * 50)
        self.patch_laa()
        self.patch_reloc_executable()

        # ============================================================
        # 1. HASH TABLE SIZE FIXES (from NVTF)
        # ============================================================
        print("\n[1] HASH TABLE SIZE FIXES (NVTF-compatible)")
        print("-" * 50)

        hash_patches = [
            (0x473F69, 5009,  "ONAM temp ID map"),
            (0x6B5C76, 10037, "NavMeshInfoMap"),
            (0x6B7A30, 2819,  "NavMeshInfoMap world NavMeshInfos"),
            (0x845558, 7057,  "BGSSaveLoadChangesMap"),
            (0x846FFB, 12049, "BGSSaveLoadGame FormID map (ctor)"),
            (0x848072, 12049, "BGSSaveLoadGame FormID map (loader)"),
            (0x84703E, 59,    "BGSSaveLoadGame worldspace FormID map"),
            (0x8470FA, 59,    "BGSSaveLoadGame changed FormID map"),
            (0x84AB60, 127,   "BGSSaveLoadGame expired cell map"),
            (0x544FA7, 41,    "TESObjectCELL animated refs"),
            (0x544FC9, 29,    "TESObjectCELL external emittance"),
            (0x582CA2, 127,   "TESWorldSpace fixed persistent refs"),
            (0x582CEF, 53,    "TESWorldSpace file offset map"),
            (0x583FF6, 1709,  "TESWorldSpace cell map (form loader)"),
            (0x582D64, 31,    "TESWorldSpace cell map (ctor)"),
            (0x587AC9, 43,    "TESWorldSpace overlapped multibounds"),
            (0x6C02F8, 127,   "NavMeshObstacleManager obstacle map"),
            (0x6C035F, 97,    "NavMeshObstacleManager obstacle data"),
            (0x6C0397, 97,    "NavMeshObstacleManager open doors"),
            (0x6C03AB, 89,    "NavMeshObstacleManager closed doors"),
            (0x6E13AF, 53,    "PathingLOSMap"),
            (0xAD9169, 113,   "BSAudioManager playing sounds"),
            (0xAD9189, 113,   "BSAudioManager playing sound infos"),
            (0xAD91CC, 41,    "BSAudioManager moving sounds"),
        ]

        for va, new_size, desc in hash_patches:
            self.patch_hash_table(va, new_size, desc)

        # ============================================================
        # 2. EXTRADATALIST::GETBYTYPE LOOP SAFETY (code cave)
        # The #1 crash source in FNV - corrupt linked list traversal.
        # Adds pointer validation without modifying traversal logic.
        # ============================================================
        print("\n[2] EXTRADATALIST CRASH PROTECTION (code cave)")
        print("-" * 50)
        self.patch_getbytype_loop_safety()
        self.patch_getbytype_frame_extension()

        # ============================================================
        # 3. LOCK SPIN COUNT OPTIMIZATION
        # ============================================================
        print("\n[3] THREADING OPTIMIZATION")
        print("-" * 50)
        self.patch_lock_spincount_limit()

        # ============================================================
        # 4. TRIPLE BUFFERING (from NVTF)
        # ============================================================
        print("\n[4] RENDERING FIXES")
        print("-" * 50)
        try:
            current = self.read_u8(0x1189464)
            if current == 1:
                self.write_u8(0x1189464, 2)
                self.patches_applied.append(
                    f"  [OK] Triple buffering @ 0x1189464: {current} -> 2")
            elif current == 2:
                self.patches_skipped.append("  SKIP: Triple buffering - already 2")
            else:
                self.patches_skipped.append(
                    f"  SKIP: Triple buffering - unexpected value {current}")
        except Exception as e:
            self.patches_skipped.append(f"  SKIP: Triple buffering - {e}")

        # ============================================================
        # SUMMARY
        # ============================================================
        print("\n" + "=" * 70)
        print("PATCH SUMMARY")
        print("=" * 70)

        print(f"\nApplied ({len(self.patches_applied)}):")
        for p in self.patches_applied:
            print(p)

        if self.patches_skipped:
            print(f"\nSkipped ({len(self.patches_skipped)}):")
            for p in self.patches_skipped:
                print(p)

        if self.cave_used > 0:
            print(f"\nCode cave used: {self.cave_used} bytes at VA 0x{self.cave_va:08X}")

        return len(self.patches_applied)

    def save(self, backup=True):
        if backup:
            backup_path = self.exe_path + '.pre-patch-backup'
            if not os.path.exists(backup_path):
                shutil.copy2(self.exe_path, backup_path)
                print(f"\nBackup saved to: {backup_path}")
            else:
                print(f"\nBackup already exists: {backup_path}")

        with open(self.exe_path, 'wb') as f:
            f.write(self.data)
        print(f"Patched executable saved: {self.exe_path}")


# ====================================================================
# STEAM DRM HANDLING
# ====================================================================

def is_steam_packed(exe_path):
    """Detect if an executable has Steam CEG DRM.

    Checks for the .bind section (Steam DRM overlay) and other signatures.
    Returns True if the exe appears to be Steam-packed.
    """
    with open(exe_path, 'rb') as f:
        # Check MZ header
        if f.read(2) != b'MZ':
            return False

        # Get PE offset
        f.seek(0x3C)
        pe_off = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_off)
        if f.read(4) != b'PE\x00\x00':
            return False

        # Read number of sections
        f.seek(pe_off + 6)
        num_sections = struct.unpack('<H', f.read(2))[0]

        # Read optional header size to find section headers
        f.seek(pe_off + 20)
        opt_header_size = struct.unpack('<H', f.read(2))[0]

        section_start = pe_off + 24 + opt_header_size
        for i in range(num_sections):
            off = section_start + i * 40
            f.seek(off)
            name = f.read(8).rstrip(b'\x00')
            if name == b'.bind':
                return True

    # Fallback: check for SteamStub signature bytes near entry point
    # The stub has characteristic patterns but .bind is the most reliable
    return False


def find_steamless():
    """Find Steamless CLI executable.

    Search order:
    1. tools/steamless/ relative to this script
    2. Same directory as the target exe
    3. Current working directory
    4. PATH
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    is_windows = platform.system() == 'Windows'

    # Possible filenames
    cli_names = ['Steamless.CLI.exe']
    if is_windows:
        cli_names.append('Steamless.CLI')

    # Search directories
    search_dirs = [
        os.path.join(script_dir, 'steamless'),
        script_dir,
        os.getcwd(),
    ]

    for d in search_dirs:
        for name in cli_names:
            path = os.path.join(d, name)
            if os.path.isfile(path):
                return path

    # Check PATH
    for name in cli_names:
        found = shutil.which(name)
        if found:
            return found

    return None


def unpack_steam_drm(exe_path, steamless_path=None):
    """Unpack Steam CEG DRM using Steamless.

    Args:
        exe_path: Path to the packed FalloutNV.exe
        steamless_path: Optional path to Steamless.CLI.exe

    Returns:
        Path to the unpacked exe, or None on failure.
    """
    unpacked_path = exe_path + '.unpacked.exe'

    # Already unpacked?
    if os.path.exists(unpacked_path):
        print(f"Found existing unpacked exe: {unpacked_path}")
        return unpacked_path

    if steamless_path is None:
        steamless_path = find_steamless()

    if steamless_path is None:
        print("ERROR: Steamless not found.")
        print()
        print("The game executable has Steam DRM that must be removed before patching.")
        print("Download Steamless from: https://github.com/atom0s/Steamless/releases")
        print()
        if platform.system() == 'Windows':
            print("Place Steamless.CLI.exe in one of:")
        else:
            print("Place Steamless.CLI.exe in one of (requires mono to run):")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"  {os.path.join(script_dir, 'steamless', '')}")
        print(f"  {os.getcwd()}{os.sep}")
        print(f"  Or anywhere in your PATH")
        print()
        print("Then run this tool again.")
        return None

    print(f"Using Steamless: {steamless_path}")
    print(f"Unpacking: {exe_path}")
    print()

    # Build command
    is_windows = platform.system() == 'Windows'
    if is_windows:
        cmd = [steamless_path, exe_path]
    else:
        # Linux/macOS: need mono to run .NET exe
        mono = shutil.which('mono')
        if mono is None:
            print("ERROR: mono not found. Install mono to run Steamless on Linux/macOS:")
            print("  Arch:   sudo pacman -S mono")
            print("  Ubuntu: sudo apt install mono-complete")
            print("  macOS:  brew install mono")
            return None

        # Steamless needs its plugin DLLs in the same directory
        steamless_dir = os.path.dirname(steamless_path)
        plugins_dir = os.path.join(steamless_dir, 'Plugins')
        if os.path.isdir(plugins_dir):
            # Copy plugin DLLs alongside CLI exe if not already there
            for dll in os.listdir(plugins_dir):
                if dll.endswith('.dll'):
                    src = os.path.join(plugins_dir, dll)
                    dst = os.path.join(steamless_dir, dll)
                    if not os.path.exists(dst):
                        shutil.copy2(src, dst)

        cmd = [mono, steamless_path, exe_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
    except FileNotFoundError as e:
        print(f"ERROR: Could not run Steamless: {e}")
        return None
    except subprocess.TimeoutExpired:
        print("ERROR: Steamless timed out after 120 seconds.")
        return None

    if os.path.exists(unpacked_path):
        print(f"Unpacked successfully: {unpacked_path}")
        return unpacked_path
    else:
        print("ERROR: Steamless did not produce an unpacked file.")
        print(f"Expected: {unpacked_path}")
        if result.returncode != 0:
            print(f"Steamless exited with code {result.returncode}")
        return None


# ====================================================================
# EXE DETECTION
# ====================================================================

def find_game_exe_cwd():
    """Check current directory for FalloutNV.exe (unpacked preferred)."""
    cwd = os.getcwd()
    unpacked = os.path.join(cwd, 'FalloutNV.exe.unpacked.exe')
    if os.path.isfile(unpacked):
        return unpacked
    packed = os.path.join(cwd, 'FalloutNV.exe')
    if os.path.isfile(packed):
        return packed
    return None


def main():
    print("=" * 70)
    print("FALLOUT NEW VEGAS BINARY PATCH TOOL v3")
    print("Compatible with NVSE, NVAC, NVTF, JIP LN NVSE")
    print("=" * 70)
    print()

    # Determine input exe
    if len(sys.argv) > 1:
        exe_path = sys.argv[1]
        if not os.path.exists(exe_path):
            print(f"Error: File not found: {exe_path}")
            sys.exit(1)
    else:
        exe_path = find_game_exe_cwd()
        if exe_path is None:
            print("Usage: fnv_patch.py <path/to/FalloutNV.exe>")
            print()
            print("Drag and drop your FalloutNV.exe onto this script, or pass the path")
            print("as an argument. The tool handles Steam DRM removal automatically.")
            sys.exit(1)
        print(f"Found in current directory: {exe_path}")

    # Check if we need to unpack Steam DRM
    if is_steam_packed(exe_path):
        print(f"\nSteam DRM detected in {os.path.basename(exe_path)}")
        unpacked = unpack_steam_drm(exe_path)
        if unpacked is None:
            sys.exit(1)
        exe_path = unpacked
        print()
    elif exe_path.endswith('.unpacked.exe'):
        print("Using unpacked exe (no Steam DRM)")
    else:
        # Not obviously packed, not obviously unpacked — just try to patch it
        print("No Steam DRM detected, proceeding with patching")

    print()

    patcher = FNVPatcher(exe_path)
    patcher.load()

    num_applied = patcher.apply_all_patches()

    if num_applied > 0:
        patcher.save()
        print(f"\n{num_applied} patches applied successfully!")
        print()
        print("Next steps:")
        game_dir = os.path.dirname(exe_path)
        original = os.path.join(game_dir, 'FalloutNV.exe')
        if os.path.isfile(original) and exe_path != original:
            print(f"  1. Backup:  rename {os.path.basename(original)} -> FalloutNV.exe.original")
            print(f"  2. Install: rename {os.path.basename(exe_path)} -> FalloutNV.exe")
            print(f"  3. Launch through Steam normally")
    else:
        print("\nNo patches were applied.")


if __name__ == '__main__':
    main()
