# New New Vegas

Static binary patches for Fallout: New Vegas to fix crashes, improve stability, and optimize performance — without requiring runtime mod loaders.

## Overview

Fallout: New Vegas is notoriously unstable. The modding community has spent over a decade identifying crash sites and developing fixes through NVSE plugins (NVAC, NVTF, JIP LN NVSE). This project takes a different approach: **applying fixes directly to the executable** as static binary patches.

This means you get crash protection and performance improvements **without needing NVSE or any mod loader installed**. The patches are also fully compatible with community mods if you choose to use them.

### What's Included

| Patch Category | Count | Description |
|----------------|-------|-------------|
| Large Address Aware | 1 | Doubles usable memory from 2GB to 4GB |
| Hash Table Resizing | 20 | Prevents freeze/crash from hash collisions |
| ExtraDataList Crash Protection | 2 | Code cave validates linked list nodes before traversal |
| Triple Buffering | 1 | Smoother frame delivery |
| Code Cave Infrastructure | 1 | Makes .reloc section executable for patch routines |

| Steam DRM Removal | auto | Detects and unpacks Steam CEG via Steamless |

**Total: 26+ patches applied in seconds**

## The Problem

Fallout: New Vegas ships with several classes of bugs:

### Hash Table Collisions
The game initializes many hash tables with tiny bucket counts (as low as 37). As gameplay progresses and tables fill up, lookups degrade from O(1) to O(n), causing stutters, freezes, and eventually crashes. Our patches increase bucket counts to prime numbers optimized for each table's typical load.

### ExtraDataList Corruption (The #1 Crash)
Every game object carries an `ExtraDataList` — a linked list of `BSExtraData` nodes storing runtime properties (health, ownership, scripts, etc.). The `GetByType` function traverses this list ~421 call sites throughout the engine. When a node becomes corrupt (use-after-free, heap corruption), the traversal follows a garbage pointer and crashes.

Our code cave patch intercepts every loop iteration and validates:
- **Null check** — standard end-of-list detection
- **Alignment check** — BSExtraData is always 4-byte aligned; unaligned = corrupt
- **Type range check** — the type field must be 0x00–0x92; anything else = corrupt
- **Next pointer pre-validation** — checks the next node before following it

If any check fails, the loop exits safely instead of crashing.

### Memory Exhaustion
The vanilla 32-bit executable can only address 2GB of memory. The LAA (Large Address Aware) patch sets the PE header flag that allows the process to use up to 4GB on 64-bit Windows, dramatically reducing out-of-memory crashes.

## Quick Start

### Prerequisites

- Fallout: New Vegas (Steam version)
- [Steamless](https://github.com/atom0s/Steamless) v3.1+ (to remove Steam DRM wrapper)
- Python 3.8+

### Step 1: Download Steamless

The game executable is wrapped in Steam CEG DRM which encrypts the `.text` section. The patch tool calls Steamless automatically to remove it.

Download [Steamless CLI](https://github.com/atom0s/Steamless/releases) and place `Steamless.CLI.exe` (and its `Plugins/` folder) in one of:
- `tools/steamless/` (next to `fnv_patch.py`)
- The same directory as `FalloutNV.exe`
- Anywhere in your PATH

On Linux/macOS you'll also need [Mono](https://www.mono-project.com/) installed to run Steamless.

### Step 2: Run the Patch Tool

```bash
python3 tools/fnv_patch.py "path/to/FalloutNV.exe"
```

The tool automatically:
1. Detects Steam DRM and runs Steamless to unpack the exe
2. Applies the LAA (Large Address Aware) patch
3. Applies all stability patches (hash tables, code cave, etc.)
4. Backs up the original (`.pre-patch-backup`)
5. Reports every patch applied/skipped with reasons

If `FalloutNV.exe` is in the current directory, you can just run:
```bash
python3 tools/fnv_patch.py
```

### Step 3: Install

```bash
cd "path/to/Fallout New Vegas/"
mv FalloutNV.exe FalloutNV.exe.steam-original
mv FalloutNV.exe.unpacked.exe FalloutNV.exe
```

Launch through Steam normally.

## Patch Details

### Hash Table Size Fixes

Based on [New Vegas Tick Fix (NVTF)](https://github.com/carxt/New-Vegas-Tick-Fix) research. Each patch changes the initial bucket count argument in a hash table constructor call.

| Address | Structure | Old | New | Impact |
|---------|-----------|-----|-----|--------|
| `0x473F69` | ONAM temp ID map | 1001 | 5009 | Save/load performance |
| `0x6B5C76` | NavMeshInfoMap | 10009 | 10037 | Navigation stability |
| `0x845558` | BGSSaveLoadChangesMap | 5039 | 7057 | Save game reliability |
| `0x846FFB` | FormID map (constructor) | 5039 | 12049 | Save/load speed |
| `0x848072` | FormID map (loader) | 5039 | 12049 | Save/load speed |
| `0x84703E` | Worldspace FormID map | 37 | 59 | Cell loading |
| `0x8470FA` | Changed FormID map | 37 | 59 | Change tracking |
| `0x84AB60` | Expired cell map | 37 | 127 | Cell cleanup |
| `0x544FA7` | Cell animated refs | 37 | 41 | Animation stability |
| `0x582CA2` | Fixed persistent refs | 37 | 127 | World loading |
| `0x582CEF` | File offset map | 37 | 53 | File I/O |
| `0x583FF6` | Cell map (form loader) | 701 | 1709 | World loading |
| `0x587AC9` | Overlapped multibounds | 37 | 43 | Collision |
| `0x6C02F8` | Obstacle map | 37 | 127 | Pathfinding |
| `0x6C035F` | Obstacle data map | 37 | 97 | Pathfinding |
| `0x6C0397` | Open doors map | 37 | 97 | Navigation |
| `0x6C03AB` | Closed doors map | 37 | 89 | Navigation |
| `0x6E13AF` | PathingLOSMap | 37 | 53 | Line of sight |
| `0xAD9169` | Playing sounds | 37 | 113 | Audio stability |
| `0xAD9189` | Playing sound infos | 37 | 113 | Audio stability |
| `0xAD91CC` | Moving sounds | 37 | 41 | Audio stability |

### ExtraDataList Code Cave

A 46-byte x86 routine injected into unused space in the `.reloc` section (VA `0x013F36A8`). The original loop-back instruction at `0x004102B6` is redirected through this validation routine.

```
Original:  MOV [EBP-8], EAX  →  JMP [code_cave]
           JMP loop_start

Code Cave: MOV [EBP-8], EAX      ; save next node (original)
           TEST EAX, EAX          ; null?
           JZ exit_loop
           TEST AL, 3             ; 4-byte aligned?
           JNZ exit_loop
           CMP byte [EAX+4], 0x93 ; type in range?
           JAE exit_loop
           MOV ECX, [EAX+8]       ; peek next pointer
           TEST ECX, ECX
           JZ continue_loop        ; null next is OK
           TEST CL, 3             ; next aligned?
           JNZ exit_loop
    continue_loop:
           JMP loop_start          ; resume normal traversal
    exit_loop:
           MOV [EBP-8], 0         ; clear corrupt pointer
           JMP unlock_and_return   ; safe exit
```

### Key Reverse Engineering Findings

These addresses were identified through Ghidra analysis of the unpacked binary:

| Address | Function | Xrefs | Purpose |
|---------|----------|-------|---------|
| `0x00410220` | `ExtraDataList::GetByType` | 421 | Linked list traversal (crash-prone) |
| `0x0044DDC0` | `BSExtraData::GetNext` | 2071 | Returns `*(this+8)` — next pointer |
| `0x004F1540` | `BSExtraData::GetType` | — | Returns `*(this+4)` — type byte |
| `0x00403550` | `BSExtraData::SetNext` | — | Sets `*(this+8)` |
| `0x0040EC80` | `BSExtraData::BSExtraData(type)` | — | Constructor |
| `0x0040FE80` | `ExtraDataList::HasType` | — | Presence bitfield check |
| `0x0040FBF0` | `ExtraDataList::Lock` | — | Spinlock (up to 10001 iterations) |
| `0x0040FBA0` | `ExtraDataList::Unlock` | — | Release lock |
| `0x00411EC0` | `ExtraDataList::CopyList` | — | Deep copy of extra data |
| `0x00401000` | Memory allocator | 3140 | Custom heap wrapper |
| `0x0086A850` | `WinMain` | — | Game entry point |
| `0x0086E650` | Main frame update | — | Per-frame render/update |

#### BSExtraData Layout (12 bytes)
```
+0x00  vtable pointer (4 bytes) → 0x01014210
+0x04  type byte (1 byte, range 0x00–0x92)
+0x05  padding (3 bytes)
+0x08  next pointer (4 bytes) → BSExtraData* or NULL
```

#### ExtraDataList Layout
```
+0x00  unknown (4 bytes, not a vtable)
+0x04  head pointer (4 bytes) → BSExtraData* linked list head
+0x08  presenceBitfield (21 bytes) → tracks which types are present
```

## Community Mod Compatibility

All patches are designed to coexist with the standard FNV stability mod stack:

| Mod | Compatibility | Notes |
|-----|--------------|-------|
| **NVSE / xNVSE** | Full | Script extender loads alongside our patches |
| **NVAC** | Full | NVAC adds SEH handlers at ~70 crash sites; our code cave is at an address NVAC doesn't touch |
| **NVTF** | Full | NVTF's runtime `SafeWrite` calls override our hash table values with identical or better ones |
| **JIP LN NVSE** | Full | JIP hooks ~100 addresses; none overlap with our patches |

**Recommended**: Install all four mods for maximum stability. Our static patches provide a baseline, and the runtime mods add protections that can't be done statically (SEH crash recovery, timing fixes, threading optimizations, D3D hooks).

## What Can't Be Static-Patched

~230 crash sites identified by the community require runtime code injection:

- **SEH exception handlers** (NVAC) — catching access violations at 70+ crash sites requires registering OS-level exception handlers at runtime
- **Function hooks** (JIP LN) — replacing entire functions with fixed versions needs runtime memory modification
- **API interception** (NVTF) — redirecting `GetTickCount`, D3D calls, and threading primitives requires DLL injection
- **Script engine fixes** (xNVSE) — patching the scripting system requires hooking into NVSE's plugin infrastructure

## Ghidra Analysis Setup

To reproduce the reverse engineering work or extend it:

```bash
# 1. Run headless analysis (requires Ghidra 12.0+)
# Use the included wrapper script with 8GB heap
tools/analyzeHeadless /path/to/project ProjectName \
    -import FalloutNV.exe.unpacked.exe \
    -overwrite

# 2. Results: 16,040 functions, 26,796 symbols, 1000+ RTTI classes
# 3. Use Ghidra MCP bridge for AI-assisted analysis
```

The binary contains MSVC RTTI type descriptors for 120+ BSExtraData subclasses and extensive debug strings (`ExtraDataList::CopyList`, `ExtraDataList::RemoveAllCopyableExtra`, etc.) that aid in function identification.

## Project Structure

```
New-New-Vegas/
├── README.md              # This file
├── tools/
│   ├── fnv_patch.py       # Main patching tool (all patches)
│   └── analyzeHeadless    # Ghidra headless analysis wrapper (8GB heap)
└── .gitignore
```

## Contributing

Areas where additional static patches could help:
- **More linked list traversals** — other functions iterate BSExtraData lists without the GetByType safety net
- **Additional null checks** — identifying crash sites where a simple conditional jump prevents a dereference
- **Save game validation** — patching the save/load code to handle corrupt data gracefully
- **Audio system hardening** — BSAudio null pointer dereferences during sound playback

The code cave in `.reloc` has ~86KB of free space at VA `0x013F36A8`, plenty of room for additional patch routines.

## References

- [NVTF Source (carxt/New-Vegas-Tick-Fix)](https://github.com/carxt/New-Vegas-Tick-Fix) — hash table research
- [JIP LN NVSE Source (jazzisparis/JIP-LN-NVSE)](https://github.com/jazzisparis/JIP-LN-NVSE) — engine bug fixes
- [xNVSE Source (xNVSE/NVSE)](https://github.com/xNVSE/NVSE) — script extender
- [NVHR (jazzisparis/NVHR)](https://github.com/jazzisparis/NVHR) — heap replacer
- [GECK Wiki — Engine Bugs](https://geckwiki.com/index.php?title=Engine_Bugs_(Fallout_New_Vegas))
- [Steamless (atom0s/Steamless)](https://github.com/atom0s/Steamless) — Steam DRM removal

