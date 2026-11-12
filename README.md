# Bulk Slash (Sega Saturn, Hudson Soft, 1997) reverse-engineering names

Function names for the Saturn version of **Bulk Slash**. Analysed disc: Japanese release (IP.BIN header `T-14310G V1.001 19970424`, area `J`).
Fifteen SH-2 images are loaded as raw programs and every function carries a name (0 `FUN_` placeholders left). No web check for an existing public decomp was made.

| Program (disc file) | Load base | Functions | hand (provisional) | rule-based (provisional) |
|---|---|---|---|---|
| IP.BIN (boot code, sectors 0-1, 4,096 B) | 0x06002000 | 12 | 6 | 6 |
| `1ST.BIN` (main program, first-read file, 356,352 B) | 0x06004000 | 744 | 23 | 721 |
| `ALL.ST1`..`ALL.ST7` entry 0 (stage code, one per stage) | 0x06026000 | 490, 475, 493, 507, 497, 489, 512 | 19 | 3,444 |
| `END.ALL` entry 0 (ending/profile screens) | 0x06026000 | 372 | 2 | 370 |
| `ERR.ALL` entry 0 (error screen) | 0x06026000 | 12 | 0 | 12 |
| `RANK.ALL` entry 0 (ranking / name entry) | 0x06026000 | 102 | 1 | 101 |
| `SEL_DEMO.ALL` entry 0 | 0x06026000 | 111 | 0 | 111 |
| `TITLE.ALL` entry 0 (title / configuration) | 0x06026000 | 108 | 4 | 104 |
| `MOVIE.BIN` entry 0 (movie player, CPK) | 0x06026000 | 306 | 2 | 304 |
| **Total** | | **5,230** | **57** | **5,173** |

IP.BIN header: first-read address 0x06004000, so root file `1ST.BIN`; `tools/basechk.py` scores base 0x06004000 at 484 prologue-matching pointer targets (next best 36).
`ALL.ST1-7`, `END.ALL`, `ERR.ALL`, `RANK.ALL`, `SEL_DEMO.ALL`, `TITLE.ALL`, `MOVIE.BIN` start with a directory of 16-byte big-endian entries (start sector, sector count, destination address, 0; 2,048-byte sectors). Entry 0 of each is the code overlay, destination 0x06026000 (best `basechk` base for every one); the other entries load to VDP memory (0x25xxxxxx) or data areas (0x06091000, 0x0023d000, 0x00270000: no code prologues) and are not imported. The overlays share one load slot. `tools/allsplit.py` lists the entries.
Not imported: `*.CPK` (Cinepak movies), `BGM.DAT`, `VCP*`/`VCDM.DAT`, `PW*.DAT`, `BVD.BIN`, `KANJI.FON`, `JPAT.BIN`.
Prologues the generic function finder missed were added by `tools/orph.py` (`sts.l pr,@-r15` outside any function) plus `CreateAt.java`: 66 in `1ST.BIN`, 4 in IP.BIN, about 89 per stage overlay (e.g. ST1 401 to 490).

**Names are heuristic and all provisional.** 6 IP.BIN names are carried from the Black Dawn repo (byte-identical SDK boot helpers); 12 `1ST.BIN` names (cdc_ and rtl_ library routines) are carried from Black Dawn and Congo where the instruction stream (pc-relative and branch displacements masked) is identical up to the first `rts`.
The other hand names come from file-name strings (`ALL.ST1`, `MOVIE.BIN`), on-screen text (`WARNING`, `DESTROYED`, `COMPLETE`, `THE BEST SLASHERS`, `CONFIGURATION`), library messages (`cpkd_sys_start`, `Heap and stack collision`) and code structure; they are literal-pool matches and have not been read in detail.
The rest are structural names `<area>_<Role>_<addr>` (role from body shape). Area labels are address-block guesses (`ghidra/naming/areas_*`) and are placeholders until read. Stage overlays use a single area `stage`.

**No game data is included**: no disc image, executables or decompiled C. Funcinfo exports contain only function addresses, names, sizes and call edges.

## Layout
| Path | Content |
|---|---|
| `ghidra/hand_<PROG>.txt` | `0x<addr> func <name> hand provisional <comment>` (ApplyNames.java) |
| `ghidra/funcinfo_<PROG>.tsv` | per-function export: `F` address name source size, `C` callees |
| `ghidra/naming/` | hand-written names (`names_*`) and the area maps used by the structural namer |
| `ghidra/scripts/` | FindSh2FunctionsMem, CreateAt, ApplyNames, ExportFuncInfo, CsDumpAll and helpers |
| `tools/` | basechk/basefind (load bases), allsplit.py (disc directory entries), orph.py (missed prologues), feat.py, carry.py, evidence.py, ptr.py, autoname.py, show.py |

## Reproduce
1. Extract track 1 of your own dump (raw 2352-byte sectors) with any ISO9660 extractor. Copy `1ST.BIN` to `ghidra/bin/MAIN.BIN`; for each of `ALL.ST1-7`, `END.ALL`, `ERR.ALL`, `RANK.ALL`, `SEL_DEMO.ALL`, `TITLE.ALL`, `MOVIE.BIN` cut directory entry 0 (sectors `start..start+count`, 2,048 B each) to `bin/ST1..ST7`, `END`, `ERR`, `RANK`, `SELD`, `TITLE`, `MOVIE` `.BIN`; IP.BIN = user data of sectors 0-1 (4,096 B) to `bin/IP.BIN`.
2. `ghidra/import.sh MAIN.BIN 0x06004000`, `import.sh IP.BIN 0x06002000`, `import.sh <PROG>.BIN 0x06026000` import as raw `SuperH:BE:32:SH-2` (adjust paths in the .sh files to your checkout and Ghidra launcher; project name `BS`). Then `tools/orph.py` and `CreateAt.java` for missed prologues.
3. `tools/feat.py . <PROG> <base>`, then `ghidra/apply.sh <PROG>` regenerates structural names (`tools/autoname.py` with `ghidra/naming/names_*` and `areas_*` copied to `work/`), applies them and re-exports; `IP` applies `hand_IP.txt` directly.

Non-commercial study and preservation. Notes, names and tools: MIT (`LICENSE`). Bulk Slash belongs to its rights holders.
