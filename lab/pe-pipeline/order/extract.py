"""Extract DLL-scoped transform recipe evidence, without copying native code.

Run with uv run --no-project lab/pe-pipeline/order/extract.py OUTPUT_JSON.
This records static evidence; execution traces must be supplied separately.
"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LLVM = Path("/opt/homebrew/opt/llvm/bin")
BASE = 0x180000000
PINS = {
    "msdelta": "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb",
    "UpdateCompression": "b2abf7125b94c5061f4044f747e23477237cb28c7a25ceae74f3d6dcbc887958",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def first_instruction(dll: Path, rva: int) -> dict[str, str | int]:
    result = subprocess.run(
        [str(LLVM / "llvm-objdump"), "-d", f"--start-address={BASE + rva}",
         f"--stop-address={BASE + rva + 16}", str(dll)],
        check=True, capture_output=True, text=True,
    )
    match = re.search(rf"^{BASE + rva:x}: ((?:[0-9a-f]{{2}} )+)", result.stdout, re.M)
    if match is None:
        raise ValueError(f"instruction missing at {rva:#x}")
    opcode = bytes.fromhex(match[1])
    return {"rva": rva, "first_instruction_hex": opcode.hex(), "first_instruction_length": len(opcode)}


def msdelta(dll: Path, data: bytes) -> dict[str, object]:
    recipes: list[dict[str, object]] = []
    for match in re.finditer(rb"flags\( GetBits \):[^\x00]+", data):
        sequence = re.findall(rb'flags\[\s*(\d+)\s*\]\s*\?\s*"([^"]+)"', match[0])
        if not sequence or sequence[0][1] not in (b"MarkNonExe", b"MarkNonExeCli4"):
            continue
        recipes.append({
            "file_offset": match.start(), "recipe_bytes_sha256": digest(match[0]),
            "stages": [{"flag_bit": int(bit), "flag_mask": 1 << int(bit),
                        "component": name.decode("ascii")} for bit, name in sequence],
        })
    stages: dict[str, object] = {}
    directory = ROOT / "reference/ghidra/pdb_decompiled_msdelta"
    for path in sorted(directory.glob("Transform__*.c")):
        source = path.read_text()
        match = re.search(r"compo::(\w+)Factory::\w+Component::Transform", source)
        if match is not None:
            rva = int(path.stem.split("__")[-1], 16) - BASE
            stages[match[1]] = first_instruction(dll, rva)
    stages["SmashLockPrefixesI386"] = first_instruction(dll, 0x11D90)
    stages["TransformInferredRelocationsI386"] = first_instruction(dll, 0x12140)
    return {"recipe_encoding": "embedded component graph", "recipes": recipes, "stage_entries": stages}


def update_compression(dll: Path, data: bytes) -> dict[str, object]:
    pdb = ROOT / "reference/UpdateCompression.pdb"
    public_symbols = subprocess.run(
        [str(LLVM / "llvm-pdbutil"), "dump", "-publics", str(pdb)],
        check=True, capture_output=True, text=True,
    ).stdout
    runners = {name: 0x1000 + int(offset) for name, offset in re.findall(
        r"`\?Run@(\w+)@@[^`]+`\s+flags = function, addr = 0001:(\d+)", public_symbols)}
    entries: list[dict[str, object]] = []
    directory = ROOT / "reference/ghidra/decompiled_all"
    for index in range(18):
        offset = 0x8C320 + index * 0x48
        mask, factory_vtable = struct.unpack_from("<QQ", data, offset)
        factory = struct.unpack_from("<Q", data, factory_vtable - BASE + 0x10)[0]
        path = next(directory.glob(f"*_{factory:x}.c"))
        source = path.read_text()
        names = re.findall(r"&(\w+)::_vftable_", source)
        name = names[-1] if names else "SmashLockPrefixesX86"
        if not names and "SmashLockPrefixesX86::SmashLockPrefixesX86" not in source:
            raise ValueError(f"unrecognized factory {factory:#x}")
        entries.append({
            "index": index, "entry_rva": offset, "flag_mask": mask,
            "factory_rva": factory - BASE, "component": name,
            "factory_decompilation_sha256": digest(path.read_bytes()),
            "run": first_instruction(dll, runners[name]),
        })
    return {
        "recipe_encoding": "g_transformsMap ordered array",
        "table_rva": 0x8C320, "entry_stride": 0x48, "entries": entries,
        "pdb_sha256": digest(pdb.read_bytes()),
        "pdb_caveat": "Matching GUID; DLL CodeView age 1, saved stripped PDB age 3. Validate runtime independently.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    results: dict[str, object] = {"schema": 1, "evidence_kind": "static", "dlls": {}}
    dlls: dict[str, object] = {}
    for name, expected in PINS.items():
        dll = ROOT / "reference" / f"{name}.dll"
        data = dll.read_bytes()
        if digest(data) != expected:
            raise ValueError(f"unrecognized DLL: {name}")
        detail = msdelta(dll, data) if name == "msdelta" else update_compression(dll, data)
        dlls[name] = {"sha256": expected, **detail}
    results["dlls"] = dlls
    results["extractor_sha256"] = digest(Path(__file__).read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
