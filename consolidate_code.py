#!/usr/bin/env python3
"""
Script to consolidate project Python source code files and specified scripts
into a single text file (all_project_code.txt).
"""

import os
from pathlib import Path


def get_files_to_consolidate(root_dir: Path):
    collected_files = []

    # 1. mtd_ip_shuffling/ (all .py files)
    mtd_dir = root_dir / "mtd_ip_shuffling"
    if mtd_dir.is_dir():
        mtd_files = []
        for p in mtd_dir.rglob("*.py"):
            if p.is_file():
                mtd_files.append(p)
        collected_files.extend(sorted(mtd_files))

    # 2. rl_agent/ (all .py files, excluding runs/ directories)
    rl_dir = root_dir / "rl_agent"
    if rl_dir.is_dir():
        rl_files = []
        for p in rl_dir.rglob("*.py"):
            # Exclude any files under 'runs' directory
            parts = p.relative_to(rl_dir).parts
            if "runs" in parts:
                continue
            if p.is_file():
                rl_files.append(p)
        collected_files.extend(sorted(rl_files))

    # 3. testbed/containernet_topos/ (all .py files)
    topo_dir = root_dir / "testbed" / "containernet_topos"
    if topo_dir.is_dir():
        topo_files = []
        for p in topo_dir.rglob("*.py"):
            if p.is_file():
                topo_files.append(p)
        collected_files.extend(sorted(topo_files))

    # 4. Root-level scripts: mtd_ip_shuffling.py, finetune_pipeline.sh (if present)
    root_scripts = ["mtd_ip_shuffling.py", "finetune_pipeline.sh"]
    for script_name in root_scripts:
        script_path = root_dir / script_name
        if script_path.is_file():
            collected_files.append(script_path)

    return collected_files


def consolidate_code():
    root_dir = Path(__file__).resolve().parent
    output_path = root_dir / "all_project_code.txt"
    files = get_files_to_consolidate(root_dir)

    separator = "=" * 80

    with open(output_path, "w", encoding="utf-8") as out:
        for idx, file_path in enumerate(files):
            rel_path = file_path.relative_to(root_dir).as_posix()
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading {rel_path}: {e}")
                continue

            if idx > 0:
                out.write("\n\n")

            out.write(f"{separator}\n")
            out.write(f"FILE: {rel_path}\n")
            out.write(f"{separator}\n")
            out.write(content)
            if not content.endswith("\n"):
                out.write("\n")

    # Calculate statistics
    with open(output_path, "r", encoding="utf-8") as f:
        line_count = sum(1 for _ in f)

    file_size_bytes = output_path.stat().st_size
    file_size_kb = file_size_bytes / 1024

    print(f"Consolidation complete.")
    print(f"Output saved to: {output_path}")
    print(f"Total files consolidated: {len(files)}")
    print(f"Total line count: {line_count:,} lines")
    print(f"Total file size: {file_size_bytes:,} bytes ({file_size_kb:.2f} KB)")
    print("\nFiles included:")
    for f in files:
        print(f"  - {f.relative_to(root_dir).as_posix()}")


if __name__ == "__main__":
    consolidate_code()
