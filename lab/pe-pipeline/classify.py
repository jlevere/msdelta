"""Select passing structural controls from the Rust corpus classification.

This does not infer failure causes. Native stage comparisons are needed for that.
"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast


class Header(TypedDict):
    file_type: int
    flags: int


class Section(TypedDict):
    name: str


class Pe(TypedDict):
    machine: str
    machine_raw: int
    is_managed: bool
    sections: list[Section]
    data_directories: list[tuple[int, int]]


class Classification(TypedDict):
    corpus: str
    id: str
    source: str
    delta: str
    expected_sha256: str
    source_size: int
    outcome: str
    header: Header
    pe: Pe


class Document(TypedDict):
    schema: int
    cases: list[Classification]


@dataclass(frozen=True)
class Case:
    row: Classification

    @property
    def key(self) -> str:
        return f"{self.row['corpus']}--{self.row['id']}"

    @property
    def signature(self) -> tuple[int, int, int, bool]:
        return (
            self.row["pe"]["machine_raw"],
            self.row["header"]["file_type"],
            self.row["header"]["flags"],
            self.row["pe"]["is_managed"],
        )

    def distance(self, other: "Case") -> tuple[bool, int, float, int, str]:
        left = self.row
        right = other.row
        left_sections = [section["name"] for section in left["pe"]["sections"]]
        right_sections = [section["name"] for section in right["pe"]["sections"]]
        directories = sum(
            bool(lrva and lsize) != bool(rrva and rsize)
            for (lrva, lsize), (rrva, rsize) in zip(
                left["pe"]["data_directories"], right["pe"]["data_directories"], strict=True
            )
        )
        size_ratio = abs(left["source_size"] - right["source_size"]) / max(left["source_size"], right["source_size"], 1)
        return (
            left_sections != right_sections,
            directories,
            size_ratio,
            abs(len(left_sections) - len(right_sections)),
            other.key,
        )

    def input(self) -> dict[str, str]:
        return {
            "id": self.key,
            "source": self.row["source"],
            "delta": self.row["delta"],
            "expected_sha256": self.row["expected_sha256"],
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classification", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    document = cast(Document, json.loads(args.classification.read_text()))
    if document["schema"] != 1:
        raise ValueError("unsupported classification schema")
    cases = [Case(row) for row in document["cases"]]
    failures = [case for case in cases if case.row["outcome"] != "exact"]
    passing = [case for case in cases if case.row["outcome"] == "exact"]
    selected: dict[str, Case] = {case.key: case for case in failures}
    comparisons: list[dict[str, object]] = []
    for failure in failures:
        candidates = [case for case in passing if case.signature == failure.signature]
        if not candidates:
            raise ValueError(f"no passing control with matching machine/file-type/flags/managed state: {failure.key}")
        control = min(candidates, key=failure.distance)
        selected[control.key] = control
        comparisons.append({
            "failure": failure.key,
            "control": control.key,
            "matching": {"machine": failure.row["pe"]["machine"], "file_type": failure.signature[1], "flags": failure.signature[2], "managed": failure.signature[3]},
            "control_distance": failure.distance(control)[:-1],
            "cause": "unclassified; native boundary comparison pending",
        })
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "selected-inputs.json").write_text(json.dumps([selected[key].input() for key in sorted(selected)], indent=2) + "\n")
    (args.output / "matched-controls.json").write_text(json.dumps({"schema": 1, "comparisons": comparisons}, indent=2) + "\n")
    print(json.dumps({"corpus_cases": len(cases), "failures": len(failures), "selected_cases": len(selected), "comparisons": comparisons}, indent=2))


if __name__ == "__main__":
    main()
