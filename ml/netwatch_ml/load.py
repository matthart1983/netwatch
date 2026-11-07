"""Read a features CSV written by `netwatch diagnose features --unstable`.

The CSV and its schema.json come from the same netwatch build. Nothing here
computes a feature: if a column is wrong, fix it in src/diagnose/features.rs
and regenerate, so training and inference keep using the same numbers.

Missing values are empty fields and load as NaN. Check features are +1 passed,
-1 failed, 0 not run, NaN when the check belongs to another rule.
"""

from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass, field
from pathlib import Path


class SchemaMismatch(ValueError):
    """The CSV doesn't match the schema it was supposed to be written with."""


def schema_hash(features: list[dict]) -> str:
    """FNV-1a over `"group":name\\n`, matching features::schema_hash in Rust."""
    h = 0xCBF29CE484222325
    for spec in features:
        line = f'"{spec["group"]}":{spec["name"]}\n'.encode()
        for b in line:
            h ^= b
            h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


@dataclass
class Dataset:
    names: list[str]
    groups: list[str]
    meta: list[dict[str, str]]
    rows: list[list[float]]
    schema_hash: str
    meta_columns: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rows)

    def column(self, name: str) -> list[float]:
        i = self.names.index(name)
        return [r[i] for r in self.rows]

    def groups_of(self) -> list[str]:
        """Grouping key for splits: the episode. Never split one episode's
        decision points across train and test."""
        return [m["episode"] for m in self.meta]

    def labelled(self, sources: tuple[str, ...] = ("lab", "expert")) -> "Dataset":
        """Rows whose label came from a trusted source. User labels are kept
        out by default until their agreement with reviewers is measured."""
        keep = [i for i, m in enumerate(self.meta) if m["label"] and m["label_source"] in sources]
        return self._subset(keep)

    def where(self, **meta_equals: str) -> "Dataset":
        keep = [
            i
            for i, m in enumerate(self.meta)
            if all(m.get(k) == v for k, v in meta_equals.items())
        ]
        return self._subset(keep)

    def feature_names(self, *groups: str) -> list[str]:
        return [n for n, g in zip(self.names, self.groups) if not groups or g in groups]

    def to_pandas(self):
        import pandas as pd  # optional: pip install netwatch-ml[train]

        frame = pd.DataFrame(self.rows, columns=self.names)
        for col in self.meta_columns:
            frame.insert(len(frame.columns) - len(self.names), col, [m[col] for m in self.meta])
        return frame

    def _subset(self, keep: list[int]) -> "Dataset":
        return Dataset(
            names=self.names,
            groups=self.groups,
            meta=[self.meta[i] for i in keep],
            rows=[self.rows[i] for i in keep],
            schema_hash=self.schema_hash,
            meta_columns=self.meta_columns,
        )


def load(csv_path: str | Path, schema_path: str | Path, expect_hash: str | None = None) -> Dataset:
    """Load features, refusing any mismatch with the schema.

    `expect_hash` pins a schema, e.g. the one a model was trained on.
    """
    schema = json.loads(Path(schema_path).read_text())
    features = schema["features"]
    meta_columns = schema["meta_columns"]
    names = [f["name"] for f in features]

    computed = schema_hash(features)
    if computed != schema["hash"]:
        raise SchemaMismatch(f"schema.json hash {schema['hash']} does not match its names ({computed})")
    if expect_hash is not None and schema["hash"] != expect_hash:
        raise SchemaMismatch(f"schema {schema['hash']} is not the expected {expect_hash}")

    meta: list[dict[str, str]] = []
    rows: list[list[float]] = []
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        if header != meta_columns + names:
            extra = [c for c in header if c not in meta_columns + names]
            missing = [c for c in meta_columns + names if c not in header]
            raise SchemaMismatch(
                f"CSV header differs from schema {schema['hash']}: "
                f"{len(missing)} missing, {len(extra)} unexpected, first {(missing or extra)[:3]}"
            )
        m = len(meta_columns)
        for line_no, record in enumerate(reader, start=2):
            if len(record) != len(header):
                raise SchemaMismatch(f"line {line_no}: {len(record)} fields, expected {len(header)}")
            meta.append(dict(zip(meta_columns, record[:m])))
            rows.append([float(v) if v != "" else math.nan for v in record[m:]])

    return Dataset(
        names=names,
        groups=[f["group"] for f in features],
        meta=meta,
        rows=rows,
        schema_hash=schema["hash"],
        meta_columns=meta_columns,
    )
