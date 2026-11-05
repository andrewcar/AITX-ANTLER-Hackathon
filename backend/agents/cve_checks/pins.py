"""Data-driven vulnerable dependency pins.

Add an advisory by appending one object to ``vulnerable_pins.json``:

    {"name", "ecosystem", "cve", "affected", "summary", "fixed"}

``ecosystem`` is pypi, npm, packagist, or rubygems.
``affected`` is a comparator and a version, such as ``<=5.1.0`` or ``<1.2.3``.
``fixed`` is optional; leave it empty when there is no patched release.
"""
import json
import re
from pathlib import Path

from .versions import cmp_ver, fmt, parse_dotted


PATH = Path(__file__).with_name("vulnerable_pins.json")
ECOSYSTEMS = ("pypi", "npm", "packagist", "rubygems")
_REQUIRED = ("name", "ecosystem", "cve", "affected", "summary")
_AFFECTED = re.compile(r"^(==|<=|>=|<|>)(\d+\.\d+(?:\.\d+)?)$")
_SPEC_OP = re.compile(r"(===|==|~=|!=|<=|>=|<|>)\s*([0-9][0-9A-Za-z.+_-]*)")
_REQ_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(.*)$"
)


def load_pins() -> list[dict]:
    data = json.loads(PATH.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("vulnerable_pins.json must be a list")
    pins = []
    for row in data:
        if not isinstance(row, dict):
            raise ValueError("each pin must be an object")
        for key in _REQUIRED:
            if not row.get(key) and row.get(key) != "":
                raise ValueError(f"pin missing {key}")
        if row["ecosystem"] not in ECOSYSTEMS:
            raise ValueError(f"unknown ecosystem {row['ecosystem']!r}")
        if parse_affected(row["affected"])[1] is None:
            raise ValueError(f"bad affected spec {row['affected']!r}")
        pins.append(row)
    return pins


def parse_affected(spec: str) -> tuple[str | None, tuple[int, ...] | None]:
    match = _AFFECTED.match((spec or "").strip())
    if not match:
        return None, None
    return match.group(1), parse_dotted(match.group(2))


def norm_name(name: str, ecosystem: str) -> str:
    text = (name or "").strip().lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", text)
    return text


def version_matches(version: tuple[int, ...], affected: str) -> bool:
    op, bound = parse_affected(affected)
    if op is None or bound is None or not version:
        return False
    order = cmp_ver(version, bound)
    if op == "==":
        return order == 0
    if op == "<=":
        return order <= 0
    if op == "<":
        return order < 0
    if op == ">=":
        return order >= 0
    if op == ">":
        return order > 0
    return False


def _numeric_prefix(token: str) -> tuple[int, ...] | None:
    """Leading dotted numbers of a PEP 440 version, ignoring local/pre labels."""
    parts: list[int] = []
    for piece in token.split("."):
        digits = ""
        for char in piece:
            if char.isdigit():
                digits += char
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
        if digits != piece:
            break
    return tuple(parts) or None


def _empty(lower, lower_inc, upper, upper_inc) -> bool:
    if lower is None or upper is None:
        return False
    order = cmp_ver(lower, upper)
    if order > 0:
        return True
    if order < 0:
        return False
    return not (lower_inc and upper_inc)


def _tighter_lower(cur, cur_inc, new, new_inc):
    if cur is None:
        return new, new_inc
    order = cmp_ver(new, cur)
    if order > 0:
        return new, new_inc
    if order < 0:
        return cur, cur_inc
    return cur, cur_inc and new_inc


def _tighter_upper(cur, cur_inc, new, new_inc):
    if cur is None:
        return new, new_inc
    order = cmp_ver(new, cur)
    if order < 0:
        return new, new_inc
    if order > 0:
        return cur, cur_inc
    return cur, cur_inc and new_inc


def _compatible_upper(version: tuple[int, ...]) -> tuple[int, ...]:
    """PEP 440 ``~=X.Y.Z`` upper bound (exclusive): bump the second-to-last component."""
    if len(version) < 2:
        return (version[0] + 1,)
    prefix = list(version[:-1])
    prefix[-1] += 1
    return tuple(prefix) + (0,) * (len(version) - len(prefix))


def _range_overlaps(lower, lower_inc, upper, upper_inc, affected: str) -> bool:
    op, bound = parse_affected(affected)
    if op is None or bound is None:
        return False
    if _empty(lower, lower_inc, upper, upper_inc):
        return False
    if op == "==":
        return _contains(bound, lower, lower_inc, upper, upper_inc)
    if op == "<=":
        if lower is not None and (
            cmp_ver(lower, bound) > 0 or (cmp_ver(lower, bound) == 0 and not lower_inc)
        ):
            return False
        return True
    if op == "<":
        if lower is not None and cmp_ver(lower, bound) >= 0:
            return False
        return True
    if op == ">=":
        if upper is not None and (
            cmp_ver(upper, bound) < 0 or (cmp_ver(upper, bound) == 0 and not upper_inc)
        ):
            return False
        return True
    if op == ">":
        if upper is not None and cmp_ver(upper, bound) <= 0:
            return False
        return True
    return False


def _contains(version, lower, lower_inc, upper, upper_inc) -> bool:
    if lower is not None and (
        cmp_ver(version, lower) < 0 or (cmp_ver(version, lower) == 0 and not lower_inc)
    ):
        return False
    if upper is not None and (
        cmp_ver(version, upper) > 0 or (cmp_ver(version, upper) == 0 and not upper_inc)
    ):
        return False
    return True


def spec_overlaps(spec: str, affected: str) -> bool:
    """True when some release allowed by a requirement spec matches ``affected``.

    A direct URL (``pkg @ https://...``) has no version we can read, so it does
    not match. ``!=`` exclusions are ignored, which can only add a hit.
    """
    text = (spec or "").strip()
    if not text:
        # A bare name allows every version, including the affected ones.
        return parse_affected(affected)[0] is not None
    if text.startswith("@") or ("://" in text and not _SPEC_OP.search(text)):
        return False
    exact: list[tuple[int, ...]] = []
    lower = upper = None
    lower_inc = upper_inc = False
    for op, token in _SPEC_OP.findall(text):
        version = _numeric_prefix(token)
        if not version:
            continue
        if op in ("==", "==="):
            exact.append(version)
        elif op == "!=":
            continue
        elif op == ">=":
            lower, lower_inc = _tighter_lower(lower, lower_inc, version, True)
        elif op == ">":
            lower, lower_inc = _tighter_lower(lower, lower_inc, version, False)
        elif op == "<=":
            upper, upper_inc = _tighter_upper(upper, upper_inc, version, True)
        elif op == "<":
            upper, upper_inc = _tighter_upper(upper, upper_inc, version, False)
        elif op == "~=":
            lower, lower_inc = _tighter_lower(lower, lower_inc, version, True)
            upper, upper_inc = _tighter_upper(
                upper, upper_inc, _compatible_upper(version), False
            )
    if len(exact) > 1:
        return False
    if len(exact) == 1:
        return version_matches(exact[0], affected)
    return _range_overlaps(lower, lower_inc, upper, upper_inc, affected)


def described_version(spec: str) -> str:
    text = (spec or "").strip()
    found = _SPEC_OP.findall(text)
    if len(found) == 1 and found[0][0] in ("==", "==="):
        version = _numeric_prefix(found[0][1])
        if version:
            return fmt(version)
    return text or "unpinned"


def iter_requirements(text: str):
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        match = _REQ_LINE.match(line)
        if not match:
            continue
        yield match.group(1), match.group(2).strip()


def _hit(pin: dict, version: str) -> dict:
    return {
        "name": pin["name"],
        "ecosystem": pin["ecosystem"],
        "cve": pin["cve"],
        "affected": pin["affected"],
        "fixed": pin.get("fixed") or "",
        "summary": pin.get("summary") or "",
        "version": version,
    }


def _pins_for(pins: list[dict] | None) -> list[dict]:
    return load_pins() if pins is None else pins


def match_requirements(text: str, ecosystem: str = "pypi", pins: list[dict] | None = None) -> list[dict]:
    hits = []
    seen = set()
    for name, spec in iter_requirements(text):
        for pin in _pins_for(pins):
            if pin["ecosystem"] != ecosystem:
                continue
            if norm_name(name, ecosystem) != norm_name(pin["name"], ecosystem):
                continue
            if not spec_overlaps(spec, pin["affected"]):
                continue
            version = described_version(spec)
            key = (pin["cve"], pin["name"], version)
            if key in seen:
                continue
            seen.add(key)
            hits.append(_hit(pin, version))
    return hits


def match_exact(pairs, ecosystem: str, pins: list[dict] | None = None) -> list[dict]:
    hits = []
    seen = set()
    for name, version_text in pairs:
        version = parse_dotted(str(version_text).lstrip("vV"))
        if not version:
            continue
        for pin in _pins_for(pins):
            if pin["ecosystem"] != ecosystem:
                continue
            if norm_name(str(name), ecosystem) != norm_name(pin["name"], ecosystem):
                continue
            if not version_matches(version, pin["affected"]):
                continue
            label = fmt(version)
            key = (pin["cve"], pin["name"], label)
            if key in seen:
                continue
            seen.add(key)
            hits.append(_hit(pin, label))
    return hits


def iter_poetry(text: str):
    name = version = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if name and version:
                yield name, version
            name = version = None
            continue
        if line.startswith("name ="):
            name = line.split("=", 1)[1].strip().strip("\"'")
            version = None
        elif line.startswith("version =") and name and version is None:
            version = line.split("=", 1)[1].strip().strip("\"'")
    if name and version:
        yield name, version


def iter_package_lock(text: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    packages = data.get("packages") if isinstance(data, dict) else None
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if key == "" or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            if not name:
                name = str(key).split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                yield name, version
    deps = data.get("dependencies") if isinstance(data, dict) else None
    yield from _walk_npm(deps)


def _walk_npm(deps):
    if not isinstance(deps, dict):
        return
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        if meta.get("version"):
            yield name, meta["version"]
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            yield from _walk_npm(nested)


def iter_yarn(text: str):
    current = None
    for raw in text.splitlines():
        if raw and not raw.startswith((" ", "\t")) and raw.rstrip().endswith(":"):
            head = raw.split(",", 1)[0].strip().strip("\"'")
            current = head.rsplit("@", 1)[0] if "@" in head else None
            continue
        stripped = raw.strip()
        if current and stripped.startswith('version "'):
            yield current, stripped[len('version "'):-1]
            current = None


_PNPM_PKG = re.compile(r"^\s+/?([^/\s][^\s@:]*)@(\d+\.\d+\.\d+[^\s:]*)\s*:\s*$")


def iter_pnpm(text: str):
    for raw in text.splitlines():
        match = _PNPM_PKG.match(raw)
        if match:
            yield match.group(1), match.group(2)


def iter_pipfile(text: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if isinstance(meta, dict) and meta.get("version"):
                yield name, meta["version"]


def iter_composer(text: str):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    for key in ("packages", "packages-dev"):
        rows = data.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and row.get("name") and row.get("version"):
                yield row["name"], row["version"]


_GEM = re.compile(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$")


def iter_gemfile(text: str):
    for raw in text.splitlines():
        match = _GEM.match(raw)
        if match:
            yield match.group(1), match.group(2).split(",")[0].strip()


def scan_manifest(kind: str, text: str, pins: list[dict] | None = None) -> list[dict]:
    """Parse one manifest/lockfile and return pin hits. ``kind`` is the URL path."""
    if kind.endswith("requirements.txt"):
        return match_requirements(text, "pypi", pins)
    if kind.endswith("poetry.lock"):
        return match_exact(iter_poetry(text), "pypi", pins)
    if kind.endswith("Pipfile.lock"):
        return match_requirements(
            "\n".join(f"{name}{spec if str(spec).startswith(('=', '<', '>', '~', '!')) else '==' + str(spec).lstrip('=')}"
                      for name, spec in iter_pipfile(text)),
            "pypi",
            pins,
        )
    if kind.endswith("package-lock.json"):
        return match_exact(iter_package_lock(text), "npm", pins)
    if kind.endswith("yarn.lock"):
        return match_exact(iter_yarn(text), "npm", pins)
    if kind.endswith("pnpm-lock.yaml"):
        return match_exact(iter_pnpm(text), "npm", pins)
    if kind.endswith("composer.lock"):
        return match_exact(iter_composer(text), "packagist", pins)
    if kind.endswith("Gemfile.lock"):
        return match_exact(iter_gemfile(text), "rubygems", pins)
    return []
