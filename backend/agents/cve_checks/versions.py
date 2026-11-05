"""Small dotted-version helpers shared by the CVE checks. No I/O."""
import re


_DOTTED = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+){0,2})(?!\d)")


def parse_dotted(text: str | None) -> tuple[int, ...] | None:
    """First major.minor[.patch] in ``text``, or None."""
    if not text:
        return None
    match = _DOTTED.search(str(text))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def fmt(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def cmp_ver(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a = tuple(left) + (0,) * (width - len(left))
    b = tuple(right) + (0,) * (width - len(right))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def pad3(version: tuple[int, ...]) -> tuple[int, int, int]:
    vals = tuple(int(part) for part in version[:3])
    return vals + (0,) * (3 - len(vals))
