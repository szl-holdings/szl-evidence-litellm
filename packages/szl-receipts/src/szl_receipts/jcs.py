"""RFC 8785 JSON Canonicalization Scheme (JCS), implemented stdlib-only.

Why this module exists
----------------------
Every recomputed digest in the estate — ``receipt_id``, chain
``entry_digest``, envelope payload hashes — assumes that two parties can look
at "the same JSON document" and produce *identical bytes*. JSON itself makes
no such guarantee: key order, whitespace, number formatting, string escaping,
and unicode normalization are all serializer choices. RFC 8785 removes every
degree of freedom so that equality becomes byte equality.

Three classic pitfalls this module gets right (each covered by tests):

1. **Key ordering is by UTF-16 code units, not Unicode code points.** For BMP
   characters they coincide, but an astral character such as U+1F600 encodes
   as a surrogate *pair* whose first unit (0xD83D) sorts *below* U+FFFF
   (0xFFFF). Sorting by code point puts U+1F600 after U+FFFF; sorting by
   UTF-16 code units puts it before. We encode each key as big-endian UTF-16
   (``surrogatepass`` keeps lone surrogates deterministic) and sort on those
   bytes. This matches ECMAScript ``Array.prototype.sort`` on strings, which
   is what the RFC is standardized against.

2. **Numbers follow ECMAScript ``Number::toString``.** Python's ``repr`` of a
   float is already the shortest string that round-trips to the same double
   (ECMAScript Minimal Number Form String), but the *notation* differs from
   ECMAScript's fixed/exponential boundary rules. ``1e20`` must serialize as
   the 21-digit integer ``100000000000000000000`` while ``1e21`` is
   ``1e+21``; ``0.000001`` stays fixed while ``0.0000001`` becomes ``1e-7``.
   Exponents carry an explicit sign and no leading zeros. Integers below 2**53
   print without a decimal point; integers >= 2**53 are *rejected* because a
   JSON parser is allowed to route them through an IEEE-754 double and
   silently lose precision — a canonicalizer must never emit a value a reader
   cannot hold exactly. NaN/Infinity have no JSON representation and are
   rejected as well, and negative zero canonicalizes to ``0``.

3. **Strings are escaped minimally and never normalized.** Only the two
   mandatory escapes, the seven single-character control escapes, and other
   code points below 0x20 (as ``\\u00xx`` with lowercase hex) are escaped;
   everything else is emitted as raw UTF-8. No unicode normalization is
   performed: ``é`` (U+00E9) and ``e`` + combining acute (U+0065 U+0301) are
   different code point sequences and must canonicalize to *different* bytes.

The output of every public function here is bytes (or a text form thereof)
that is stable across Python versions, platforms, and locales.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = [
    "IJsonError",
    "JcsError",
    "escape_string",
    "jcs_canon_bytes",
    "jcs_canon_json_text",
    "number_to_js_str",
    "serialize",
    "sort_key_utf16",
]

# 2**53 — the largest magnitude an IEEE-754 double (every JSON number, per the
# ECMAScript data model RFC 8785 adopts) can hold as an exact integer. Beyond
# this, a parser that maps JSON numbers to doubles cannot round-trip the
# value, so emitting it would be dishonest.
_MAX_SAFE_INTEGER = 1 << 53

Number = int | float


class JcsError(Exception):
    """Base class for all canonicalization failures."""


class IJsonError(JcsError):
    """Raised when a value is legitimate JSON but not interoperable (I-JSON).

    RFC 8785 requires input to conform to I-JSON (RFC 7493): no NaN or
    infinities, and integers must stay within the range every implementation
    can represent exactly (|n| < 2**53). Rejecting here, at serialization
    time, is what keeps a receipt digest meaningful across implementations.
    """


def sort_key_utf16(key: str) -> bytes:
    """Return the UTF-16BE code-unit byte sequence used for key ordering.

    ``surrogatepass`` lets lone surrogates encode deterministically instead of
    raising — the RFC's ordering rule is defined on UTF-16 code units, so even
    degenerate input must order consistently rather than crash the serializer.
    """
    return key.encode("utf-16-be", "surrogatepass")


_ESCAPES = {
    0x22: '\\"',  # quotation mark
    0x5C: "\\\\",  # reverse solidus
    0x08: "\\b",  # backspace
    0x09: "\\t",  # horizontal tab
    0x0A: "\\n",  # line feed
    0x0C: "\\f",  # form feed
    0x0D: "\\r",  # carriage return
}


def escape_string(value: str) -> str:
    """Escape *value* per RFC 8785 §3.2.2.2 (minimal escaping).

    Returns the escaped content *without* surrounding quotes. Only the
    mandatory escapes are produced; all other characters — including DEL,
    lone surrogates, and any astral character — are passed through untouched
    and will be emitted as raw UTF-8 by the caller. No normalization is ever
    applied: the exact code points on input are the exact code points on
    output.
    """
    out: list[str] = []
    for ch in value:
        cp = ord(ch)
        seq = _ESCAPES.get(cp)
        if seq is not None:
            out.append(seq)
        elif cp < 0x20:
            # Remaining C0 controls: \u00xx with lowercase hex, per the RFC.
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)


def number_to_js_str(value: Number) -> str:
    """Format a Python int/float exactly as ECMAScript ``Number::toString``.

    Why the gymnastics: Python ``repr(float)`` and ECMAScript agree on the
    shortest round-tripping digits (ECMAScript's "Minimal Number Form
    String"), so the significant digits are free. What differs is *notation*:

    * ECMAScript uses plain (fixed) notation when -6 < n <= 21, where n is
      the decimal exponent of the value written as d.ddd × 10**(n-1); outside
      that window it uses exponential notation. Python switches to exponential
      much earlier (repr(1e16) == "1e+16").
    * ECMAScript writes the exponent with an explicit sign and no leading
      zeros; Python pads to two digits ("1e-07" vs "1e-7").
    * Integers print without a decimal point up to (but excluding) 1e21.

    Boundary examples (all exercised by the test suite):
    ``1e20`` → ``100000000000000000000`` but ``1e21`` → ``1e+21``;
    ``0.000001`` → ``0.000001`` but ``0.0000001`` → ``1e-7``.

    Raises:
        IJsonError: for NaN, ±Infinity, integers with |n| >= 2**53, or any
            float the conversion cannot place (a disciplined absence of
            ambiguous numbers is the entire point).
        TypeError: for non-numeric values (bool is rejected explicitly; in
            Python ``bool`` subclasses ``int`` but JSON treats them
            differently, so serialize() handles booleans before numbers).
    """
    if isinstance(value, bool):
        raise IJsonError("bool is not a JSON number; serialize() handles booleans first")

    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INTEGER:
            raise IJsonError(
                f"integer {value} exceeds the I-JSON exactness bound of 2**53; "
                "a compliant parser may represent it as a double and lose precision"
            )
        return str(value)

    if not isinstance(value, float):
        raise TypeError(f"number_to_js_str requires int or float, got {type(value).__name__}")

    if math.isnan(value):
        raise IJsonError("NaN has no JSON representation")
    if math.isinf(value):
        raise IJsonError("Infinity has no JSON representation")

    if value == 0.0:
        # Covers -0.0: ECMAScript Number::toString(-0) is "0", and Python's
        # repr would give "-0.0". Canonical form must not leak the sign bit.
        return "0"

    sign = "-" if value < 0 else ""
    # repr() gives Python's shortest round-trip form, whose digits are the
    # same Minimal Number Form digits ECMAScript would choose. We only have
    # to re-notation it.
    mantissa, exponent = _split_repr(repr(abs(value)))
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".", 1)
        # repr pads integral floats with a trailing ".0" (e.g. repr(2.0) and
        # repr(1234567890123456.0)); those zeros are notation, not precision,
        # and ECMAScript's shortest form never includes them.
        frac_part = frac_part.rstrip("0")
        mantissa = int_part if not frac_part else int_part + "." + frac_part
    digits = mantissa.replace(".", "")
    dot_pos = mantissa.index(".") if "." in mantissa else len(mantissa)
    # k: significant digit count. n: decimal exponent such that the value is
    # D[0].D[1..k-1] × 10**(n-1). repr never emits leading zeros in the
    # mantissa, so digits[0] is always nonzero; leading fractional zeros are
    # absorbed by the 0 < n <= 21 branch below (digits[:1] is "0").
    k = len(digits)
    n = dot_pos + exponent

    if k <= n <= 21:
        # Integral value, short enough for plain notation: append zeros.
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        # Fixed notation with a real decimal point inside the digits.
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        # Small fraction, plain notation with leading zeros: 0.00…digits.
        return sign + "0." + "0" * (-n) + digits
    if k == 1:
        # Single significant digit, exponential notation.
        return sign + digits + _format_exponent(n - 1)
    # Multiple digits, exponential notation with a mantissa point.
    return sign + digits[0] + "." + digits[1:] + _format_exponent(n - 1)


def _split_repr(s: str) -> tuple[str, int]:
    """Split repr output into (mantissa, decimal-exponent-as-int).

    repr uses 'e' notation with a signed, possibly zero-padded exponent; the
    mantissa is used verbatim because its digits are exactly the shortest
    round-trip digits ECMAScript specifies.
    """
    if "e" in s or "E" in s:
        mantissa, exp = s.lower().split("e", 1)
        return mantissa, int(exp)
    return s, 0


def _format_exponent(n: int) -> str:
    """Format an ECMAScript exponent: explicit sign, no leading zeros."""
    if n >= 0:
        return "e+" + str(n)
    return "e-" + str(-n)


def serialize(value: Any) -> bytes:
    """Serialize a JSON-serializable Python object to canonical UTF-8 bytes.

    Determinism contract: same logical value in, same bytes out, forever.
    Raises IJsonError for numbers outside the interoperable range and
    TypeError for values with no JSON representation (e.g. sets, datetimes,
    bytes). ``None`` maps to ``null`` as usual; ``bytes`` are deliberately
    rejected (a digest belongs in a hex string, not a serializer-specific
    encoding).
    """
    out = bytearray()
    _serialize_into(value, out)
    return bytes(out)


def _serialize_into(value: Any, out: bytearray) -> None:
    # NOTE: bool must precede int — Python makes True/False instances of int.
    if value is None:
        out += b"null"
    elif value is True:
        out += b"true"
    elif value is False:
        out += b"false"
    elif isinstance(value, (int, float)):
        out += number_to_js_str(value).encode("ascii")
    elif isinstance(value, str):
        out += b'"'
        out += escape_string(value).encode("utf-8", "surrogatepass")
        out += b'"'
    elif isinstance(value, (list, tuple)):
        out += b"["
        for index, element in enumerate(value):
            if index:
                out += b","
            _serialize_into(element, out)
        out += b"]"
    elif isinstance(value, dict):
        pairs: list[tuple[str, Any]] = []
        for key, element in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    f"JSON object keys must be str, got {type(key).__name__!r}: {key!r}"
                )
            pairs.append((key, element))
        pairs.sort(key=lambda pair: sort_key_utf16(pair[0]))
        out += b"{"
        for index, (key, element) in enumerate(pairs):
            if index:
                out += b","
            out += b'"'
            out += escape_string(key).encode("utf-8", "surrogatepass")
            out += b'":'
            _serialize_into(element, out)
        out += b"}"
    else:
        raise TypeError(f"object of type {type(value).__name__} is not JSON serializable")


def jcs_canon_bytes(obj: Any) -> bytes:
    """Canonical RFC 8785 UTF-8 bytes for an already-parsed Python object."""
    return serialize(obj)


def jcs_canon_json_text(text: str | bytes) -> str:
    """Parse JSON text, then return its canonical serialization as text.

    This is the equivalence machine: two documents that differ only in
    whitespace or member order — ``{"a":1,"b":2}`` and
    ``' { "b" : 2 , "a" : 1 } '`` — parse to the same value and therefore
    canonicalize to identical bytes. Parsing first also means the
    canonicalizer never trusts the producer's serializer choices.
    """
    return serialize(json.loads(text)).decode("utf-8", "surrogatepass")
