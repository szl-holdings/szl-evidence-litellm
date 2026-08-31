"""RFC 8785 (JCS) conformance tests — the canonicalization ground truth.

These vectors are the estate's interop contract: any independent
canonicalizer that disagrees with even one of them produces different digest
bytes and therefore splits the chain of custody. Boundary numbers, UTF-16
key ordering, minimal escaping, and the no-normalization rule are each
pinned individually.
"""

import math

import pytest
from szl_receipts.jcs import (
    IJsonError,
    escape_string,
    jcs_canon_bytes,
    jcs_canon_json_text,
    number_to_js_str,
    serialize,
)


class TestStructure:
    def test_primitives(self):
        assert jcs_canon_bytes(None) == b"null"
        assert serialize(True) == b"true"
        assert serialize(False) == b"false"
        assert serialize("") == b'""'

    def test_empty_containers(self):
        assert serialize({}) == b"{}"
        assert serialize([]) == b"[]"

    def test_nested_document(self):
        doc = {"b": [1, {"c": None}], "a": "x"}
        assert serialize(doc) == b'{"a":"x","b":[1,{"c":null}]}'


class TestKeyOrdering:
    def test_numeric_string_keys_sort_lexically(self):
        # Numeric-looking keys are still strings: "10" sorts before "2"
        # because '1' < '2' in UTF-16 code units.
        assert serialize({"2": "two", "1": "one", "10": "ten"}) == (
            b'{"1":"one","10":"ten","2":"two"}'
        )

    def test_astral_character_sorts_before_uffff(self):
        # THE classic pitfall: by Unicode code point, U+1F600 (128512) >
        # U+FFFF (65535). By UTF-16 code units, U+1F600 encodes as the pair
        # (0xD83D, 0xDE00), and 0xD83D < 0xFFFF, so the astral key sorts
        # BEFORE the BMP key. RFC 8785 follows ECMAScript, i.e. UTF-16.
        astral = "\U0001f600"
        bmp_high = "\uffff"
        doc = {bmp_high: 1, astral: 2}
        out = serialize(doc)
        assert out == f'{{"{astral}":2,"{bmp_high}":1}}'.encode()
        assert out.index(astral.encode()) < out.index(bmp_high.encode())

    def test_bmp_order_matches_code_point_order(self):
        doc = {"b": 1, "a": 2, "ab": 3}
        assert serialize(doc) == b'{"a":2,"ab":3,"b":1}'

    def test_astral_vs_ascii(self):
        # astral lead surrogate 0xD83D > 'z' (0x007A): ASCII first.
        doc = {"\U0001f600": 1, "z": 2}
        assert serialize(doc) == '{"z":2,"\U0001f600":1}'.encode()


class TestStringEscaping:
    def test_mandatory_escapes(self):
        assert serialize('"') == b'"\\""'
        assert serialize("\\") == b'"\\\\"'

    def test_control_character_escapes(self):
        assert serialize("\b\f\n\r\t") == b'"\\b\\f\\n\\r\\t"'

    def test_other_c0_controls_use_lowercase_u00xx(self):
        assert serialize("\x00\x1f") == b'"\\u0000\\u001f"'
        assert serialize("\x07") == b'"\\u0007"'

    def test_del_is_not_escaped(self):
        # RFC 8785 escapes only < 0x20; DEL (0x7F) passes through raw.
        assert serialize("\x7f") == b'"\x7f"'

    def test_solidus_is_not_escaped(self):
        assert serialize("/") == b'"/"'

    def test_non_ascii_emitted_raw(self):
        assert serialize("€") == '"€"'.encode()
        assert serialize("unicode \U0001f600 raw") == '"unicode \U0001f600 raw"'.encode("utf-8")

    def test_escape_string_helper_has_no_quotes(self):
        assert escape_string('a"b') == 'a\\"b'


class TestNoUnicodeNormalization:
    def test_precomposed_vs_combining_serialize_differently(self):
        # U+00E9 'é' vs 'e' + U+0301 combining acute: visually identical,
        # canonically distinct. A normalizing canonicalizer would merge them
        # and silently break signatures made on the other form. RFC 8785
        # preserves exact code points — so must we.
        precomposed = "\u00e9"
        combining = "e\u0301"
        assert serialize(precomposed) != serialize(combining)
        assert serialize(precomposed) == b'"\xc3\xa9"'  # é as 2-byte UTF-8
        assert serialize(combining) == b'"e\xcc\x81"'  # e + combining acute

    def test_same_distinction_in_keys(self):
        assert serialize({"\u00e9": 1}) != serialize({"e\u0301": 1})


class TestNumbers:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, "0"),
            (7, "7"),
            (-13, "-13"),
            (2**53 - 1, "9007199254740991"),  # max I-JSON-exact integer
            (-(2**53 - 1), "-9007199254740991"),
            (3.0, "3"),  # integral floats drop the decimal point
            (0.0, "0"),
            (-0.0, "0"),  # negative zero canonicalizes to zero
            (1.5, "1.5"),
            (-1.5, "-1.5"),
            (0.1, "0.1"),
            (0.5, "0.5"),
            (3.141592653589793, "3.141592653589793"),
            (1e15, "1000000000000000"),
            (1e20, "100000000000000000000"),  # boundary: largest plain-notation integer
            (1e21, "1e+21"),  # boundary: first exponential integer
            (-1e21, "-1e+21"),
            (0.000001, "0.000001"),  # boundary: smallest plain-notation fraction
            (1.23e-6, "0.00000123"),
            (0.0000001, "1e-7"),  # boundary: first exponential fraction
            (1e-7, "1e-7"),
            (5e-324, "5e-324"),  # smallest positive double (denormal)
            (1.7976931348623157e308, "1.7976931348623157e+308"),  # DBL_MAX, explicit sign
            (1.23e-7, "1.23e-7"),
            (-1.23e-7, "-1.23e-7"),
            (7.2e20, "720000000000000000000"),
            (1.23e21, "1.23e+21"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e308, "1e+308"),
            # A 20-digit integral double just below the 1e21 membrane.
            (float(10**20) - float(10**4) * 2, "99999999999999980000"),
        ],
    )
    def test_number_boundaries(self, value, expected):
        assert number_to_js_str(value) == expected
        # Round-trip: the emitted text parses back to the same double.
        assert float(expected) == float(value)

    @pytest.mark.parametrize(
        "value",
        [
            float("nan"),
            float("inf"),
            float("-inf"),
            2**53,
            -(2**53),
            -(2**53) - 1,
            2**53 + 2,
        ],
    )
    def test_non_interoperable_numbers_rejected(self, value):
        with pytest.raises(IJsonError):
            number_to_js_str(value)

    def test_nan_inside_document_rejected(self):
        with pytest.raises(IJsonError):
            serialize({"x": math.nan})

    def test_bool_is_not_a_number(self):
        with pytest.raises(IJsonError):
            number_to_js_str(True)  # type: ignore[arg-type]

    def test_json_parse_of_exponents_canonicalizes_plain(self):
        assert jcs_canon_json_text("1E+22") == "1e+22"
        assert jcs_canon_json_text("1e-7") == "1e-7"
        assert jcs_canon_json_text("-0.0") == "0"


class TestEquivalence:
    def test_whitespace_and_member_order_irrelevant(self):
        a = jcs_canon_json_text('{"a":1,"b":2}')
        b = jcs_canon_json_text(' { "b" : 2 , "a" : 1 } ')
        assert a == b == '{"a":1,"b":2}'

    def test_parsed_and_constructed_match(self):
        assert jcs_canon_json_text('{"x":[1,2.5,"y"]}') == (
            jcs_canon_bytes({"x": [1, 2.5, "y"]}).decode()
        )

    def test_deeply_nested_equivalence(self):
        text_a = '{"o":{"z":[{"k":null},3],"a":{"b":{}}}}'
        text_b = '{ "o" : { "a" : {"b" : {}} , "z" : [ {"k":null} , 3 ] } }'
        assert jcs_canon_json_text(text_a) == jcs_canon_json_text(text_b)

    def test_canon_bytes_returns_bytes(self):
        assert isinstance(jcs_canon_bytes([1]), bytes)


class TestRejection:
    def test_non_string_keys_rejected(self):
        with pytest.raises(TypeError):
            serialize({1: "one"})

    def test_non_serializable_types_rejected(self):
        with pytest.raises(TypeError):
            serialize(object())
        with pytest.raises(TypeError):
            serialize(b"bytes are not JSON")

    def test_invalid_json_text_rejected(self):
        import json as _json

        with pytest.raises(_json.JSONDecodeError):
            jcs_canon_json_text("{not json")
