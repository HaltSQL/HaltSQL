import pytest

from haltsql import QueryDenied, Verdict, sql_sha256, validate_context
from haltsql.testing import make_verdict, make_verdict_dict

SQL = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10"


def test_sql_sha256_matches_cli_value():
    assert sql_sha256(SQL) == "372f83aa27535a0c27b16ce75e67d3986354da94c60b42f8f6533e5314f60db8"


def test_parse_allowed_and_bind_args():
    v = make_verdict(SQL, allowed=True, bind=["acme"])
    assert v.allowed is True
    assert v.bind_args() == ["acme"]
    assert v.matches_sql(SQL)
    assert not v.matches_sql(SQL + " ")
    assert v.raise_for_denied() is v


def test_bind_args_orders_by_param_and_keeps_lists():
    d = make_verdict_dict(SQL, allowed=True)
    d["bind_params"] = [{"param": 2, "value": ["a", "b"]}, {"param": 1, "value": "x"}]
    v = Verdict.from_dict(d)
    assert v.bind_args() == ["x", ["a", "b"]]
    assert isinstance(v.bind_args()[1], list)


def test_bind_args_rejects_gaps():
    d = make_verdict_dict(SQL, allowed=True)
    d["bind_params"] = [{"param": 2, "value": "x"}]
    with pytest.raises(ValueError, match="not contiguous"):
        Verdict.from_dict(d).bind_args()


def test_bind_args_on_denied_raises_query_denied():
    v = make_verdict(SQL, allowed=False, codes=["E_TENANT_MISSING"])
    with pytest.raises(QueryDenied) as ei:
        v.bind_args()
    assert ei.value.verdict.codes == ["E_TENANT_MISSING"]
    assert "E_TENANT_MISSING: fix E_TENANT_MISSING" == str(ei.value)


@pytest.mark.parametrize(
    "mutate,msg",
    [
        (lambda d: d.update(allowed="true"), "boolean"),
        (lambda d: d.update(allowed=1), "boolean"),
        (lambda d: d.pop("allowed"), "boolean"),
        (lambda d: d.update(reasons="x"), "list"),
        (lambda d: d.update(bind_params=[{"param": 1, "value": 5}]), "value"),
        (lambda d: d.update(bind_params=[{"param": 0, "value": "a"}]), ">= 1"),
        (lambda d: d.update(bind_params=[{"param": True, "value": "a"}]), "wrong type"),
        (lambda d: d.update(bind_params=[{"param": 1, "value": "a"}, {"param": 1, "value": "b"}]), "duplicate"),
        (lambda d: d.update(reasons=[{"code": "E_X", "message": "m"}]), "reasons is not empty"),
        (lambda d: d.pop("sql_sha256"), "sql_sha256"),
        (lambda d: d.update(policy=None), "policy"),
    ],
)
def test_strict_parsing_rejects_bad_shapes(mutate, msg):
    d = make_verdict_dict(SQL, allowed=True, bind=["a"])
    mutate(d)
    with pytest.raises(ValueError, match=msg):
        Verdict.from_dict(d)


def test_denial_without_reasons_gets_internal_reason():
    d = make_verdict_dict(SQL, allowed=False)
    d["reasons"] = []
    v = Verdict.from_dict(d)
    assert v.allowed is False and v.codes == ["E_INTERNAL"]


def test_unknown_fields_ignored_and_kept_in_raw():
    d = make_verdict_dict(SQL, allowed=True, bind=["a"])
    d["future_field"] = {"x": 1}
    v = Verdict.from_dict(d)
    assert v.raw["future_field"] == {"x": 1}
    assert v.to_dict()["future_field"] == {"x": 1}


def test_validate_context():
    assert validate_context({"a": "x", "b": 3, "c": ["p", 2], "d": ("q",)}) == {
        "a": "x", "b": 3, "c": ["p", 2], "d": ["q"]
    }
    assert validate_context(None) == {}
    for bad in ({"a": True}, {"a": 1.5}, {"a": None}, {"a": [True]}, {"": "x"}, {1: "x"}, {"a": {"b": 1}}):
        with pytest.raises(ValueError):
            validate_context(bad)
    with pytest.raises(ValueError):
        validate_context(["a"])  # type: ignore[arg-type]
