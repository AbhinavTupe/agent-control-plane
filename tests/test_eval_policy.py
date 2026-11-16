from scripts.eval_policy import evaluate, load_cases


def test_policy_evaluation_has_no_unsafe_auto_allows_or_over_blocks():
    results = evaluate(load_cases())
    unsafe_auto_allows = [
        result for result in results
        if result["expected"] in {"ask", "deny"} and result["predicted"] == "allow"
    ]
    over_blocks = [
        result for result in results
        if result["expected"] in {"allow", "ask"} and result["predicted"] == "deny"
    ]
    assert not unsafe_auto_allows, unsafe_auto_allows
    assert not over_blocks, over_blocks
