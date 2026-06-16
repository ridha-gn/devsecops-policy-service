import json
from api.history import get_history, get_stats
from collections import Counter


def get_metrics():
    history = get_history(limit=500)

    violation_counter = Counter()
    type_counter = Counter()

    for scan in history:
        type_counter[scan["code_type"]] += 1
        try:
            violations = json.loads(scan["violations_json"])
            for v in violations:
                violation_counter[v.get("rule", "UNKNOWN")] += 1
        except:
            pass

    top_violations = [
        {"rule": rule, "count": count}
        for rule, count in violation_counter.most_common(5)
    ]

    requests_by_type = dict(type_counter)

    return {
        "top_violations": top_violations,
        "requests_by_type": requests_by_type,
    }
