"""Read local rules repeatedly; no scanner, project or network access."""
import json
import time
from security_runtime.rulepacks import RulePackManager
manager = RulePackManager()
rows = []
for sample in range(3):
    started = time.perf_counter()
    pack = manager.resolve()
    rows.append(dict(sample=sample+1, elapsed_ms=round((time.perf_counter()-started)*1000,3),
                     cache_hit=manager.cache_hit, rules=len(pack.catalog)))
print(json.dumps(rows,indent=2))
