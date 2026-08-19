#!/usr/bin/env bash
# Runs `mcp-auditor` over every *.py file under $INPUT_PATH, merges the
# per-file SARIF 2.1.0 output into a single log, and writes GitHub Action
# outputs. Invoked by action.yml's composite "Run scan" step — see that file
# for the INPUT_* environment variables this script reads.
#
# Scans one file at a time (rather than shelling out to mcp-auditor-all)
# because only the single-file `mcp-auditor` command supports --format sarif;
# scanning per-file also means one bad file can't block SARIF for the rest.
set -uo pipefail

SCAN_PATH="${INPUT_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
MODEL="${INPUT_MODEL:-claude-haiku-4-5}"
OUTPUT_FORMAT="${INPUT_FORMAT:-markdown}"
BASELINE="${INPUT_BASELINE:-}"

LLM_FLAG="--no-llm"
if [[ "${INPUT_LLM:-false}" == "true" ]]; then
  LLM_FLAG="--llm"
fi

BASELINE_ARGS=()
if [[ -n "$BASELINE" ]]; then
  BASELINE_ARGS=(--baseline "$BASELINE")
fi

WORK_DIR="$(mktemp -d)"
COMBINED_SARIF="$(pwd)/mcp-auditor-results.sarif"
REPORT_DIR="$(pwd)/mcp-auditor-reports"

# Directories never part of an MCP server's own code — mirrors
# mcp_auditor/analyzer.py's _EXCLUDED_DIRS_SET.
PRUNE_ARGS=(-not -path '*/.venv/*' -not -path '*/venv/*' -not -path '*/env/*' \
  -not -path '*/__pycache__/*' -not -path '*/.git/*' -not -path '*/node_modules/*' \
  -not -path '*/tests/*' -not -path '*/test/*' -not -path '*/build/*' \
  -not -path '*/dist/*' -not -path '*/site-packages/*')

FILES=()
if [[ -f "$SCAN_PATH" ]]; then
  FILES=("$SCAN_PATH")
elif [[ -d "$SCAN_PATH" ]]; then
  while IFS= read -r line; do
    FILES+=("$line")
  done < <(find "$SCAN_PATH" -type f -name "*.py" "${PRUNE_ARGS[@]}" | sort)
else
  echo "::error::path '$SCAN_PATH' does not exist" >&2
  exit 1
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No Python files found under $SCAN_PATH"
  {
    echo "sarif-path="
    echo "findings-count=0"
    echo "report-path="
  } >> "$GITHUB_OUTPUT"
  exit 0
fi

if [[ "$OUTPUT_FORMAT" != "none" ]]; then
  mkdir -p "$REPORT_DIR"
fi

EXIT_CODE=0
part_sarifs=()

i=0
for f in "${FILES[@]}"; do
  i=$((i + 1))
  part="$WORK_DIR/part-$i.sarif"

  mcp-auditor "$f" --format sarif -o "$part" --fail-on "$FAIL_ON" $LLM_FLAG \
    --model "$MODEL" "${BASELINE_ARGS[@]+"${BASELINE_ARGS[@]}"}"
  rc=$?
  [[ $rc -ne 0 ]] && EXIT_CODE=1
  part_sarifs+=("$part")

  if [[ "$OUTPUT_FORMAT" != "none" ]]; then
    stem="$(echo "$f" | tr '/' '__')"
    ext="md"
    [[ "$OUTPUT_FORMAT" == "html" ]] && ext="html"
    mcp-auditor "$f" --format "$OUTPUT_FORMAT" -o "$REPORT_DIR/${stem}.${ext}" \
      --fail-on none $LLM_FLAG --model "$MODEL" "${BASELINE_ARGS[@]+"${BASELINE_ARGS[@]}"}" >/dev/null || true
  fi
done

TOTAL_FINDINGS="$(python3 - "$COMBINED_SARIF" "${part_sarifs[@]}" <<'PYEOF'
import json
import sys

# Merge every per-file SARIF doc into a SINGLE run. GitHub Code Scanning
# rejects multiple runs sharing one upload category (as of 2025-07-21 —
# https://github.blog/changelog/2025-07-21-code-scanning-will-stop-combining-multiple-sarif-runs-uploaded-in-the-same-sarif-file/),
# and this action always uploads under one category per job, so N per-file
# runs must collapse into one before upload rather than being concatenated.
out_path, *parts = sys.argv[1:]

merged_doc = None
merged_run = None
rules_by_id: dict[str, dict] = {}
results: list[dict] = []
taxonomy_meta_by_name: dict[str, dict] = {}  # taxonomy name -> its non-taxa fields
taxa_by_name: dict[str, dict[str, dict]] = {}  # taxonomy name -> {taxon id: taxon}

for p in parts:
    with open(p, encoding="utf-8") as fh:
        doc = json.load(fh)

    for run in doc["runs"]:
        results.extend(run["results"])

        driver = run["tool"]["driver"]
        for rule in driver.get("rules", []):
            rules_by_id.setdefault(rule["id"], rule)

        for taxonomy in run.get("taxonomies", []):
            name = taxonomy["name"]
            taxonomy_meta_by_name.setdefault(
                name, {k: v for k, v in taxonomy.items() if k != "taxa"}
            )
            taxa_for_name = taxa_by_name.setdefault(name, {})
            for taxon in taxonomy.get("taxa", []):
                taxa_for_name.setdefault(taxon["id"], taxon)

        if merged_doc is None:
            merged_doc = doc
            merged_run = run

if merged_doc is None:
    raise SystemExit("no SARIF parts to merge")

merged_run["tool"]["driver"]["rules"] = list(rules_by_id.values())
merged_run["results"] = results

if taxa_by_name:
    merged_run["taxonomies"] = [
        {**taxonomy_meta_by_name[name], "taxa": list(taxa.values())}
        for name, taxa in taxa_by_name.items()
    ]

merged_doc["runs"] = [merged_run]

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(merged_doc, fh, indent=2)

print(len(results))
PYEOF
)"

{
  echo "sarif-path=$COMBINED_SARIF"
  echo "findings-count=$TOTAL_FINDINGS"
  if [[ "$OUTPUT_FORMAT" != "none" ]]; then
    echo "report-path=$REPORT_DIR"
  else
    echo "report-path="
  fi
} >> "$GITHUB_OUTPUT"

echo "Scanned ${#FILES[@]} file(s), $TOTAL_FINDINGS finding(s) total. SARIF: $COMBINED_SARIF"

exit $EXIT_CODE
