# Contributing to HDWP

## Requirements

- Python 3.12+
- Git

```bash
git clone https://github.com/devmail0561-web/hdwp
cd hdwp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Branch workflow

- `main` — stable releases only
- `feature/<short-name>` — new features, open PR against `main`
- `fix/<short-name>` — bug fixes

```bash
git checkout -b feature/my-improvement
# work, then:
git push origin feature/my-improvement
# open PR on GitHub
```

## Running tests

```bash
pytest tests/ -x -q                     # unit tests (fast)
pytest tests/ -x -q --ignore=tests/integration  # skip integration
```

## Adding an exploit strategy (YAML)

Strategies live in `src/hdwp/core/exploit/strategies/`. Each file must have:

```yaml
id: core.<owasp_category>.<technique>.<variant>  # unique, no spaces
name: "Human-readable name"
vuln_type: sqli                                   # matches property engine types
tech_stack: [mysql, php]                          # empty list = universal
proof_type: network                               # network | response_diff | timing
mode: sequential                                  # sequential | parallel
params: {}
phases:
  - name: detect
    inject: param_from_winning_request
    payloads:
      - "' OR '1'='1"
    success:
      type: body_contains_any
      keywords: ["syntax error", "mysql_fetch"]
    output: detect_result
```

**Rules:**
- Every new technique must have meaningfully different `payloads` or `phases` from existing ones
- CI blocks duplicates (`tools/check_strategy_dupes.py`)
- Use `_v1`, `_v2` suffixes only when the mechanism differs (different protocol, header, encoding) — not just a different payload variant

## Adding a plugin (entry point)

Expose a callable via the `hdwp.exploit_strategies` entry point group in your `pyproject.toml`:

```toml
[project.entry-points."hdwp.exploit_strategies"]
my_plugin = "my_package.strategies:load_yaml"
```

`load_yaml()` must return a valid strategy YAML string.

## Code style

```bash
ruff check src/ --select E,F,W --ignore E501
```

No trailing summaries in commit messages. Commit message = `type(scope): short imperative`.

## Checklist before opening a PR

- [ ] `pytest tests/ -x -q` passes
- [ ] `python tools/check_strategy_dupes.py` passes
- [ ] New code covered by unit tests
- [ ] `ruff check src/` clean
