# emailscan

Typed event assessment with DSPy and Jev

This Python 3.13 project assesses one security event with Jev. DSPy sends the
event and the three judgments from `signatures.py` in a single request.

## Run the example

```sh
uv sync
cp .env.example .env
# Set DSPY_API_KEY in .env or export TYPESAFE_API_KEY in your shell.
uv run emailscan --text "Multiple failed logins preceded a successful login."
```

The same arguments work with `uv run python -m emailscan`.
The CLI writes one JSON object to stdout. A provider or result validation
failure exits with status 1 and writes a diagnostic to stderr. Missing or
blank input exits with status 2.

| Field | Meaning |
| --- | --- |
| `investigate` | Noul boolean and probability that the event warrants investigation |
| `risk` | Score with a continuous value from 0 to 4 and a zero-based level |
| `category` | Choice of `credential_attack`, `malware`, `lateral_movement`, or `benign` |
| `usage` | Model usage reported by DSPy, included when available |

The risk levels are Benign, Low risk, Moderate risk, High risk, and Critical
risk, in that order. To adapt the example, edit the input description and
decision criteria in `signatures.py`, then update the JSON validation in
`models.py` if you change the output fields or allowed values.

## Configuration

The default model is `typesafe:jev-latest`. The settings layer
reads `DSPY_MODEL`, `DSPY_API_KEY`, `DSPY_API_BASE`, `DSPY_LM_KWARGS`, and
`DSPY_TRACK_USAGE`. CLI overrides take precedence over the environment,
followed by `.env` and the built-in defaults.

An explicit `DSPY_API_KEY` is passed to DSPy. With no explicit key, the native
TypeSafe provider reads an exported `TYPESAFE_API_KEY`. Use `DSPY_API_KEY` when
storing the key in the generated project's `.env`. `DSPY_API_BASE` optionally
overrides the TypeSafe base URL. Keep `DSPY_LM_KWARGS` empty for the example
unless you need a supported LM option such as disabling the request cache
with `{"cache": false}`.

Set `MLFLOW_TRACKING_URI` to enable optional DSPy tracing. Use
`MLFLOW_EXPERIMENT_NAME` to choose the experiment and `--no-tracing` or
`MLFLOW_ENABLED=false` to disable tracing for a run.

## Checks

```sh
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv build
```

The offline integration test uses DSPy's decision adapter and TypeSafe
provider with a stubbed HTTP transport. The example command above is the
live smoke test and sends the supplied synthetic event to TypeSafe.
