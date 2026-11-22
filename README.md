# Phishcheck

Parse and triage an Outlook `.msg` or RFC 822 `.eml` file from the command
line or a local webpage.

## Install and run

From a checkout, install the command with `uv tool install .` or run it
without installing with `uvx --from . phishcheck --help`. After publication,
the corresponding commands are `uv tool install phishcheck` and
`uvx phishcheck --help`.

```sh
phishcheck parse file.eml
phishcheck triage file.msg --json
phishcheck serve
phishcheck serve -p 9000
```

`parse` shows headers, body, link text and destinations, attachment findings,
and extraction status. `triage` shows a final verdict, phishing evidence strength on a 0–4 scale,
and the supported findings. **Needs review** means the model selected review
or a probability or evidence check held back its choice. The default output is text. Use `--json`
for one JSON result on stdout and diagnostics on stderr. An invalid input
exits with status 2. A runtime failure exits with status 1 and preserves
any recovered parse report.

`serve` prints the URL and binds to loopback by default. It starts at port
8000 and tries the next port if needed. An explicit port must be available.
Use the **Parse** and **Triage** buttons on the upload form.

## Extraction and deployment

Install `msgconvert` to read Outlook files. On Debian, install
`libemail-outlook-message-perl` and `libemail-address-perl`. Set `PHISHCHECK_TIKA_URL` to an Apache Tika
Server for attachment text and metadata extraction and for email body
fallback. When extraction is unavailable, the report identifies the
affected evidence and retains the data recovered so far.

```sh
docker run --rm -p 127.0.0.1:9998:9998 apache/tika:4.2.0-2
```

In another terminal, run
`PHISHCHECK_TIKA_URL=http://127.0.0.1:9998 phishcheck parse file.eml`.

Compose includes `msgconvert`, Tika, and MLflow. It exposes the app at
`http://127.0.0.1:8000` by default. Set `PHISHCHECK_PORT` to change the host
port. Copy `.env.example` to `.env` to configure triage.

```sh
docker compose up --build -d
docker compose exec app phishcheck --help
```

## Provider and history

Only triage sends selected evidence to the configured decision provider.
The default model is `typesafe:jev-latest` through the TypeSafe System One
API. Set `DSPY_API_KEY` or export `TYPESAFE_API_KEY`. The CLI's provider
overrides take precedence over environment variables, then `.env`, then
built-in defaults. Set `DSPY_API_BASE` for a System One-compatible endpoint.

CLI and web runs save the original filename and exact uploaded bytes,
the complete parsed email, and any triage inputs, responses, judgments,
labels, verdict, and diagnostics in SQLite. Use `PHISHCHECK_DATABASE_PATH`
to set the path. The default is `$XDG_DATA_HOME/phishcheck/history.sqlite`
or `~/.local/share/phishcheck/history.sqlite`. Compose stores it in the
`phishcheck-data` volume. The first release saves history for later viewing.

MLflow tracing requires a tracking URI and `MLFLOW_ENABLED=true`.
Compose supplies the URI. `MLFLOW_EXPERIMENT_NAME` sets the experiment and
`triage --no-tracing` disables tracing for one CLI run.

## Checks

```sh
uv lock --check
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv build
docker compose config --quiet
```

Run the shared EML corpus from a sibling `emlparser` checkout:

```sh
export PHISHCHECK_EML_FIXTURES=../emlparser/emailparser/tests/fixtures/eml
uv run pytest tests/test_eml_corpus.py -q
PHISHCHECK_LIVE_TESTS=1 uv run pytest tests/test_eml_corpus.py -qs
```

The live run reads provider settings from the environment and this project's
`.env`, sends the projected evidence for every fixture to the configured provider,
and reports the verdict labels per file. Set `PHISHCHECK_TIKA_URL` in the
environment to exercise attachment extraction. Both runs use temporary SQLite
databases for test history.
