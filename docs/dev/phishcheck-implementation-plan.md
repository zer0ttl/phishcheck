# Phishcheck implementation plan

Implement the [first-release design](phishcheck-design.md) in three working increments. Deliver parsing and source installation first, add typed triage and history second, then expose the same services through the webpage and Compose. Use the repository's test-first workflow. Each task lists the failing behavior to capture, the implementation boundary, and the verification command. Group changes at the increment boundaries for review and commit when authorized under `AGENTS.md`.

Keep Python 3.13, `argparse`, Pydantic, DSPy, and MLflow. Add `eml-parser`, Magika, and HTTPX for parsing and extraction. Use the system `msgconvert` executable for Outlook input. Use standard-library SQLite, FastAPI with a server-rendered Jinja template, Uvicorn, and Docker Compose. Use only public dependencies, synthetic fixtures, and placeholder configuration in repository files.

## File map

| Files | Responsibility |
| --- | --- |
| `pyproject.toml`, `uv.lock`, `src/phishcheck/`, `tests/` | Package rename, console and module entry points, and locked Python dependencies. |
| `src/phishcheck/config.py`, `tracing.py` | Application, provider, and tracing settings. |
| `src/phishcheck/models.py` | Validated reports, extraction results, judgments, and verdicts. |
| `src/phishcheck/parsing.py`, `extraction.py` | Intake, format detection and validation, conversion, MIME normalization, and Tika client. |
| `src/phishcheck/signatures.py`, `modules.py`, `triage.py` | Decision questions and DSPy integration, model input projection, evidence checks, and verdict rules. |
| `src/phishcheck/history.py`, `service.py` | SQLite records and shared parse and triage orchestration. |
| `src/phishcheck/cli.py`, `web.py`, `templates/index.html` | CLI commands, output formatting, port binding, and the single-page upload and report. |
| `Dockerfile`, `.dockerignore`, `compose.yaml`, `.env.example`, `README.md` | Container deployment and public setup instructions. |

Paths in the table are rooted at the repository. After the rename, all tests import `phishcheck`.

## Increment 1 · Source installation and parsing

### 1. Rename the package and establish the CLI contract

**Files to edit** `pyproject.toml`, `uv.lock`, `src/emailscan/` → `src/phishcheck/`, `tests/`, `.env.example`, `README.md`.

- [ ] Add `test_public_entry_points` in `tests/test_cli.py`. Assert that `importlib.metadata.distribution("phishcheck")` supplies `phishcheck = phishcheck.cli:main`, and that `python -m phishcheck --help` exits successfully without loading credentials. Run `uv run pytest tests/test_cli.py -k public_entry_points -q` and verify the existing distribution fails the new check.
- [ ] Update the project metadata, Hatch wheel package, script target, Ruff first-party package, imports, module entry point, and user-facing defaults. Refresh `uv.lock` with `uv lock`. Preserve the existing event example temporarily so the provider and tracing tests stay runnable through this task. Remove the example when email triage replaces it in task 6.
- [ ] Run `uv run pytest -q`, `uv build`, and `uvx --from . phishcheck --help`. Verify that the wheel contains `phishcheck` and the executable and module entry points resolve identically. Smoke-test `uv tool install .` in an isolated uv tool directory so the verification leaves user tools alone.

### 2. Add bounded intake, Magika detection, and Outlook conversion

**Files to edit** `src/phishcheck/config.py`, `models.py`, `parsing.py`, `tests/test_parsing.py`, `tests/fixtures/`, `pyproject.toml`, `uv.lock`.

- [ ] Create synthetic fixtures `tests/fixtures/plain.eml` and `tests/fixtures/outlook.msg`. The EML should have RFC 822 headers, a text body, and an inert `example.com` URL. Create the MSG from a synthetic message or use a redistribution-compatible public fixture with its provenance documented in `tests/fixtures/README.md`. Assert that a valid EML with a generic Magika result passes structural validation, a renamed unrelated file fails with its detection result, and a `.msg` goes through conversion before the MIME parser. Cover missing executable, malformed conversion, timeout, and oversized input separately. Run `uv run pytest tests/test_parsing.py -q` and check the new behaviors fail.
- [ ] Implement `read_email(stream, filename, settings) -> EmailInput` and `normalize_email(source, settings) -> bytes`. Read through the configured bound plus one byte to detect overflow. Retain a SHA-256 of the original bytes for run history. Normalize Magika's status, output label, MIME type, and score from `Magika().identify_bytes(...)`, accessing prediction fields only for a successful result. A generic result allows structural validation. An unrelated format with a spoofed extension must still fail validation. Validate plausible RFC 822 structure before accepting arbitrary text as EML. For ambiguous Outlook input, require a plausible compound-file signature and validate the converted output as email.
- [ ] Invoke `msgconvert` with an argv list and private generated paths, with no shell or file-derived command arguments. Use `msgconvert --outfile` to produce one EML, enforce a conversion timeout, and bound the converted output before reading it. Report a missing executable or timeout as a runtime failure. Treat invalid or unparseable conversion output as invalid email. Remove temporary files on every path and exclude child stderr content from public errors.
- [ ] Run `uv run pytest tests/test_parsing.py -q`. Verify a real `msgconvert` run against the MSG fixture during the Compose smoke test. Mock the subprocess boundary in the ordinary test suite so it also runs on a machine without Perl. [Magika Python API](https://securityresearch.google/magika/cli-and-bindings/python/) · [msgconvert manual](https://manpages.debian.org/trixie/libemail-outlook-message-perl/msgconvert.1p.en.html)

### 3. Normalize EML and add Tika extraction

**Files to edit** `src/phishcheck/parsing.py`, `extraction.py`, `models.py`, `config.py`, `tests/test_parsing.py`, `tests/test_extraction.py`, `pyproject.toml`, `uv.lock`.

- [ ] Add tests for plain text, multipart alternatives, HTML-only content, attachment-only mail, malformed body text, and mixed attachment outcomes. For attachment extraction, assert that the request contains the decoded attachment bytes and targets only the configured Tika URL. Use an HTTPX mock transport for a response with `X-TIKA:content`, a timeout, a malformed response, and a response over the configured limit. Assert that intact text and attachment-only mail make no Tika body request. Run `uv run pytest tests/test_parsing.py tests/test_extraction.py -q` and verify the new cases fail before implementation.
- [ ] Implement `parse_email(source, settings, tika) -> ParseReport`. Configure `eml_parser.EmlParser` to return raw body, links including HTML hrefs, and attachment data. Feed it the EML bytes from `normalize_email`. Use the MIME alternatives to prefer plain text and derive readable text from HTML-only mail through a parser that reads markup without fetching resources. Preserve the link targets as data. Keep body state explicit with `complete`, `absent`, `unavailable`, and `truncated` outcomes. Call Tika for message-body text only when the body exists and text recovery fails. If using recursive metadata for the fallback, select the message entry and exclude embedded attachment text from the message body.
- [ ] Implement `TikaClient.extract(data) -> ExtractedContent` with an HTTPX request to `PUT /rmeta/text` for attachment text and metadata. Stream and bound the response before decoding JSON. Read `X-TIKA:content` from each returned record and retain its metadata and embedded-resource identity. Apply timeouts, disable redirects, and map unset URL, server failures, and invalid responses to extraction status. Keep independent attachment outcomes after failures. Record each processed attachment's declared name and MIME type, Magika result, extraction metadata, and text. Retain all recovered body parts, full headers, and extraction details for history. Report skipped or truncated evidence at the attachment or report level. Keep decoded bytes outside the public report.
- [ ] Add `PHISHCHECK_TIKA_URL` to application settings. Use provisional defaults of 25 MiB for input and converted email, 20 attachments, 10 MiB per attachment, 15 seconds for conversion, 10 seconds per Tika request within a 30-second extraction budget, and 1 MiB per Tika response. Bound reads and processing before crossing these limits and make limit-related omissions visible. Revisit the numbers only if the representative fixtures expose a concrete problem.
- [ ] Run `uv run pytest tests/test_parsing.py tests/test_extraction.py -q`. Confirm that missing Tika still produces a partial report for mail that needs extraction and that plain `.eml` parsing works without a Tika server. [eml-parser configuration](https://eml-parser.readthedocs.io/en/latest/) · [Tika Server API](https://github.com/apache/tika/blob/main/docs/modules/ROOT/pages/using-tika/server/index.adoc)

### 4. Expose `parse` in the CLI

**Files to edit** `src/phishcheck/cli.py`, `service.py`, `tests/test_cli.py`, `README.md`.

- [ ] Add CLI tests for default text, redirected stdout, one JSON report with `--json`, partial extraction returning `0`, invalid email returning `2` with Magika on stderr, and runtime failure returning `1`. Assert that parsing and help leave the provider and tracing untouched. Run `uv run pytest tests/test_cli.py -q` and check that the new CLI cases fail.
- [ ] Wire the `parse FILE [--json]` subcommand to `service.parse`, which wraps bounded intake and `parse_email`. Keep exit mapping in `cli.py` and use the same report model for both renderers. Include headers, body, URLs, attachments, and extraction status in text. Normalize untrusted control characters in terminal text and diagnostics. JSON uses the model serializer for escaping and emits exactly one document on success. In JSON mode, write a structured invalid-email diagnostic with Magika to stderr. Keep actionable diagnostics free of raw data and absolute paths.
- [ ] Run `uv run pytest -q`, `uv run phishcheck parse tests/fixtures/plain.eml`, and `uvx --from . phishcheck parse tests/fixtures/plain.eml --json`. If `msgconvert` is installed, run `uv run phishcheck parse tests/fixtures/outlook.msg --json` as a converter smoke check.

## Increment 2 · Typed triage and SQLite history

### 5. Add decision questions, evidence projection, and verdict rules

**Files to edit** `src/phishcheck/signatures.py`, `models.py`, `triage.py`, `tests/test_triage.py`.

- [ ] Add table-driven tests for the 26 approved classification values, inclusive `0.20` and `0.80` boundaries, uncertainty, insufficient evidence despite a high score, and multiple supported attack labels. Cover all four headline choices, the 80% boundary, conflicting attack findings, incomplete evidence for benign choices, and a supported benign explanation. Assert that the projection contains only selected fields and that the serialized model state stays within its budget, including non-ASCII content. Run `uv run pytest tests/test_triage.py -q` and verify failure before implementing the rules.
- [ ] Add one typed Noul judgment per approved question. Use the stable lowercase classification values from the [design's judgment table](phishcheck-design.md#judgment-questions) as identifiers. Keep question text and criteria together in `signatures.py`. Validate probabilities as finite numbers in `[0, 1]`. Report each judgment as `supported`, `unsupported`, `uncertain`, or `insufficient_evidence`. An insufficient-evidence result carries the missing evidence field and no inferred probability.
- [ ] Implement `project_evidence(report) -> DecisionEvidence` with named, selected sender and authentication headers, subject, body text, inert link records with anchor text and destination, attachment findings, and evidence availability. Start with a 16 KiB serialized state budget, accounting for UTF-8, JSON escaping, and availability fields. Truncate visible evidence in a stable order and record omissions. Keep original MIME, raw bytes, path, and arbitrary metadata outside the request. Present deterministic field references alongside relevant judgments.
- [ ] Apply evidence gates before a score contributes to a verdict. For example, a failed attachment extraction and an absent attachment are different states. An unavailable destination behavior cannot substantiate `drive_by_download`. Campaign variants require multiple corroborated samples. Sender compromise requires independent account evidence. Thread hijacking and trusted third-party impersonation require appropriate thread or relationship evidence. In v1 a file alone cannot establish `phishing_simulation` or `incorrectly_submitted`. Never treat a claim inside the email as trusted corroboration.
- [ ] Add a typed email verdict Choice, a five-level phishing evidence Score, and a Noul for a benign explanation to the same request as the finding questions. Apply the headline verdict rules in the design and keep attack labels in taxonomy order. Store the complete result and review reasons. Verify the verdict gates and partial-evidence cases with `uv run pytest tests/test_triage.py -q`.

### 6. Replace the event example with typed email triage

**Files to edit** `src/phishcheck/modules.py`, `signatures.py`, `config.py`, `tracing.py`, `service.py`, `cli.py`, `tests/test_program.py`, `tests/test_cli.py`, `tests/test_config.py`, `tests/test_tracing.py`, `.env.example`, `README.md`.

- [ ] Adapt the stubbed native provider round-trip test to accept an `.eml` file, assert one native decision request, inspect the projected email state and typed question definitions, and return typed fixture answers. Add malformed and missing-answer cases and assert a processing error rather than a fabricated verdict. Cover text and JSON verdict output, provider overrides, and parse report retention on provider error. Run `uv run pytest tests/test_program.py tests/test_cli.py tests/test_config.py tests/test_tracing.py -q` before wiring the new entry point.
- [ ] Implement the DSPy email assessor and hook it up to `service.triage`. Preserve existing `DSPY_*` configuration precedence and call the decision provider only after the file parses. Keep the model cache disabled for email triage by default. Capture the triage input and provider response payloads for the SQLite run record, including response payloads that fail typed validation. Require explicit tracing opt-in in addition to a tracking URI. Preserve the `--no-tracing` override and the existing behavior when optional tracing setup fails. Keep test transport and keys synthetic.
- [ ] Exercise the supported provider routes using the locked dependency and offline transport fixtures. Keep the native `/v1/systemone` test as the baseline. For any direct provider, LiteLLM route, or compatible `/v1/decisions` route advertised in the README, identify its typed adapter and verify the endpoint, request, and typed response with an offline test. Document verified routing and report a clear configuration error for routes that cannot return typed decisions. The code path must not fall back to a generative model.
- [ ] Expose `triage FILE [--json]` and remove the temporary generic event CLI and types. Make provider failure a runtime outcome with a sanitized diagnostic on stderr and the existing parse report on stdout. Keep **Needs review** a successful triage report. Run `uv run pytest -q` and verify CLI help lists the new subcommands.

### 7. Persist completed parse and triage attempts

**Files to edit** `src/phishcheck/history.py`, `service.py`, `config.py`, `tests/test_history.py`, `tests/test_cli.py`, `.env.example`.

- [ ] Test one row per completed parse or triage attempt, separate run IDs for the same hash, partial extraction, provider failure with recovered parse evidence, invalid input with diagnostics, and safe or attack verdicts with labels and judgments. Assert that help creates neither a row nor a database. Reopen the database from a fresh connection and load each saved report by run ID to assert that all parsed fields and triage data round-trip, including both plain-text and HTML body parts, attachment text, provider payloads, and judgments omitted from the live display. Cover a metadata-only row with no report. Run `uv run pytest tests/test_history.py -q` and confirm these cases fail first.
- [ ] Add a configurable `PHISHCHECK_DATABASE_PATH` and resolve a per-user local default outside the checkout, with Compose supplying its volume path. Use `sqlite3`, parameterized writes, and schema creation on first history write. Store the run ID, action, UTC timestamp, optional original SHA-256, terminal processing status, optional classification values, and the versioned JSON snapshot of the complete parsed email, triage data, and stage diagnostics available for that run. Write the summary and report atomically in one short transaction per attempt with a bounded lock wait. Hold no database transaction during parsing or inference. Return an actionable persistence failure while preserving any in-memory report.
- [ ] Integrate history writes into the shared parse and triage entry points. Triage uses the parsing pipeline internally and records its parse evidence in the triage row. Add a read by run ID that decodes the stored report version without invoking parsing or the decision provider. Capture all available stage data before rendering or display filtering, and serialize it without redaction or additional truncation. Run `uv run pytest tests/test_history.py tests/test_cli.py -q`.
- [ ] Store the original filename and complete upload as a BLOB in the run transaction. Capture the bytes during intake before parsing or Outlook conversion. Expose a read by run ID for future downloads. Reopen the database and verify byte-for-byte recovery of `.eml` and `.msg` uploads, including parse and provider failures. Verify that oversized uploads and read failures record the diagnostic and original-file availability without saving a partial file.

## Increment 3 · Webpage, Compose, and release checks

### 8. Add the single-page web workflow

**Files to edit** `src/phishcheck/web.py`, `templates/index.html`, `tests/test_web.py`, `pyproject.toml`, `uv.lock`.

- [ ] Add FastAPI test-client cases for `GET /`, each form action, missing and invalid uploads, oversized requests, partial extraction, and provider failure retaining the parse report. Include synthetic HTML and an inert URL as fixture content. Assert that output escapes the HTML and displays URLs without clickable anchors. Run `uv run pytest tests/test_web.py -q` and verify the new interface tests fail first.
- [ ] Implement `create_app` with `GET /` and one multipart `POST /` that accepts one file and one action. Route both actions through `service.py`. Bound request bytes and form parts before handing file data to the shared intake. Close each upload on success and failure. Use a sync worker for blocking detector, subprocess, HTTP, and database work. Use the template engine's HTML autoescape and render all message content as data. Keep provider credentials in server-side settings. Return `400` for invalid input, `413` for oversized uploads, and an error page with recovered parse content for provider failure. Successful results and **Needs review** remain `200`.
- [ ] Run `uv run pytest tests/test_web.py -q` and `uv build`. Check that the installed wheel includes the template and can render the upload page from a directory outside the checkout.

### 9. Add `serve` and Compose

**Files to edit** `src/phishcheck/cli.py`, `web.py`, `tests/test_cli.py`, `Dockerfile`, `.dockerignore`, `compose.yaml`, `.env.example`, `README.md`.

- [ ] Add tests that occupy the starting port and verify that implicit selection advances to the next port, while `serve -p` fails on an occupied port. Check that a permission or bind-address error stops selection and that the printed URL reflects the bound port. Use sockets in tests and pass the selected socket into Uvicorn, keeping the bind until the server owns it. Run `uv run pytest tests/test_cli.py -k serve -q` before implementing.
- [ ] Add `serve` with `127.0.0.1` and `8000` as defaults. Retry only address-in-use errors when no explicit port was supplied. Accept an explicit port in the range `1`–`65535`. Use a host override for container binding and report startup failures as runtime errors. Close the acquired socket on failed startup and shutdown.
- [ ] Build the locked app image with `msgconvert` from the public OS package and run the app as a non-root container user. Use `.dockerignore` to exclude local environments, credentials, Git data, and generated artifacts. Pin supported app, standard Tika, and MLflow image versions when implementing and verify they build and run. In Compose, bind the app to `0.0.0.0:8000` inside the container and expose a configurable host port on loopback. Set `PHISHCHECK_TIKA_URL=http://tika:9998` and use the Compose service directly. Tika needs no host port. Limit Tika resources and keep temporary extraction data ephemeral. Give the app SQLite database and MLflow SQLite and artifact directories separate named volumes. Leave MLflow tracing opt-in even when Compose supplies the tracking URI.
- [ ] Run `uv run pytest tests/test_cli.py tests/test_web.py -q` and `docker compose config --quiet`. Start the stack with `docker compose up --build -d` and verify startup through the published loopback address. Test a real `.msg` and a synthetic `.eml` with a known text attachment to verify conversion and Tika extraction inside the Compose app. Check the same attachment with the host CLI pointed at a loopback Tika instance as documented in the design. [Apache Tika Server images](https://github.com/apache/tika/blob/main/tika-server/docker-build/README.md) · [Uvicorn settings](https://uvicorn.org/settings/)

### 10. Verify and document the release

**Files to edit** `README.md`, `.env.example`, and any affected test or configuration from the preceding tasks.

- [ ] Document checkout installs, the published command examples, all three subcommands, text and JSON behavior, standalone `msgconvert` and Tika setup, Compose startup, settings precedence, verdict states, SQLite history, and tracing opt-in. Explain that parse and triage log the complete parsed email and triage data locally by default and that only triage sends selected evidence to the configured provider. Use public documentation links and loopback or reserved example addresses throughout.
- [ ] Run the automated release gates below. In Compose, exercise **Parse** and **Triage** using a local typed-response stub and a synthetic upload. Confirm that CLI and web actions both persist report snapshots and that the stored reports can be loaded after restarting the app. Check tracing with opt-in disabled and enabled. Confirm that `parse` produces zero provider calls. Verify that a Tika outage yields a partial report and a decision-provider outage preserves recovered evidence with a processing error in the returned and stored reports. Record any live-provider checks separately from offline verification.
- [ ] Inspect the repository, lockfile, fixtures, image build context, and wheel for private names, paths, addresses, and secrets. Verify that `phishcheck` is still the intended distribution name before public registration. Publishing is a separate release action.

```sh
uv lock --check
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv build
uvx --from . phishcheck --help
uvx --from . phishcheck parse tests/fixtures/plain.eml --json
docker compose config --quiet
```
