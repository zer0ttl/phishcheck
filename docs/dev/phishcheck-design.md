# Phishcheck first-release design

## User workflow

Phishcheck is a single-analyst tool for examining one `.eml` or Outlook `.msg` file at a time. The CLI and a locally hosted webpage share the same parsing and triage services. Code extracts evidence, applies classification rules, and renders results. A configured decision model provides typed judgments about the email.

The Python distribution, import package, module entry point, and console script all use `phishcheck`. The Git repository can keep its existing name. From a checkout, `uv tool install .` installs the tool and `uvx --from . phishcheck --help` runs it. After publication, the corresponding commands are `uv tool install phishcheck` and `uvx phishcheck --help`. PyPI returned HTTP 404 from both public package endpoints for `phishcheck` on November 20, 2026. Claiming the name remains a release step. [uv tools guide](https://docs.astral.sh/uv/guides/tools/) · [PyPI package index API](https://docs.pypi.org/api/index-api/)

| Command | Behavior |
| --- | --- |
| `phishcheck parse file.eml` | Show headers, body, URLs, attachments, and extraction status. |
| `phishcheck triage file.msg` | Show the verdict first, followed by its basis and the parse report. |
| Either command with `--json` | Emit one structured report on stdout. Keep diagnostics on stderr. The default text report also applies when stdout is redirected. |
| `phishcheck serve` | Bind to loopback and try ports in order from `8000`, retrying when a port is occupied. Print the bound URL. |
| `phishcheck serve -p 9000` | Bind to port `9000` or report a startup error. |

Use exit status `0` for a returned report, including a partial report or **Needs review**. Use `1` for runtime failures and `2` for argument or invalid email input errors. Invalid file diagnostics include Magika's reported result if detection ran. In JSON mode, emit structured diagnostics on stderr. A provider failure leaves the parse report available on stdout and is reported on stderr with exit status `1`.

The webpage accepts one upload and offers **Parse** and **Triage**. It shows the report or input error on the same page. It displays email bodies and extracted text as escaped text and suspicious links as inert evidence. It also preserves the parse report when the decision provider fails. SQLite history has no webpage view in this release.

## Parsing and extraction

1. Run Magika on the uploaded file and retain its reported type and score when available. Use the extension as a hint and validate the expected email structure. An ambiguous or generic Magika result can proceed to format validation. Reject input that cannot be recognized or parsed as an email, and show Magika's result with the error.
2. For Outlook `.msg`, use `msgconvert` to produce RFC 822 message bytes in a private temporary workspace. Pass converted bytes and native `.eml` bytes through the same `eml-parser` workflow. Missing `msgconvert` is an actionable runtime dependency error for `.msg`.
3. Extract structured headers, body parts, links, and attachments through `eml-parser`. Normalize the output into an application report. Retain all recovered body parts, including plain-text and HTML alternatives. Prefer plain text for display and derive readable text from an HTML-only body without loading external resources. If the parser identifies a body but cannot recover its text, try Apache Tika as the last-resort text extractor. Mark an attachment-only email as having no body when the available structure supports that conclusion.
4. Run Magika on decoded attachments. Use Apache Tika Server's HTTP API to extract text and metadata. Keep attachment-level outcomes and warnings in the report. Report the detected types and names separately from the message-declared types and names where both are available. Do not include raw attachment bytes in the report.
5. Return the evidence recovered so far when a body fallback or individual attachment fails. Make extraction gaps and truncation visible. Treat link destinations and attachment content as data for static analysis. The workflow does not visit links, load remote email content, or execute attachments.

Bound intake, attachment count and size, extraction time and output, and the model payload. Capture a visible status when a limit skips or truncates evidence. Clean up temporary files on success and failure. Start with the standard Tika image for native document text and metadata. OCR belongs in a later release. [eml-parser documentation](https://eml-parser.readthedocs.io/en/latest/) · [Magika content types](https://securityresearch.google/magika/core-concepts/models-and-content-types) · [msgconvert manual](https://manpages.debian.org/trixie/libemail-outlook-message-perl/msgconvert.1p.en.html) · [Tika Server API](https://github.com/apache/tika/blob/main/docs/modules/ROOT/pages/using-tika/server/index.adoc)

## Typed triage

Only an explicit `triage` command or **Triage** click calls the configured provider. Reuse the repository's DSPy configuration and typed decision path. The existing native TypeSafe `/v1/systemone` integration provides the first verified baseline. Retain the configured direct, LiteLLM, and compatible API routes where they support typed decisions. Require typed results and surface provider or response-validation failures as processing errors.

Send a bounded structured payload containing selected headers, normalized body text, link records, and relevant attachment findings. Each link record pairs the displayed text with the destination. HTML anchors take precedence when an HTML body is recovered. Plain-text URLs use the destination as their text. Include extraction availability in state so a missing field is distinguishable from an examined field with no finding. Send no original email or attachment bytes. Display source fields and typed judgments relevant to the verdict so the analyst can inspect its basis. The model does not generate a written explanation. [TypeSafe typed questions](https://docs.typesafe.ai/llms.txt)

### Judgment questions

| Classification | Question |
| --- | --- |
| `credential_harvesting` | Does the message appear designed to obtain credentials, one-time codes, or other authentication secrets under a pretext? |
| `drive_by_download` | Does the evidence indicate that visiting a linked destination would trigger an unwanted download or execution without a deliberate download step? |
| `reconnaissance` | Does the message appear designed to gather information that could support a later attack, such as reporting lines, contact details, or internal processes? |
| `reply_solicitation` | Is eliciting a reply the apparent objective of a suspicious message, for example to confirm that the mailbox is monitored or move the conversation forward? |
| `spoofing` | Does the available sender, envelope, or authentication evidence indicate falsification of the apparent sending address or domain? |
| `malicious_attachment` | Does the extracted attachment evidence indicate that opening or interacting with the attachment could advance the attack? |
| `malicious_url` | Does the available evidence indicate that a linked destination serves a malicious purpose? |
| `malicious_web_app_integration` | Is the recipient being steered toward granting permissions to a web app integration that appears intended for unauthorized access? |
| `malware` | Does the available evidence indicate delivery of software intended to execute malicious behavior? |
| `compromised_sender` | Does corroborating evidence indicate that the message came from a real sender account under unauthorized control? |
| `email_thread_hijacking` | Does thread evidence indicate that the message inserts an attacker-controlled request into an existing legitimate conversation? |
| `financial_fraud` | Does the message appear designed to induce an unauthorized payment, divert funds, or change payment details? |
| `webmail_abuse` | Does the message appear to abuse a webmail service or account to deliver or facilitate the attack? |
| `high_value_target` | Does the lure appear tailored to a recipient because of their authority, access, or financial decision-making power? |
| `opportunistic` | Does the evidence support broad, opportunistic distribution of this lure? |
| `targeted` | Does the lure use recipient- or organization-specific details that indicate deliberate targeting? |
| `polymorphic` | Do corroborated campaign samples show deliberate changes to the message, links, or attachments while preserving the same attack objective? |
| `impersonation` | Does the message deceptively pose as a different person or organization? |
| `government_agency_impersonation` | Does the message deceptively pose as a government agency or official acting in that capacity? |
| `third_party_impersonation` | Does the message deceptively pose as an organization external to the recipient? |
| `trusted_third_party_impersonation` | Does the message deceptively pose as an external party with a known trusted relationship to the recipient? |
| `vip_impersonation` | Does the message deceptively pose as a named executive or other high-profile person? |
| `incorrectly_submitted` | Does submission context establish that this message was submitted by mistake or is outside the queue's scope? |
| `legitimate_email` | Does the available evidence affirmatively support a genuine sender and legitimate purpose? |
| `unsolicited_email` | Does the evidence support unsolicited bulk or promotional email with an ordinary commercial or nuisance purpose? |
| `phishing_simulation` | Does trusted context establish that the message belongs to an authorized phishing simulation? |

### Verdict rules

Code applies the following rules to the typed answers and extraction state.

- A reported probability of `0.80` or higher supports an applicable judgment. A probability of `0.20` or lower gives an evaluated but unsupported judgment. A probability between those thresholds gives an uncertain judgment. A required evidence source that is missing gives an insufficient-evidence result regardless of the model score. The thresholds are initial values to verify against representative mail.
- Jev chooses Likely phishing, Likely legitimate, Unsolicited bulk email, or Needs review. It also rates phishing evidence strength on a 0–4 rubric and judges whether the email itself supports an ordinary explanation for the suspicious feature.
- Show Needs review when Jev chooses it or the winning choice has less than 80% probability. Hold back legitimate and bulk-email choices if there are supported attack findings or incomplete evidence. Hold back a phishing choice if the probability of a supported benign explanation is at least 80%. Keep all applicable reasons and all supported attack findings.
- Show the final verdict first and the evidence score alongside the supported findings. The score measures evidence strength. A provider failure is a processing error, and any recovered parse report remains available.

## Deployment, history, and tracing

The recommended deployment uses Docker Compose with an app container, an official Tika Server container, and an MLflow container. In Compose, set `PHISHCHECK_TIKA_URL` to `http://tika:9998` so the app and CLI running in the app container can use Tika by service name. Tika needs no published host port in this deployment. Include `msgconvert` in the app image. Use a fixed app port inside the container and a configurable host port, published on loopback by default.

### Tika for the standalone CLI

When running `phishcheck` on the host via `uv tool install` or `uvx`, set `PHISHCHECK_TIKA_URL` to an existing Tika Server. For a local instance, run the official image bound to loopback.

```sh
docker run --rm -p 127.0.0.1:9998:9998 apache/tika
```

Then run the CLI in another terminal.

```sh
PHISHCHECK_TIKA_URL=http://127.0.0.1:9998 phishcheck parse file.eml
PHISHCHECK_TIKA_URL=http://127.0.0.1:9998 uvx --from . phishcheck triage file.msg
```

The `uvx --from .` example runs from a source checkout. Both commands use the same setting. The CLI calls Tika for attachment text and metadata and for last-resort email body text extraction. If Tika is needed and the URL is unset or the service is unavailable, return the evidence recovered so far and mark affected body or attachment extraction as incomplete. [Apache Tika Server](https://github.com/apache/tika/blob/main/tika-server/README.md)

### History and tracing

Use a named volume for the application's SQLite database. Record each completed parse or triage attempt under its own run ID with the action, UTC timestamp, original file's hash when available, processing status, and verdict where present. The CLI and webpage use the same storage policy. Repeated submissions of the same file have separate run IDs.

Log the complete parsed email and triage data to SQLite by default in a versioned JSON snapshot. Save the filename, format detection results, all recovered headers and body parts, URLs, attachment metadata and extracted text, and every extraction outcome and warning. Save the triage input and provider response payloads, every typed judgment with its probability and evidence status, all assigned labels, and the final verdict. Capture data as each stage produces it so a failed stage still leaves a record of the evidence and diagnostics available at that point. Persist the snapshot without redaction, display filters, or additional storage-time truncation.

Store the original filename and exact uploaded bytes as a SQLite BLOB in the same transaction as the run snapshot. Capture the bytes before parsing or Outlook conversion, including when a fully received file fails to parse or triage. If intake rejects an oversized upload or the stream ends with a read error, record the failure and mark the original unavailable.

A future history page can list run metadata, load the saved snapshot by run ID to show the original results without another provider call, and offer the original upload as a download when available. It applies the same escaping and inert URL rendering as the live report. Keep stored report versions readable as the report model changes. If a row contains only metadata, the detail view shows the available fields and indicates that the report was never saved.

Back MLflow with a separate SQLite database and artifact directory in its own volume. Reuse the existing MLflow integration and keep content-bearing traces opt-in even when the service is running. Display or document the tracing setting where an operator configures triage.

## Delivery and verification

1. Rename the distribution, Python package, and CLI to `phishcheck`. Verify the wheel, checkout installation, help, and `parse` using `.eml` and `.msg` fixtures.
2. Add the typed decision signature, verdict rules, and SQLite history. Use an offline provider test to verify request projection, classification, partial evidence, and provider errors. Include cases where safe and attack signals conflict and where the evidence is insufficient.
3. Connect the webpage and Compose deployment to the same services. Verify both upload actions, invalid input diagnostics, escaped reports, default and explicit port behavior, end-to-end attachment extraction, history persistence after restart, and optional MLflow tracing.
