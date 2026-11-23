# PhishCheck upload and report UI

Help an analyst decide what to do with the email they just uploaded. The verdict, its reasons, and the available sender, link, and attachment evidence should be readable without opening raw JSON.

## Rendering and assets

Style the FastAPI and Jinja upload and report page with Tailwind CSS. Serve the compiled CSS locally from the installed Python package. Use the existing multipart form and render the result on the same page. The [first-release design](phishcheck-design.md#user-workflow) describes the upload and reporting behavior this page builds on.

Docker Compose compiles CSS automatically with the standalone Tailwind CLI. When Jinja classes or Tailwind styles change, refresh the checked-in CSS for Python installs. Run this command from the repository root with the [Tailwind v4.3.5 standalone CLI](https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.3.5) on your PATH.

```sh
tailwindcss -i src/phishcheck/tailwind.css -o src/phishcheck/static/phishcheck.css --minify
```

For a new component, use the HTML version of a collection such as [HyperUI](https://www.hyperui.dev/) in a Jinja template. Keep each Tailwind class name complete in the template so the compiler can find it. Interactive components may also need their documented script and a keyboard check.

## Upload and report

- Use a slim header and a centered title above a white upload card with a dashed drop zone. Center the charcoal **Triage** and outlined **Parse** buttons below the drop zone, with short descriptions of both actions under the card.
- Accept one `.eml` or `.msg` file via drag and drop or the native file picker. Offer a synthetic sample that users can select and submit with either action. Make **Triage** the primary submit action and keep **Parse** visible for inspection without a model call. Show which action is running, prevent duplicate submission while it runs, and preserve the selected action in the submitted form.
- When a report is available, replace the upload panel with the filename, run status, and **Analyze another email**. Lead Triage with the verdict and reasons. Lead Parse and partial Triage with the subject and sender.
- Group evidence in a two-column section that stacks on narrow screens. Show the subject and sender on one side, with a disclosure for Reply-To or Return-Path when available. Show link counts, display text and destinations, and attachment names and extraction status on the other side. Label missing fields and empty evidence lists.
- Group **Message body**, **Headers**, and **Raw JSON** in tabs, with the message body visible first. Keep **Model answers** in a disclosure below the verdict. Show model probabilities with progress bars and visible percentage labels. For scored findings, show Yes and No as two segments of one bar. Give unscored findings a text explanation when the report provides one. Render email-derived values as escaped text throughout. Show extracted links as plain text without navigation.
- When space allows, place Verdict probabilities and Evidence strength probabilities side by side. Lay out Individual findings in three columns beneath them. Stack both groups on narrow screens.
- Color verdict bars red for likely phishing, amber for needs review, green for likely legitimate, and slate for unsolicited bulk email. Use progressively darker blue for higher evidence-strength scores. Use red for Yes on attack findings, green for Yes on a benign explanation, and neutral gray for No. Keep the category and percentage visible in text.
- Show the same evidence sections for Parse runs. If the triage provider fails, show the error and any recovered evidence together. Keep upload and persistence errors visible.

Saved-run browsing is deferred. The existing CLI, service, report models, and history storage support the current workflow.

## Verification

- Submit a representative email with Triage. Check that the report starts with the verdict and that **Analyze another email** returns to the upload form. Check that sender, subject, link pairs, and attachment names and statuses are visible. Use the message tabs to inspect the body, all headers, and raw JSON. Open the model answers to inspect their probabilities.
- Submit the same file with Parse and check that it shows the evidence without a verdict. Simulate a provider failure and check that its error appears alongside the recovered evidence.
- Check that the waiting state names the selected action, blocks a second submission, and sends the selected action to the server. Verify the page loads its styles from the installed application with external browser requests blocked.
- Retain the web regression checks for invalid and oversized uploads, escaped email content, inert links, and partial reports.
