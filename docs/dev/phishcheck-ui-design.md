# PhishCheck upload and report UI

Help an analyst decide what to do with the email they just uploaded. The verdict, its reasons, and the available sender, link, and attachment evidence should be readable without opening raw JSON.

## Rendering and assets

Use Tabler components in the existing FastAPI and Jinja upload page. Pin the compiled Tabler CSS and serve it from the application. Include the asset in the installed package and container so browsers can load the page without a CDN. Use the existing multipart form and render the result on the same page. The [first-release design](phishcheck-design.md#user-workflow) describes the upload and reporting behavior this page builds on.

## Upload and report

- Use a slim header and a centered title above a white upload card with a dashed drop zone. Center the green **Triage** and outlined **Parse** buttons below the drop zone, with short descriptions of both actions under the card.
- Accept one `.eml` or `.msg` file via drag and drop or the native file picker. Offer a synthetic sample that users can select and submit with either action. Make **Triage** the primary submit action and keep **Parse** visible for inspection without a model call. Show which action is running, prevent duplicate submission while it runs, and preserve the selected action in the submitted form.
- Lead a triage report with the final verdict and its reasons. Place three evidence cards beneath it for **Sender and subject**, **Links**, and **Attachments**. Show the From and Subject headers, the display text and destination of each extracted link, and attachment names and extraction status. Place the cards side by side on wide screens and stack them on narrow screens. Label missing fields and empty evidence lists. Distinguish unavailable, truncated, and unattempted attachment extraction using the recorded status.
- Put the message body, model answers, and raw JSON behind disclosures. Show model probabilities with Tabler progress bars and visible percentage labels. For scored findings, show Yes and No as two segments of one bar. Give unscored findings a text explanation when the report provides one. Render email-derived values as escaped text throughout. Show extracted links as plain text without navigation.
- When space allows, place Verdict probabilities and Evidence strength probabilities side by side. Lay out Individual findings in three columns beneath them. Stack both groups on narrow screens.
- Color verdict bars red for likely phishing, amber for needs review, green for likely legitimate, and slate for unsolicited bulk email. Use progressively darker blue for higher evidence-strength scores. Use red for Yes on attack findings, green for Yes on a benign explanation, and neutral gray for No. Keep the category and percentage visible in text.
- Show the same evidence sections for Parse runs. If the triage provider fails, show the error and any recovered evidence together. Keep upload and persistence errors visible.

Saved-run browsing is deferred. The existing CLI, service, report models, and history storage support the current workflow.

## Verification

- Submit a representative email with Triage. Check that the verdict, reasons, sender, subject, link pairs, and attachment names and statuses are visible with the disclosures closed. Open the disclosures and check that the message body, model answers, and raw JSON are available.
- Submit the same file with Parse and check that it shows the evidence without a verdict. Simulate a provider failure and check that its error appears alongside the recovered evidence.
- Check that the waiting state names the selected action, blocks a second submission, and sends the selected action to the server. Verify the page loads its styles from the installed application with external browser requests blocked.
- Retain the web regression checks for invalid and oversized uploads, escaped email content, inert links, and partial reports.
