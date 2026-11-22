const uploadForm = document.getElementById("email-upload");
const uploadStatus = document.getElementById("upload-status");
const actions = uploadForm.querySelectorAll('button[name="action"]');
let submitting = false;

uploadForm.addEventListener("submit", (event) => {
  if (submitting) {
    event.preventDefault();
    return;
  }

  submitting = true;
  uploadStatus.textContent = event.submitter?.value === "parse" ? "Parsing email…" : "Triaging email…";
  // Keep the submitter enabled so the browser includes its name and value.
  actions.forEach((button) => button.setAttribute("aria-disabled", "true"));
});

window.addEventListener("pageshow", () => {
  submitting = false;
  uploadStatus.textContent = "";
  actions.forEach((button) => button.removeAttribute("aria-disabled"));
});
