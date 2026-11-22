const uploadForm = document.getElementById("email-upload");
const uploadStatus = document.getElementById("upload-status");
const actions = uploadForm.querySelectorAll('button[name="action"]');
const filePanel = document.getElementById("file-panel");
const emailFile = document.getElementById("email-file");
const chooseFile = document.getElementById("choose-file");
const selectedFile = document.getElementById("selected-file");
const sampleButton = document.getElementById("sample-email");
let submitting = false;

function showSelection(message = "") {
  const file = emailFile.files[0];
  selectedFile.textContent = file?.name ?? "";
  selectedFile.hidden = !file;
  chooseFile.textContent = file ? "Change file" : "Choose file";
  actions.forEach((button) => { button.disabled = !file; });
  uploadStatus.textContent = message;
}

function validateSelection(file) {
  if (!file || !/\.(eml|msg)$/i.test(file.name)) {
    emailFile.value = "";
    showSelection("Choose one .eml or .msg file.");
    return false;
  }
  return true;
}

function announceSelection(file) {
  showSelection(`${file.name} selected. Choose Triage or Parse.`);
}

function selectFile(file) {
  if (!validateSelection(file)) return;
  const selection = new DataTransfer();
  selection.items.add(file);
  emailFile.files = selection.files;
  announceSelection(file);
}

chooseFile.addEventListener("click", () => emailFile.click());

emailFile.addEventListener("change", () => {
  const file = emailFile.files[0];
  if (!file) showSelection();
  else if (validateSelection(file)) announceSelection(file);
});

sampleButton.addEventListener("click", () => {
  const sample = [
    "From: Taylor <taylor@example.com>",
    "To: Morgan <morgan@example.com>",
    "Subject: Team lunch",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    "Hi Morgan, lunch is in the break room at noon. See you there!",
    "",
  ].join("\r\n");
  selectFile(new File([sample], "sample-message.eml", { type: "message/rfc822" }));
});

document.addEventListener("dragover", (event) => {
  if (event.dataTransfer.types.includes("Files")) event.preventDefault();
});
document.addEventListener("drop", (event) => {
  if (event.dataTransfer.types.includes("Files")) event.preventDefault();
});
filePanel.addEventListener("dragover", (event) => {
  if (submitting || !event.dataTransfer.types.includes("Files")) return;
  event.dataTransfer.dropEffect = "copy";
  filePanel.classList.add("is-dragging");
});
filePanel.addEventListener("dragleave", (event) => {
  if (!filePanel.contains(event.relatedTarget)) filePanel.classList.remove("is-dragging");
});
filePanel.addEventListener("drop", (event) => {
  filePanel.classList.remove("is-dragging");
  if (submitting || !event.dataTransfer.types.includes("Files")) return;
  event.preventDefault();
  const files = event.dataTransfer.files;
  selectFile(files.length === 1 ? files[0] : null);
});

uploadForm.addEventListener("submit", (event) => {
  if (submitting) {
    event.preventDefault();
    return;
  }

  submitting = true;
  uploadStatus.textContent = event.submitter?.value === "parse" ? "Parsing email…" : "Triaging email…";
  // Keep the submitter enabled so the browser includes its name and value.
  actions.forEach((button) => button.setAttribute("aria-disabled", "true"));
  sampleButton.disabled = true;
});

window.addEventListener("pageshow", () => {
  submitting = false;
  sampleButton.disabled = false;
  actions.forEach((button) => button.removeAttribute("aria-disabled"));
  showSelection();
});

emailFile.hidden = true;
chooseFile.hidden = false;
sampleButton.hidden = false;
showSelection();
