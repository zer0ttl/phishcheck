const uploadForm = document.getElementById("email-upload");
const uploadStatus = document.getElementById("upload-status");
const actions = uploadForm.querySelectorAll('button[name="action"]');
const filePanel = document.getElementById("file-panel");
const emailFile = document.getElementById("email-file");
const chooseFile = document.getElementById("choose-file");
const selectedFile = document.getElementById("selected-file");
const samplePicker = document.getElementById("sample-picker");
let submitting = false;

function selectedSample() {
  return samplePicker.querySelector('input[name="sample"]:checked');
}

function showSelection(message = "") {
  const file = emailFile.files[0];
  const sample = selectedSample();
  selectedFile.textContent = sample ? `Sample: ${sample.dataset.title}` : (file?.name ?? "");
  selectedFile.hidden = !file && !sample;
  chooseFile.textContent = file ? "Change file" : "Choose file";
  emailFile.required = !sample;
  actions.forEach((button) => { button.disabled = !file && !sample; });
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
  const sample = selectedSample();
  if (sample) sample.checked = false;
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

samplePicker.addEventListener("change", () => {
  const sample = selectedSample();
  if (!sample) return;
  emailFile.value = "";
  showSelection("Sample selected. Choose Triage or Parse.");
  samplePicker.open = false;
  actions[0].focus();
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
  const action = event.submitter?.value === "parse" ? "parse" : "triage";
  // Keep the submitter enabled so the browser includes its name and value.
  actions.forEach((button) => button.setAttribute("aria-disabled", "true"));
  samplePicker.inert = true;

  const sample = selectedSample();
  if (sample) {
    event.preventDefault();
    uploadStatus.textContent = "Opening saved sample…";
    const reportUrl = new URL(sample.dataset.reportUrl, location.href);
    reportUrl.searchParams.set("action", action);
    location.assign(reportUrl);
    return;
  }
  uploadStatus.textContent = action === "parse" ? "Parsing email…" : "Triaging email…";
});

window.addEventListener("pageshow", () => {
  submitting = false;
  samplePicker.inert = false;
  actions.forEach((button) => button.removeAttribute("aria-disabled"));
  showSelection();
});

emailFile.hidden = true;
chooseFile.hidden = false;
samplePicker.hidden = false;
showSelection();
