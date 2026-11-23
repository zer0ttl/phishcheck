const messageDetails = document.getElementById("message-details");
const tabList = messageDetails.querySelector('[role="tablist"]');
const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));
const panels = tabs.map((tab) => document.getElementById(tab.getAttribute("aria-controls")));

function selectTab(selectedIndex) {
  tabs.forEach((tab, index) => {
    const selected = index === selectedIndex;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    panels[index].hidden = !selected;
  });
}

tabs.forEach((tab, index) => {
  const panel = panels[index];
  panel.setAttribute("role", "tabpanel");
  panel.setAttribute("aria-labelledby", tab.id);
  panel.tabIndex = 0;
  panel.querySelector(".report-panel-heading").hidden = true;

  tab.addEventListener("click", () => selectTab(index));
  tab.addEventListener("keydown", (event) => {
    let nextIndex;
    switch (event.key) {
      case "ArrowLeft":
        nextIndex = (index + tabs.length - 1) % tabs.length;
        break;
      case "ArrowRight":
        nextIndex = (index + 1) % tabs.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = tabs.length - 1;
        break;
      default:
        return;
    }

    event.preventDefault();
    selectTab(nextIndex);
    tabs[nextIndex].focus();
  });
});

messageDetails.querySelector("[data-primary-json]").open = true;
selectTab(0);
tabList.hidden = false;
