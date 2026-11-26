const status = document.getElementById("copy-status");

for (const button of document.querySelectorAll("[data-copy]")) {
  const code = document.getElementById(button.dataset.copy);
  let reset;

  button.hidden = false;
  button.addEventListener("click", async () => {
    clearTimeout(reset);
    try {
      await navigator.clipboard.writeText(code.textContent.trim());
      status.textContent = "Copied to the clipboard.";
      button.textContent = "Copied";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = "Command selected. Copy it with your keyboard.";
      button.textContent = "Selected";
    }
    reset = setTimeout(() => {
      button.textContent = "Copy";
      status.textContent = "";
    }, 2300);
  });
}
