const form = document.getElementById("requestForm");
const copyBtn = document.getElementById("copyRequestBtn");
const mailtoFallback = document.getElementById("mailtoFallback");

function buildMailto(formEl) {
  const data = new FormData(formEl);
  const lines = [];
  for (const [key, value] of data.entries()) {
    lines.push(`${key}: ${String(value).trim()}`);
  }
  const subject = encodeURIComponent("API Key Request - Swagger Tester");
  const body = encodeURIComponent(lines.join("\n"));
  return {
    mailtoUrl: `mailto:eminpepic2003@gmail.com?subject=${subject}&body=${body}`,
    plainText: lines.join("\n"),
  };
}

if (form) {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const { mailtoUrl } = buildMailto(form);
    if (mailtoFallback) mailtoFallback.href = mailtoUrl;
    if (typeof chrome !== "undefined" && chrome.tabs?.create) {
      chrome.tabs.create({ url: mailtoUrl });
    } else {
      window.location.href = mailtoUrl;
    }
  });
}

if (copyBtn && form) {
  copyBtn.addEventListener("click", async () => {
    const { plainText, mailtoUrl } = buildMailto(form);
    if (mailtoFallback) mailtoFallback.href = mailtoUrl;
    try {
      await navigator.clipboard.writeText(plainText);
      copyBtn.textContent = "Copied!";
      setTimeout(() => (copyBtn.textContent = "Copy request"), 1500);
    } catch (e) {
      copyBtn.textContent = "Copy failed";
      setTimeout(() => (copyBtn.textContent = "Copy request"), 1500);
    }
  });
}
