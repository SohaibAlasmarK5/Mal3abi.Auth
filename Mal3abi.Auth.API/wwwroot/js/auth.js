// Mal3abi account pages: theme toggle, remembered language, and the six-digit code input.
(function () {
  "use strict";

  var root = document.documentElement;

  // Remember the language shown, so the next page (and the form post) keeps it.
  document.cookie =
    "mal3abi-lang=" + root.lang + "; path=/; max-age=31536000; SameSite=Lax" +
    (location.protocol === "https:" ? "; Secure" : "");

  // Theme toggle. The early script in <head> already applied the saved or system theme.
  var toggle = document.querySelector("[data-theme-toggle]");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("mal3abi-theme", next);
      } catch (e) {
        // Storage blocked: the theme still applies for this page.
      }
    });
  }

  // Six-digit code: accept Western and Arabic-Indic digits, keep only six, mirror into the boxes.
  var arabicDigits = "٠١٢٣٤٥٦٧٨٩";
  function normalize(value) {
    var out = "";
    for (var i = 0; i < value.length; i++) {
      var ch = value[i];
      var index = arabicDigits.indexOf(ch);
      if (index >= 0) ch = String(index);
      if (ch >= "0" && ch <= "9") out += ch;
    }
    return out;
  }

  document.querySelectorAll("[data-code]").forEach(function (box) {
    var input = box.querySelector("input");
    var slots = box.querySelectorAll(".code-slot");
    var length = slots.length;

    function render() {
      var clean = normalize(input.value).slice(0, length);
      if (clean !== input.value) input.value = clean;
      slots.forEach(function (slot, i) {
        slot.textContent = clean[i] || "";
        slot.classList.toggle("is-active", i === Math.min(clean.length, length - 1));
      });
      if (box.dataset.state && clean.length > 0) box.removeAttribute("data-state");
    }

    input.addEventListener("input", render);
    input.addEventListener("focus", function () {
      // Keep the caret at the end so typing always fills the next box.
      var end = input.value.length;
      input.setSelectionRange(end, end);
    });
    render();
  });

  // Resend button: wait, then allow a new code.
  document.querySelectorAll("[data-resend]").forEach(function (button) {
    var seconds = parseInt(button.dataset.seconds || "60", 10);
    var waitText = button.dataset.waitText || "";
    var readyText = button.textContent;

    function tick() {
      if (seconds <= 0) {
        button.disabled = false;
        button.textContent = readyText;
        return;
      }
      button.disabled = true;
      button.textContent = waitText.replace("{0}", String(seconds));
      seconds -= 1;
      setTimeout(tick, 1000);
    }
    tick();
  });
})();
