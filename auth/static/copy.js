// data-copy 属性の値をクリップボードにコピーするボタン（承認方式の待ち画面）
document.querySelectorAll("button[data-copy]").forEach(function (button) {
  var label = button.textContent;
  button.addEventListener("click", function () {
    navigator.clipboard.writeText(button.getAttribute("data-copy")).then(
      function () { button.textContent = "Copied"; },
      function () { button.textContent = "Copy failed"; }
    );
    setTimeout(function () { button.textContent = label; }, 2000);
  });
});
