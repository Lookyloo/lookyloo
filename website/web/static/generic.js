"use strict";

// Copy to clipboard
// Source: https://codepen.io/nathanlong/pen/ZpAmjv
let copyToClipboard = (text, el) => {
  const elOriginalText = el.attr('data-original-title');

  const copyTextArea = document.createElement("textarea");
  copyTextArea.value = text;
  document.body.appendChild(copyTextArea);
  copyTextArea.select();

  const successful = document.execCommand('copy');
  const msg = successful ? 'Copied!' : 'Whoops, not copied!';
  el.attr('data-original-title', msg).tooltip('show');

  document.body.removeChild(copyTextArea);
  el.attr('data-original-title', elOriginalText);
}

function checkAllBoxes(name) {
  let checkboxs = document.getElementsByName(name);
  for(let i = 0; i < checkboxs.length ; i++) {
    checkboxs[i].checked = !checkboxs[i].checked;
  }
}
