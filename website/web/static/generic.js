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

function openURLInNewTab(url) {
    let win = window.open(url, '_blank');
    if (win == null) {
        return false;
    }
    win.focus();
    return true;
}

function openTreeInNewTab(capture_uuid, hostnode_uuid=null) {
    let url = `/tree/${capture_uuid}`;
    if (hostnode_uuid != null) {
        url += `/${hostnode_uuid}`;
    }
    return openURLInNewTab(url);
}

const goBackButtons = document.querySelectorAll('.goBack');
goBackButtons.forEach(el => el.addEventListener('click', event => {
  window.history.back();
}));

const openNewTabButtons = document.querySelectorAll('.openNewTab');
openNewTabButtons.forEach(el => el.addEventListener('click', event => {
    if (window.opener === null) {
        return openTreeInNewTab(el.dataset.capture, el.dataset.hostnode)
    } else {
        let success = window.opener.openTreeInNewTab(el.dataset.capture, el.dataset.hostnode);
        if (! success) {
            alert("Your browser doesn't allow Lookyloo to open a new tab. There should be an icon on the right side of your URL bar *in the main window* to allow it.");
        }
    }
}));

const locateInTree = document.querySelectorAll(".locateInTree")
if (locateInTree) {
    locateInTree.forEach(el => el.addEventListener('click', event => {
        window.opener.LocateNode(el.dataset.hostnode);
    }));
}

// Parameters:
// contentType: The content type of your file.
//              its like application/pdf or application/msword or image/jpeg or
//              image/png and so on
// base64Data: Its your actual base64 data
// fileName: Its the file name of the file which will be downloaded.
// Source: https://stackoverflow.com/questions/14011021/how-to-download-a-base64-encoded-image
function downloadBase64File(contentType, base64Data, fileName) {
     const linkSource = `data:${contentType};base64,${base64Data}`;
     const downloadLink = document.createElement("a");
     downloadLink.href = linkSource;
     downloadLink.download = fileName;
     downloadLink.click();
}
