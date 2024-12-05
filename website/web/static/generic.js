"use strict";

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

function render_datetime_with_tz(data) {
    const date = new Date(data);
    return `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, "0")}-${date.getDate().toString().padStart(2, "0")} ${date.toTimeString()}`;
};

DataTable.render.datetime_with_tz = function () {
    return function ( data, type, row ) {
        if ( type === 'display' ) {
            return render_datetime_with_tz(data);
        }
        return data;
    };
}

function newTabClickListener() {
    document.querySelectorAll('.openNewTab').forEach(el => el.addEventListener('click', event => {
        if (window.opener === null) {
            return openTreeInNewTab(el.dataset.capture, el.dataset.hostnode)
        } else {
            let success = window.opener.openTreeInNewTab(el.dataset.capture, el.dataset.hostnode);
            if (! success) {
                alert("Your browser doesn't allow Lookyloo to open a new tab. There should be an icon on the right side of your URL bar *in the main window* to allow it.");
            }
        }
    }));
};

document.addEventListener("DOMContentLoaded", () => {

  document.querySelectorAll('.goBack').forEach(el => el.addEventListener('click', event => {
    window.history.back();
  }));

  newTabClickListener();

  document.querySelectorAll(".locateInTree").forEach(el => el.addEventListener('click', event => {
    window.opener.LocateNode(el.dataset.hostnode);
  }));
});
