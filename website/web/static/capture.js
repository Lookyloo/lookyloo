"use strict";

// scripts for the submission type

document.getElementById('nav-url-tab').addEventListener('click', function (e) {
    // switch to tab for capture of URL(s)

    // default: single capture field
    document.getElementById("singleCaptureField").required = true;
    document.getElementById("singleCaptureField").classList.remove("d-none");
    // hide multiple captures field
    document.getElementById('multipleCaptures').checked = false;
    document.getElementById("multipleCapturesField").required = false;
    document.getElementById("multipleCapturesField").classList.add("d-none");

    document.getElementById("document").required = false;
});

document.getElementById('nav-doc-tab').addEventListener('click', function (e) {
    // switch to tab for capture of document
    document.getElementById("document").required = true;
    document.getElementById("multipleCapturesField").required = false;
    document.getElementById("singleCaptureField").required = false;
});

document.getElementById('multipleCaptures').addEventListener('click', function (e) {
    // switch input-fields between multiple and single capture
    if (document.getElementById('multipleCaptures').checked === true) {
        // enable multiple captures
        document.getElementById('singleCaptureField').value = '';
        document.getElementById("singleCaptureField").classList.add("d-none");
        document.getElementById("singleCaptureField").required = false;
        document.getElementById("multipleCapturesField").classList.remove("d-none");
        document.getElementById("multipleCapturesField").required = true;
    } else {
        // disable multiple captures
        document.getElementById('multipleCapturesField').value = '';
        document.getElementById("multipleCapturesField").classList.add("d-none");
        document.getElementById("multipleCapturesField").required = false;
        document.getElementById("singleCaptureField").classList.remove("d-none");
        document.getElementById("singleCaptureField").required = true;
    }
});

// Remote lacus & proxy selector

if ( document.getElementById("remote_lacus_name") ){
  document.getElementById("remote_lacus_name").addEventListener("change", function (e) {
    let lacus_name = this.options[this.selectedIndex].value;
    document.getElementsByName("remote_lacus_proxies").forEach(function (element) {
        element.style.display = 'none';
    });
    document.getElementById(`proxies_${lacus_name}`).style.display = 'block';
    document.getElementById('user_defined_proxy').style.display = '';
    document.getElementById(`remote_lacus_proxy_name_${lacus_name}`).selectedIndex = 0;

    let lacusProxyNameSelect = document.getElementById(`remote_lacus_proxy_name_${lacus_name}`);
    let event = new Event('change');
    lacusProxyNameSelect.dispatchEvent(event);
  });
}

const remote_lacuses_proxy_names = document.getElementsByName("remote_lacus_proxy_name")

for (const remote_lacus_proxy_name of remote_lacuses_proxy_names) {
  remote_lacus_proxy_name.addEventListener("change", change_proxy_details, false);
}

function change_proxy_details(e) {
    let lacusNameSelect = document.getElementById("remote_lacus_name");
    let lacus_name = lacusNameSelect.options[lacusNameSelect.selectedIndex].value;

    let lacus_proxy_name = this.options[this.selectedIndex].value;
    document.getElementsByName("proxy_details").forEach(function (element) {
        element.style.display = 'none';
    });
    if (lacus_proxy_name === "") {
        if (document.getElementById(`${lacus_name}_no_proxy_details`)) {
            document.getElementById(`${lacus_name}_no_proxy_details`).style.display = 'block';
        }
        document.getElementById('user_defined_proxy').style.display = '';
    }
    else {
        document.getElementById(`${lacus_name}_${lacus_proxy_name}_details`).style.display = 'block';
        document.getElementById('user_defined_proxy').style.display = 'none';
    }
};

// scripts for browser configuration of the capture

function hide_disable_browser_ua() {
    document.querySelectorAll(".browsers").forEach(function (element) {
        element.style.display = 'none';
    });
    document.querySelectorAll('select[name="browser"]').forEach(function (select) {
        select.disabled = true;
    });
    document.querySelectorAll(".user-agents").forEach(function (element) {
        element.style.display = 'none';
    });
    document.querySelectorAll('select[name="user_agent"]').forEach(function (select) {
        select.disabled = true;
    });
}

document.getElementById("os").addEventListener("change", function (e) {
    let id_os_name = this.options[this.selectedIndex].value.replace(/ /g, "_");
    let first_browser_name = document.querySelector(`[id='${id_os_name}'] select option:first-child`).value;
    let id_first_browser_name = first_browser_name.replace(/ /g, "_");

    // Hide and disable everything
    hide_disable_browser_ua()

    // Re-enable and show what makes sense
    document.getElementById(id_os_name).style.display = 'block';
    let id_os_sel = document.getElementById(`sel_${id_os_name}`);
    id_os_sel.disabled = false;
    id_os_sel.value = first_browser_name;

    document.getElementById(`${id_os_name}_${id_first_browser_name}`).style.display = 'block';
    document.getElementById(`sel_${id_os_name}_${id_first_browser_name}`).disabled = false;
});

document.querySelectorAll('select[name="browser"]').forEach( function(element) {
    element.addEventListener('change', function (e) {
        let osSelect = document.getElementById("os");
        let id_os_name = osSelect.options[osSelect.selectedIndex].value.replace(/ /g, "_");
        let id_browser_name = this.options[this.selectedIndex].value.replace(/ /g, "_");

        // Hide and disable every useragent
        document.querySelectorAll(".user-agents").forEach(function (element) {
            element.style.display = 'none';
        });
        document.querySelectorAll('select[name="user_agent"]').forEach(function (select) {
            select.disabled = true;
        });

        // Show only the correct user-agent
        document.getElementById(`${id_os_name}_${id_browser_name}`).style.display = 'block';
        document.getElementById(`sel_${id_os_name}_${id_browser_name}`).disabled = false;
    });
});

document.getElementById('personal_ua_select').addEventListener('click', function (e) {
    //disable select fields when personal useragent (ua) selected etc...
    document.getElementById('personal_ua').disabled = false;
    document.getElementById('freetext_ua').disabled = true;
    disablePredefinedUA();
});


document.getElementById('predefined_ua_select').addEventListener('click', function (e) {
    document.getElementById('os-type').value = 'desktop';
    document.getElementById('os-type').dispatchEvent(new Event('change'));
    document.getElementById('freetext_ua').disabled = true;
    document.getElementById('personal_ua').disabled = true;
    // Enable predefinded user-agent
    let os_type = document.getElementById('os-type');
    os_type.value = 'desktop';
    os_type.dispatchEvent(new Event('change'))
});

document.getElementById('freetext_ua_select').addEventListener('click', function (e) {
    // Enable freetext user-agent
    document.getElementById('freetext_ua').disabled = false;
    document.getElementById('personal_ua').disabled = true;
    disablePredefinedUA()
})

const disablePredefinedUA = function () {
    document.getElementById('os-type').disabled = true;
    document.getElementById('device-name-mobile').disabled = true;
    document.getElementById('os').disabled = true;
    document.querySelectorAll('select[name="browser"]').forEach(function (element) {
        element.disabled = true;
    });
    document.querySelectorAll('select[name="user_agent"]').forEach(function (element) {
        element.disabled = true;
    });
};

function enable_mobile() {
    document.getElementById("mobiles-list").style.display = 'block';
    document.getElementById('device-name-mobile').disabled = false;
    document.getElementById("desktops-list").style.display = 'none';
    document.getElementById('os').disabled = true;

    // Hide and disable everything
    hide_disable_browser_ua()

    if (default_device.default_device_type === "mobile") {
        document.getElementById('device-name-mobile').value = default_device.default_device_name;
    }
    else {
        // just have the first in the list ?
    }
};

function enable_desktop() {
    document.getElementById("mobiles-list").style.display = 'none';
    document.getElementById('device-name-mobile').disabled = true;
    document.getElementById("desktops-list").style.display = 'block';
    document.getElementById('os').disabled = false;

    if (default_device.default_device_type === "mobile") {
        // get first OS in the selector
        let fallback_id_os = document.getElementById('os')[0].value.replace(' ', '_');
        document.getElementById(fallback_id_os).style.display = 'block';
        document.getElementById(`sel_${fallback_id_os}`).disabled = false;
        // get first os browser in selector
        let fallback_id_os_browser = document.getElementById(`sel_${fallback_id_os}`)[0].value.replace(' ', '_');
        document.getElementById(`${fallback_id_os}_${fallback_id_os_browser}`).style.display = 'block';
        document.getElementById(`sel_${fallback_id_os}_${fallback_id_os_browser}`).disabled = false;

        document.getElementById("mobiles-list").style.display = 'none';
    } else {
        document.getElementById('os').value = default_device.os;

        const id_os = `${default_device.os.replace(' ', '_')}`;
        document.getElementById(id_os).style.display = 'block';
        const selectBrowserType = document.getElementById(`sel_${id_os}`);
        selectBrowserType.disabled = false;
        selectBrowserType.value = default_device.browser;

        const id_os_browser = `${id_os}_${default_device.browser.replace(' ', '_')}`
        document.getElementById(id_os_browser).style.display = 'block';
        const selectUA = document.getElementById(`sel_${id_os_browser}`);
        selectUA.disabled = false;
        selectUA.value = default_device.useragent;
    }
}

document.getElementById('os-type').addEventListener('change', function () {
    if (this.value === "mobile") {
        enable_mobile();
    } else { // os-type is desktop
        enable_desktop();
    }
});

// admin-only report-form
let report_form = document.getElementById("auto-report");
if (report_form) { // admin is logged in
    report_form.addEventListener('change', function() {
        let show_form = document.getElementById("auto-report").checked;
        if(show_form) {
          document.getElementById("collapseMailConfiguration").style.display = "block";
        } else {
          document.getElementById("collapseMailConfiguration").style.display = "none";
        }
    });
}

window.addEventListener('DOMContentLoaded', (event) => {
    // trigger default select from config
    if (default_device.default_device_type === "mobile") {
        document.getElementById('os-type').value = "mobile"
        enable_mobile();
    } else {
        document.getElementById('os-type').value = "desktop"
        enable_desktop();
    };
});
