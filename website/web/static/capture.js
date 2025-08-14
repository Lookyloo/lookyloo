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

document.getElementById("os").addEventListener("change", function () {
    let osSelect = document.getElementById("os");
    let os_name = osSelect.options[osSelect.selectedIndex].value.replace(/(:|\.|\[|\]|,|=|\\)/g, "\\$1").replace(/ /g, "_");
    let first_browser_name = document.querySelector(`[id='${os_name}'] select option:first-child`).value.replace(/(:|\.|\[|\]|,|=|\\)/g, "\\$1").replace(/ /g, "_");

    // Hide and disable everything
    document.querySelectorAll("#os option").forEach(function (option) {
        option.removeAttribute('selected');
    });
    document.querySelectorAll(".style-sub-1").forEach(function (element) {
        element.style.display = 'none';
    });
    document.querySelectorAll(".style-sub-1 > label > span > select").forEach(function (select) {
        select.disabled = true;
        select.querySelectorAll('option').forEach(function (option) {
            option.removeAttribute('selected');
        });
    });
    document.querySelectorAll(".style-sub-2").forEach(function (element) {
        element.style.display = 'none';
    });
    document.querySelectorAll(".style-sub-2 > label > span > select").forEach(function (select) {
        select.disabled = true;
        select.querySelectorAll('option').forEach(function (option) {
            option.removeAttribute('selected');
        });
    });

    // Re-enable and show what makes sense
    document.querySelector(`[id='${os_name}']`).style.display = 'block';
    document.querySelectorAll(`[id='${os_name}'] > label > span > select`).forEach(function (select) {
        select.disabled = false;
        select.querySelector('option:first-child').selected = true;
    });
    document.querySelector(`[id='${os_name}_${first_browser_name}']`).style.display = 'block';
    document.querySelectorAll(`[id='${os_name}_${first_browser_name}'] > label > span > select`).forEach(function (select) {
        select.disabled = false;
        select.querySelector('option:first-child').selected = true;
    });
});

document.querySelectorAll('select[name="browser"]').forEach( function(element)
{
    element.addEventListener('change', function (e) {
        let browser_name = element.options[element.selectedIndex].value.replace(/(:|\.|\[|\]|,|=|\\)/g, "\\$1").replace(/ /g, "_");
        let osSelect = document.getElementById("os");
        let os_name = osSelect.options[osSelect.selectedIndex].value.replace(/(:|\.|\[|\]|,|=|\\)/g, "\\$1").replace(/ /g, "_");

        // Hide and disable every useragent
        document.querySelectorAll(".style-sub-2").forEach(function (element) {
            element.style.display = 'none';
        });
        document.querySelectorAll(".style-sub-2 > label > span > select").forEach(function (select) {
            select.disabled = true;
            select.querySelectorAll('option').forEach(function (option) {
                option.removeAttribute('selected');
            });
        });

        // Show only the correct user-agent
        document.querySelector(`[id='${os_name}_${browser_name}']`).style.display = 'block';
        document.querySelectorAll(`[id='${os_name}_${browser_name}'] > label > span > select`).forEach(function (select) {
            select.disabled = false;
            select.querySelector('option:first-child').selected = true;
        });
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

document.getElementById('os-type').addEventListener('change', function () {
    document.getElementById('os-type').disabled = false;
    if (this.value === "mobile") {
        document.getElementById("mobiles-list").style.display = 'block';
        document.getElementById('device-name-mobile').disabled = false;

        document.getElementById("desktops-list").style.display = 'none';
        document.getElementById('os').disabled = true;
        document.querySelectorAll('select[name="browser"]').forEach(function (element) {
            element.disabled = true;
        });
        document.querySelectorAll('select[name="user_agent"]').forEach(function (element) {
            element.disabled = true;
        });
    } else { // os-type is desktop
        document.getElementById("desktops-list").style.display = 'block';
        document.getElementById('os').disabled = false;
        document.querySelectorAll('select[name="browser"]:not([hidden])').forEach(function (element) {
            element.disabled = false;
        });
        document.querySelectorAll('select[name="user_agent"]:not([hidden])').forEach(function (element) {
            element.disabled = false;
        });
        document.getElementById("mobiles-list").style.display = 'none';
        document.getElementById('device-name-mobile').disabled = true;
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
