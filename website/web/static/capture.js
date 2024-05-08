$("#os").change(function () {
  var os_name = $(this).find(":selected").val().replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g, "_");
  var first_browser_name = $("[id='" + os_name + "']").find('select option:first-child').val().replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g, "_");
  // Hide and disable everything
  $("#os > option").removeAttr('selected');
  $(".style-sub-1").hide();
  $(".style-sub-1 > div > select").attr('disabled', true);
  $(".style-sub-1 > div > select").removeAttr('selected');
  $(".style-sub-2").hide();
  $(".style-sub-2 > div > select").attr('disabled', true);
  $(".style-sub-2 > div > select").removeAttr('selected');
  // Enable everything that makes sense
  $("[id='" + os_name + "']").show();
  $("[id='" + os_name + "'] > div > select").removeAttr('disabled');
  $("[id='" + os_name + "'] > div > select option:first").prop('selected', true);
  $("[id='" + os_name + '_' + first_browser_name + "']").show();
  $("[id='" + os_name + '_' + first_browser_name + "'] > div > select").removeAttr('disabled');
  $("[id='" + os_name + '_' + first_browser_name + "'] > div > select option:first").prop('selected', true);
});

document.getElementById("os").addEventListener("change", function() {
    let os_name = document.getElementById("os").options[osSelect.selectedIndex].value.replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");
    let first_browser_name = document.querySelector("[id='" + os_name + "'] select option:first-child").value.replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");

    // Hide and disable everything
    document.querySelectorAll("#os option").forEach(function(option) {
        option.removeAttribute('selected');
    });
    document.querySelectorAll(".style-sub-1").forEach(function(element) {
        element.style.display = 'none';
    });
    document.querySelectorAll(".style-sub-1 > div > select").forEach(function(select) {
        select.disabled = true;
        select.querySelectorAll('option').forEach(function(option) {
            option.removeAttribute('selected');
        });
    });
    document.querySelectorAll(".style-sub-2").forEach(function(element) {
        element.style.display = 'none';
    });
    document.querySelectorAll(".style-sub-2 > div > select").forEach(function(select) {
        select.disabled = true;
        select.querySelectorAll('option').forEach(function(option) {
            option.removeAttribute('selected');
        });
    });

    // Re-enable and show what makes sense
    document.querySelector("[id='" + os_name + "']").style.display = 'block';
    document.querySelectorAll("[id='" + os_name + "'] > div > select").forEach(function(select) {
        select.disabled = false;
        select.querySelector('option:first-child').selected = true;
    });
    document.querySelector("[id='" + os_name + '_' + first_browser_name + "']").style.display = 'block';
    document.querySelectorAll("[id='" + os_name + '_' + first_browser_name + "'] > div > select").forEach(function(select) {
        select.disabled = false;
        select.querySelector('option:first-child').selected = true;
    });
});

$('select[name="browser"]').change(function () {
  var browser_name = $(this).find(":selected").val().replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g, "_");
  var os_name = $(this).parent().parent().attr("id").replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g, "_");

  // Hide what makes sense
  $(".style-sub-1 > div > select").removeAttr('selected');
  $(".style-sub-2").hide();
  $(".style-sub-2 > div > select").attr('disabled', true);
  $(".style-sub-2 > div > select").removeAttr('selected');

  $("[id='" + os_name + '_' + browser_name + "']").show();
  $("[id='" + os_name + '_' + browser_name + "'] > div > select").removeAttr('disabled');
});
 document.querySelector('select[name="browser"]').addEventListener('click', function(e) {
     let browser_name = document.querySelector('select[name="browser"]').options[osSelect.selectedIndex].value.replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");
     let os_name = document.querySelector('select[name="browser"]').parentNode.parentNode.getAttribute("id").replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g, "_");

     // Hide what makes sense
     // Why does it make sense???
     document.querySelectorAll(".style-sub-1 > div > select").forEach(function(select) {
        select.querySelectorAll('option').forEach(function(option) {
            option.removeAttribute('selected');
        });
    });
    document.querySelectorAll(".style-sub-2").forEach(function(element) {
        element.style.display = 'none';
    });
    document.querySelectorAll(".style-sub-2 > div > select").forEach(function(select) {
        select.disabled = true;
        select.querySelectorAll('option').forEach(function(option) {
            option.removeAttribute('selected');
        });
    });
    document.querySelector("[id='" + os_name + '_' + browser_name + "']").style.display = 'block';
    document.querySelectorAll("[id='" + os_name + '_' + browser_name + "'] > div > select").forEach(function(select) {
        select.disabled = false;
        select.querySelector('option:first-child').selected = true;
    });
 });

  //switch between tabs for entering url or upload a web enabled document
  // multipleCaptures != multipleCaptureField
  $('#nav-url-tab').on('click', function(e) {
  document.getElementById("singleCaptureField").required = true;
  document.getElementById("document").required = false;
  $("#singleCaptureField").removeClass("d-none");
  document.getElementById('multipleCaptures').checked = false;
  $("#multipleCapturesField").addClass("d-none");
});

  $('#nav-doc-tab').on('click', function(e) {
  document.getElementById("document").required = true;
  document.getElementById("multipleCapturesField").required = false;
  document.getElementById("singleCaptureField").required = false;
});

  //switch input-fields between multiple and single Capture
  $('#multipleCaptures').on('click', function(e) {
  if (document.getElementById('multipleCaptures').checked == true) {
  document.getElementById('singleCaptureField').value = '';
  $("#singleCaptureField").addClass("d-none");
  document.getElementById("singleCaptureField").required = false;
  $("#multipleCapturesField").removeClass("d-none");
  document.getElementById("multipleCapturesField").required = true;
}
  else {
  document.getElementById('multipleCapturesField').value = '';
  $("#singleCaptureField").removeClass("d-none");
  document.getElementById("singleCaptureField").required = true;
  $("#multipleCapturesField").addClass("d-none");
  document.getElementById("multipleCapturesField").required = false;
}
})

//disable select fields when personal useragent (ua) selected etc...
  $('#personal_ua_select').on('click', function(e) {
  $('#personal_ua').prop("disabled", false);

  $('#freetext_ua').prop("disabled", true);
  disablePredefinedUA();
});

  // Enable free user-agent input
  document.getElementById('personal_ua_select').addEventListener('click', function(e){
    document.getElementById('personal_ua').disabled = false;
    document.getElementById('freetext_ua').disabled = true;
    disablePredefinedUA();
  })

  $('#predefined_ua_select').on('click', function(e) {
  $('#os-type').val('desktop').trigger('change');

  $('#freetext_ua').prop("disabled", true);
  $('#personal_ua').prop("disabled", true);
});

  // Enable predefinded user-agent
  document.getElementById('predefined_ua_select').addEventListener('click', function (e){
    let os_type = document.getElementById('os-type');
    os_type.value = 'desktop';
    os_type.dispatchEvent(new Event('change'))
    document.getElementById('freetext_ua').disabled = true;
    document.getElementById('personal_ua').disabled = true;
  })

  $('#freetext_ua_select').on('click', function(e) {
  $('#freetext_ua').prop("disabled", false);

  $('#personal_ua').prop("disabled", true);
  disablePredefinedUA();
});

  // Enable freetext user-agent
  document.getElementById('freetext_ua_select').addEventListener('click', function (e){
    document.getElementById('freetext_ua').disabled = false;
    document.getElementById('personal_ua').disabled = true;
    disablePredefinedUA()
  })

  const disablePredefinedUA = function() {
  $('#device-name-mobile').prop("disabled", true);
  $('#os').prop("disabled", true);
  $('select[name="browser"]').prop("disabled", true);
  $('select[name="user_agent"]').prop("disabled", true);
  document.getElementById('os-type').disabled = true;
  document.getElementById('device-name-mobile').disabled = true;
  document.getElementById('os').disabled = true;
  document.querySelector('select[name="browser"]').disabled = true;
  document.querySelector('select[name="user_agent"]').disabled = true;

};


  $('#os-type').on('change', function() {
  $('#os-type').prop("disabled", false);
  if ( this.value == "mobile")
{
  $("#mobiles-list").show();
  $('#device-name-mobile').prop("disabled", false);

  $("#desktops-list").hide();
  $('#os').prop("disabled", true);
  $('select[name="browser"]').prop("disabled", true);
  $('select[name="user_agent"]').prop("disabled", true);
}
  else
{
  $("#desktops-list").show();
  $('#os').prop("disabled", false);
  $('select[name="browser"]:visible').prop("disabled", false);
  $('select[name="user_agent"]:visible').prop("disabled", false);

  $("#mobiles-list").hide();
  $('#device-name-mobile').prop("disabled", true);
}
});
