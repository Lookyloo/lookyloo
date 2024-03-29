$("#os").change(function(){
  var os_name = $(this).find(":selected").val().replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");
  var first_browser_name = $("[id='" + os_name + "']").find('select option:first-child').val().replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");
  // Hide and disable everything
  $("#os > option").removeAttr('selected');
  $(".style-sub-1").hide();
  $(".style-sub-1 > div > select").attr('disabled', true);
  $(".style-sub-1 > div > select").removeAttr('selected');
  $(".style-sub-2").hide();
  $(".style-sub-2 > div > select").attr('disabled', true);
  $(".style-sub-2 > div > select").removeAttr('selected');

  $("[id='" + os_name + "']").show();
  $("[id='" + os_name + "'] > div > select").removeAttr('disabled');
  $("[id='" + os_name + "'] > div > select option:first").prop('selected',true);
  $("[id='" + os_name + '_' + first_browser_name + "']").show();
  $("[id='" + os_name + '_' + first_browser_name + "'] > div > select").removeAttr('disabled');
  $("[id='" + os_name + '_' + first_browser_name + "'] > div > select option:first").prop('selected',true);
});

$('select[name="browser"]').change(function(){
  var browser_name = $(this).find(":selected").val().replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");
  var os_name = $(this).parent().parent().attr("id").replace(/(:|\.|\[|\]|,|=)/g, "\\$1").replace(/ /g,"_");

  // Hide what makes sense
  $(".style-sub-1 > div > select").removeAttr('selected');
  $(".style-sub-2").hide();
  $(".style-sub-2 > div > select").attr('disabled', true);
  $(".style-sub-2 > div > select").removeAttr('selected');

  $("[id='" + os_name + '_' + browser_name + "']").show();
  $("[id='" + os_name + '_' + browser_name + "'] > div > select").removeAttr('disabled');
});
