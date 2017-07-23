function highlight_node(x, y, width, height){
  //console.log(treeid, nodeid, x, y, width, height);
  var img = $('#img');
  var offset = img.offset();
  // console.log(img);
  // console.log(offset);

  $("#highlighter").show();
  $("#highlighter").css("top", offset.top+y-1);
  $("#highlighter").css("left", offset.left+x-1);
  $("#highlighter").css("width", width+1);
  $("#highlighter").css("height", height+1);

}
function unhighlight_node(){
  // console.log("unhighlight");
  $("#highlighter").hide();
}

