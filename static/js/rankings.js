// Copyright 2014 Team 254. All Rights Reserved.
// Author: nick@team254.com (Nick Eyre) 

initialize();

var template;
function initialize(){
  getData(populateView);
  template = Handlebars.compile($('#row-template').html());
}

var rankings;
function getData(callback){
  $.getJSON('/reports/json/rankings', function(data){
    data = {teams: data};
    rankings = data;
    if(typeof(callback) == "function")
      callback();
    var date = new Date();
    console.log("New Data Acquired\n"+date);
  });
}

function populateView(){
  $('#container table').html(template(rankings));
  equalize(true);
  scroll();
}

// Balance Column Widths
var widths = [];
function equalize(all){
  if(all){
    var width = $('#container table').width();
    var count = $('#container tr').first().children('td').length;
    var offset = ($(window).width() - width) / (count + 1);
    $('#container tr').first().children('td').each(function(){
      var width = $(this).width()+offset;
      $(this).width(width);
      widths.push(width);
    });
    $('#header').children('td').each(function(index){
      $(this).width(widths[index]);
    });
  }
  $('#container table#new tr').first().children('td').each(function(index){
    $(this).width(widths[index]);
  });
}

var SCROLL_SPEED = 1000;
function scroll(){
  $('#container').scrollTop(0);

  var offset = $('table#new').offset().top - $('#container').offset().top;
  var scrollTime = SCROLL_SPEED * $('table#old tr').length;
  $('#container').animate({scrollTop: offset}, scrollTime, 'linear', reset);

  $('#container table#new').html(template(rankings));
  equalize();

  interval = setInterval(pollForUpdate, POLL_INTERVAL);
}

function reset(){
  $('#container table#old').html($('#container table#new').html());
  scroll();
}

var POLL_INTERVAL = 1000;
function pollForUpdate(){
  if($('#container').offset().top * $('#container').height() > $('#container table#old tr').last().prev().offset().top){
    getData();
    clearInterval(interval);
  }
}