// Copyright 2014 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Client-side methods for editing a match in the match review page.

var scoreTemplate = Handlebars.compile($("#scoreTemplate").html());
var allianceResults = {};

// Hijack the form submission to inject the data in JSON form so that it's easier for the server to parse.
$("form").submit(function() {
  updateResults("red");
  updateResults("blue");

  var redScoreJson = JSON.stringify(allianceResults["red"].score);
  var blueScoreJson = JSON.stringify(allianceResults["blue"].score);
  var redFoulsJson = JSON.stringify(allianceResults["red"].fouls);
  var blueFoulsJson = JSON.stringify(allianceResults["blue"].fouls);
  var redCardsJson = JSON.stringify(allianceResults["red"].cards);
  var blueCardsJson = JSON.stringify(allianceResults["blue"].cards);

  // Inject the JSON data into the form as hidden inputs.
  $("<input />").attr("type", "hidden").attr("name", "redScoreJson").attr("value", redScoreJson).appendTo("form");
  $("<input />").attr("type", "hidden").attr("name", "blueScoreJson").attr("value", blueScoreJson).appendTo("form");
  $("<input />").attr("type", "hidden").attr("name", "redFoulsJson").attr("value", redFoulsJson).appendTo("form");
  $("<input />").attr("type", "hidden").attr("name", "blueFoulsJson").attr("value", blueFoulsJson).appendTo("form");
  $("<input />").attr("type", "hidden").attr("name", "redCardsJson").attr("value", redCardsJson).appendTo("form");
  $("<input />").attr("type", "hidden").attr("name", "blueCardsJson").attr("value", blueCardsJson).appendTo("form");

  return true;
});

// Draws the match-editing form for one alliance based on the cached result data.
var renderResults = function(alliance) {
  var result = allianceResults[alliance];
  var scoreContent = scoreTemplate(result);
  $("#" + alliance + "Score").html(scoreContent);

  // Set the values of the form fields from the JSON results data.
  $("select[name=" + alliance + "AutoMobilityBonuses]").val(result.score.AutoMobilityBonuses);
  $("input[name=" + alliance + "AutoHighHot]").val(result.score.AutoHighHot);
  $("input[name=" + alliance + "AutoHigh]").val(result.score.AutoHigh);
  $("input[name=" + alliance + "AutoLowHot]").val(result.score.AutoLowHot);
  $("input[name=" + alliance + "AutoLow]").val(result.score.AutoLow);
  $("input[name=" + alliance + "AutoClearHigh]").val(result.score.AutoClearHigh);
  $("input[name=" + alliance + "AutoClearLow]").val(result.score.AutoClearLow);

  if (result.score.Cycles != null) {
    $.each(result.score.Cycles, function(k, v) {
      $("#" + alliance + "Cycle" + k + "Title").text("Cycle " + (k + 1));
      $("input[name=" + alliance + "Cycle" + k + "Assists][value=" + v.Assists + "]").prop("checked", true);

      var trussCatch;
      if (v.Truss && v.Catch) {
        trussCatch = "TC";
      } else if (v.Truss) {
        trussCatch = "T";
      } else {
        trussCatch = "N";
      }
      $("input[name=" + alliance + "Cycle" + k + "TrussCatch][value=" + trussCatch + "]").prop("checked", true);

      var cycleEnd;
      if (v.ScoredHigh) {
        cycleEnd = "SH";
      } else if (v.ScoredLow) {
        cycleEnd = "SL";
      } else if (v.DeadBall) {
        cycleEnd = "DB";
      } else {
        cycleEnd = "DE";
      }
      $("input[name=" + alliance + "Cycle" + k + "End][value=" + cycleEnd + "]").prop("checked", true);
    });
  }

  if (result.fouls != null) {
    $.each(result.fouls, function(k, v) {
      $("input[name=" + alliance + "Foul" + k + "Team][value=" + v.TeamId + "]").prop("checked", true);
      $("input[name=" + alliance + "Foul" + k + "Tech][value=" + v.IsTechnical + "]").prop("checked", true);
      $("input[name=" + alliance + "Foul" + k + "Rule]").val(v.Rule);
      $("input[name=" + alliance + "Foul" + k + "Time]").val(v.TimeInMatchSec);
    });
  }

  if (result.cards != null) {
    $.each(result.cards, function(k, v) {
      $("input[name=" + alliance + "Team" + k + "Card][value=" + v + "]").prop("checked", true);
    });
  }
}

// Converts the current form values back into JSON structures and caches them.
var updateResults = function(alliance) {
  var result = allianceResults[alliance];
  var formData = {}
  $.each($("form").serializeArray(), function(k, v) {
    formData[v.name] = v.value;
  });

  result.score.AutoMobilityBonuses = parseInt(formData[alliance + "AutoMobilityBonuses"]);
  result.score.AutoHighHot = parseInt(formData[alliance + "AutoHighHot"]);
  result.score.AutoHigh = parseInt(formData[alliance + "AutoHigh"]);
  result.score.AutoLowHot = parseInt(formData[alliance + "AutoLowHot"]);
  result.score.AutoLow = parseInt(formData[alliance + "AutoLow"]);
  result.score.AutoClearHigh = parseInt(formData[alliance + "AutoClearHigh"]);
  result.score.AutoClearLow = parseInt(formData[alliance + "AutoClearLow"]);

  result.score.Cycles = [];
  for (var i = 0; formData[alliance + "Cycle" + i + "Assists"]; i++) {
    var prefix = alliance + "Cycle" + i;
    var cycle = {Assists: parseInt(formData[prefix + "Assists"]), Truss: false, Catch: false,
                 ScoredHigh: false, ScoredLow: false, DeadBall: false}
    switch (formData[prefix + "TrussCatch"]) {
      case "TC":
        cycle.Catch = true;
      case "T":
        cycle.Truss = true;
    }
    switch (formData[prefix + "End"]) {
      case "SH":
        cycle.ScoredHigh = true;
        break;
      case "SL":
        cycle.ScoredLow = true;
        break;
      case "DB":
        cycle.DeadBall = true;
    }
    result.score.Cycles.push(cycle);
  }

  result.fouls = [];
  for (var i = 0; formData[alliance + "Foul" + i + "Tech"]; i++) {
    var prefix = alliance + "Foul" + i;
    var foul = {TeamId: parseInt(formData[prefix + "Team"]), Rule: formData[prefix + "Rule"],
                TimeInMatchSec: parseFloat(formData[prefix + "Time"]),
                IsTechnical: (formData[prefix + "Tech"] == "true")};
    result.fouls.push(foul);
  }

  result.cards = {};
  $.each([result.team1, result.team2, result.team3], function(i, team) {
    result.cards[team] = formData[alliance + "Team" + team + "Card"];
  });
}

// Appends a blank cycle to the end of the list.
var addCycle = function(alliance) {
  updateResults(alliance);
  var result = allianceResults[alliance];
  result.score.Cycles.push({Assists: 1, Truss: false, Catch: false, ScoredHigh: false, ScoredLow: false,
                            DeadBall: false})
  renderResults(alliance);
}

// Removes the given cycle from the list.
var deleteCycle = function(alliance, index) {
  updateResults(alliance);
  var result = allianceResults[alliance];
  result.score.Cycles.splice(index, 1);
  renderResults(alliance);
}

// Appends a blank foul to the end of the list.
var addFoul = function(alliance) {
  updateResults(alliance);
  var result = allianceResults[alliance];
  result.fouls.push({TeamId: 0, Rule: "", TimeInMatchSec: 0, IsTechnical: false})
  renderResults(alliance);
}

// Removes the given foul from the list.
var deleteFoul = function(alliance, index) {
  updateResults(alliance);
  var result = allianceResults[alliance];
  result.fouls.splice(index, 1);
  renderResults(alliance);
}
