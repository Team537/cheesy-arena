// Copyright 2014 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Web routes for editing match results.

package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"strconv"
	"text/template"
)

type PitReviewListItem struct {
	Id          int
	DisplayName string
	Time        string
        Status      string
	RedTeams    []int
	BlueTeams   []int
	RedScore    int
	BlueScore   int
	ColorClass  string
}

// Shows the match review interface.
func PitReviewHandler(w http.ResponseWriter, r *http.Request) {
	practiceMatches, err := buildPitReviewList("practice")
	if err != nil {
		handleWebErr(w, err)
		return
	}
	qualificationMatches, err := buildPitReviewList("qualification")
	if err != nil {
		handleWebErr(w, err)
		return
	}
	eliminationMatches, err := buildPitReviewList("elimination")
	if err != nil {
		handleWebErr(w, err)
		return
	}

	template, err := template.ParseFiles("templates/pit_review.html", "templates/base.html")
	if err != nil {
		handleWebErr(w, err)
		return
	}
	matchesByType := map[string][]PitReviewListItem{"practice": practiceMatches,
		"qualification": qualificationMatches, "elimination": eliminationMatches}
	if currentMatchType == "" {
		currentMatchType = "practice"
	}
	data := struct {
		*EventSettings
		MatchesByType    map[string][]PitReviewListItem
		CurrentMatchType string
	}{eventSettings, matchesByType, currentMatchType}
	err = template.ExecuteTemplate(w, "base", data)
	if err != nil {
		handleWebErr(w, err)
		return
	}
}

// Shows the page to edit the results for a match.
func PitReviewEditGetHandler(w http.ResponseWriter, r *http.Request) {
	match, matchResult, err := getPitMatchResultFromRequest(r)
	if err != nil {
		handleWebErr(w, err)
		return
	}

	template, err := template.ParseFiles("templates/edit_match_result.html", "templates/base.html")
	if err != nil {
		handleWebErr(w, err)
		return
	}
	matchResultJson, err := matchResult.serialize()
	if err != nil {
		handleWebErr(w, err)
		return
	}
	data := struct {
		*EventSettings
		Match           *Match
		MatchResultJson *MatchResultDb
	}{eventSettings, match, matchResultJson}
	err = template.ExecuteTemplate(w, "base", data)
	if err != nil {
		handleWebErr(w, err)
		return
	}
}

// Updates the results for a match.
func PitReviewEditPostHandler(w http.ResponseWriter, r *http.Request) {
	match, matchResult, err := getPitMatchResultFromRequest(r)
	if err != nil {
		handleWebErr(w, err)
		return
	}

	r.ParseForm()
	matchResultJson := MatchResultDb{Id: matchResult.Id, MatchId: match.Id, PlayNumber: matchResult.PlayNumber,
		RedScoreJson: r.PostFormValue("redScoreJson"), BlueScoreJson: r.PostFormValue("blueScoreJson"),
		RedCardsJson: r.PostFormValue("redCardsJson"), BlueCardsJson: r.PostFormValue("blueCardsJson")}

	// Deserialize the JSON using the same mechanism as to store scoring information in the database.
	matchResult, err = matchResultJson.deserialize()
	if err != nil {
		handleWebErr(w, err)
		return
	}

	http.Redirect(w, r, "/pit_review", 302)
}

// Load the match result for the match referenced in the HTTP query string.
func getPitMatchResultFromRequest(r *http.Request) (*Match, *MatchResult, error) {
	vars := mux.Vars(r)
	matchId, _ := strconv.Atoi(vars["matchId"])
	match, err := db.GetMatchById(matchId)
	if err != nil {
		return nil, nil, err
	}
	if match == nil {
		return nil, nil, fmt.Errorf("Error: No such match: %d", matchId)
	}
	matchResult, err := db.GetMatchResultForMatch(matchId)
	if err != nil {
		return nil, nil, err
	}
	if matchResult == nil {
		// We're scoring a match that hasn't been played yet, but that's okay.
		matchResult = NewMatchResult()
	}

	return match, matchResult, nil
}

// Constructs the list of matches to display in the match review interface.
func buildPitReviewList(matchType string) ([]PitReviewListItem, error) {
	matches, err := db.GetMatchesByType(matchType)
	if err != nil {
		return []PitReviewListItem{}, err
	}

	prefix := ""
	if matchType == "practice" {
		prefix = "P"
	} else if matchType == "qualification" {
		prefix = "Q"
	}
	matchReviewList := make([]PitReviewListItem, len(matches))
	for i, match := range matches {
		matchReviewList[i].Id = match.Id
		matchReviewList[i].DisplayName = prefix + match.DisplayName
		matchReviewList[i].Time = match.Time.Local().Format("Mon 1/02 03:04 PM")
		matchReviewList[i].Status = match.Status
		matchReviewList[i].RedTeams = []int{match.Red1, match.Red2, match.Red3}
		matchReviewList[i].BlueTeams = []int{match.Blue1, match.Blue2, match.Blue3}
		matchResult, err := db.GetMatchResultForMatch(match.Id)
		if err != nil {
			return []PitReviewListItem{}, err
		}
		if matchResult != nil {
			matchReviewList[i].RedScore = matchResult.RedScoreSummary().Score
			matchReviewList[i].BlueScore = matchResult.BlueScoreSummary().Score
		}
		switch match.Winner {
		case "R":
			matchReviewList[i].ColorClass = "danger"
		case "B":
			matchReviewList[i].ColorClass = "info"
		case "T":
			matchReviewList[i].ColorClass = "warning"
		default:
			matchReviewList[i].ColorClass = ""
		}
	}

	return matchReviewList, nil
}
