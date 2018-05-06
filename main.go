package main

import (
	"encoding/json"
	"log"
	"net/http"
	"io/ioutil"
	"time"
	"fmt"
	"os"
	"encoding/base32"
	"crypto/rand"
	"net/url"
	"bytes"
	"strconv"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

// Monzo API response from initial auth or token refresh
type MonzoAuthorised struct {
	AccessToken  string `json:"access_token"`
	ClientId     string `json:"client_id"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	UserId       string `json:"user_id"`
}

// CircleCI API build
type CircleCIBuild struct {
	VcsType  string `json:"vcs_type"`
	Username string `json:"username"`
	RepoName string `json:"reponame"`
	BuildNum int64  `json:"build_num"`
	Branch   string `json:"branch"`
	Failed   bool   `json:"failed"`
}

type CircleCICallback struct {
	Payload CircleCIBuild
}

// Monzo API response for a Pot
type MonzoPot struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Currency string `json:"currency"`
	Balance  int64  `json:"balance"`
}

// User from DynamoDB table
type MonzoUser struct {
	AccessToken  string `json:"access_token"`
	ClientId     string `json:"client_id"`
	ExpiresAt    string `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	UserId       string `json:"user_id"`
}

var httpClient = http.Client{
	Timeout: time.Second * 5,
}

var awsSession, _ = session.NewSession(&aws.Config{
	Region: aws.String("eu-west-1"),
})
var dynamoDbService = dynamodb.New(awsSession)

func getToken(length int) string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:length]
}

var lastLoginStateCode = ""

func resetLastLoginStateCode() {
	lastLoginStateCode = getToken(10)
}

func getLastLoginStateCode() (string) {
	return lastLoginStateCode
}

func getMonzoUser() (MonzoUser) {
	userResult, userErr := dynamoDbService.GetItem(&dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"user_id": {
				S: aws.String(os.Getenv("MONZO_JOEL_VARDY_USER_ID")),
			},
		},
		TableName: aws.String("fail-jar-monzo-users"),
	})
	if userErr != nil {
		panic(userErr)
	}

	var monzoUser MonzoUser
	err := dynamodbattribute.Unmarshal(&dynamodb.AttributeValue{M: userResult.Item}, &monzoUser)
	if err != nil {
		panic(err)
	}

	expiresAt, err := time.Parse(time.RFC3339, monzoUser.ExpiresAt)
	if err != nil {
		panic(err)
	}

	if expiresAt.Before(time.Now()) {
		// We need to refresh the token
		monzoAuthorised := refreshMonzoAccessToken(monzoUser.RefreshToken)
		setMonzoUser(monzoAuthorised.AccessToken, monzoAuthorised.ClientId, time.Now().Add(time.Second * time.Duration(monzoAuthorised.ExpiresIn)).Format(time.RFC3339), monzoAuthorised.RefreshToken, monzoAuthorised.TokenType)
		return getMonzoUser()
	}

	return monzoUser
}

func setMonzoUser(accessToken string, clientId string, expiresAt string, refreshToken string, tokenType string) {
	_, userErr := dynamoDbService.UpdateItem(&dynamodb.UpdateItemInput{
		ExpressionAttributeNames: map[string]*string{
			"#AT": aws.String("access_token"),
			"#CI": aws.String("client_id"),
			"#EA": aws.String("expires_at"),
			"#RT": aws.String("refresh_token"),
			"#TT": aws.String("token_type"),
		},
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":at": {
				S: aws.String(accessToken),
			},
			":ci": {
				S: aws.String(clientId),
			},
			":ea": {
				S: aws.String(expiresAt),
			},
			":rt": {
				S: aws.String(refreshToken),
			},
			":tt": {
				S: aws.String(tokenType),
			},
		},
		Key: map[string]*dynamodb.AttributeValue{
			"user_id": {
				S: aws.String(os.Getenv("MONZO_JOEL_VARDY_USER_ID")),
			},
		},
		TableName:        aws.String("fail-jar-monzo-users"),
		UpdateExpression: aws.String("SET #AT = :at, #CI = :ci, #EA = :ea, #RT = :rt, #TT = :tt"),
	})
	if userErr != nil {
		panic(userErr)
	}
}

func getMonzoAccessToken(code string) (MonzoAuthorised) {
	monzoRequestForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {os.Getenv("MONZO_CLIENT_ID")},
		"client_secret": {os.Getenv("MONZO_CLIENT_SECRET")},
		"redirect_uri":  {os.Getenv("MONZO_OAUTH_CALLBACK_URL")},
		"code":          {code},
	}

	monzoRequestBody := bytes.NewBufferString(monzoRequestForm.Encode())
	monzoResponse, err := http.Post("https://api.monzo.com/oauth2/token", "application/x-www-form-urlencoded", monzoRequestBody)
	if err != nil {
		panic(err)
	}

	defer monzoResponse.Body.Close()
	monzoResponseBody, err := ioutil.ReadAll(monzoResponse.Body)
	if err != nil {
		log.Fatal(err)
	}

	var monzoAuthorised MonzoAuthorised
	err = json.Unmarshal(monzoResponseBody, &monzoAuthorised)
	if err != nil {
		panic(err)
	}

	return monzoAuthorised
}

func refreshMonzoAccessToken(refreshToken string) (MonzoAuthorised) {
	monzoRequestForm := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {os.Getenv("MONZO_CLIENT_ID")},
		"client_secret": {os.Getenv("MONZO_CLIENT_SECRET")},
		"refresh_token": {refreshToken},
	}

	monzoRequestBody := bytes.NewBufferString(monzoRequestForm.Encode())
	monzoResponse, err := http.Post("https://api.monzo.com/oauth2/token", "application/x-www-form-urlencoded", monzoRequestBody)
	if err != nil {
		panic(err)
	}

	defer monzoResponse.Body.Close()
	monzoResponseBody, err := ioutil.ReadAll(monzoResponse.Body)
	if err != nil {
		log.Fatal(err)
	}

	var monzoAuthorised MonzoAuthorised
	err = json.Unmarshal(monzoResponseBody, &monzoAuthorised)
	if err != nil {
		panic(err)
	}

	return monzoAuthorised
}

func payIntoPot(pence int64, buildId string) (MonzoPot) {
	monzoUser := getMonzoUser()

	monzoRequestForm := url.Values{
		"source_account_id": {os.Getenv("MONZO_ACCOUNT_ID")},
		"amount":            {strconv.FormatInt(pence, 10)},
		"dedupe_id":         {buildId},
	}

	requestUrl := fmt.Sprintf("https://api.monzo.com/pots/%s/deposit", os.Getenv("MONZO_POT_ID"))

	monzoRequestBody := bytes.NewBufferString(monzoRequestForm.Encode())
	monzoRequest, err := http.NewRequest(http.MethodPut, requestUrl, monzoRequestBody)
	if err != nil {
		log.Fatal(err)
	}
	monzoRequest.Header.Set("Authorization", fmt.Sprintf("Bearer %s", monzoUser.AccessToken))
	monzoRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	monzoResponse, err := httpClient.Do(monzoRequest)
	if err != nil {
		log.Fatal(err)
	}

	defer monzoResponse.Body.Close()
	monzoResponseBody, err := ioutil.ReadAll(monzoResponse.Body)
	if err != nil {
		log.Fatal(err)
	}

	var monzoPot MonzoPot
	err = json.Unmarshal(monzoResponseBody, &monzoPot)
	if err != nil {
		panic(err)
	}

	return monzoPot
}

func getCircleCiBuild(circleCICallback CircleCICallback) (CircleCIBuild) {
	requestUrl := fmt.Sprintf("https://circleci.com/api/v1.1/project/%s/%s/%s/%d?circle-token=%s", circleCICallback.Payload.VcsType, circleCICallback.Payload.Username, circleCICallback.Payload.RepoName, circleCICallback.Payload.BuildNum, os.Getenv("CIRCLECI_TOKEN"))

	circleCiRequest, err := http.NewRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		log.Fatal(err)
	}
	circleCiRequest.Header.Add("Accept", "application/json")

	circleCiResponse, err := httpClient.Do(circleCiRequest)
	if err != nil {
		log.Fatal(err)
	}

	defer circleCiResponse.Body.Close()
	circleCiResponseBody, err := ioutil.ReadAll(circleCiResponse.Body)
	if err != nil {
		log.Fatal(err)
	}

	var circleCIBuild CircleCIBuild
	err = json.Unmarshal(circleCiResponseBody, &circleCIBuild)
	if err != nil {
		panic(err)
	}

	return circleCIBuild
}

func healthHandler(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(200)
}

func monzoLoginHandler(rw http.ResponseWriter, req *http.Request) {
	resetLastLoginStateCode()

	requestUrl := fmt.Sprintf("https://auth.monzo.com/?client_id=%s&redirect_uri=%s&response_type=code&state=%s", os.Getenv("MONZO_CLIENT_ID"), os.Getenv("MONZO_OAUTH_CALLBACK_URL"), getLastLoginStateCode())

	http.Redirect(rw, req, requestUrl, 307)
}

func monzoLoginCallbackHandler(rw http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()

	if query.Get("state") != getLastLoginStateCode() {
		rw.WriteHeader(422)
		return
	}

	monzoAuthorised := getMonzoAccessToken(query.Get("code"))

	// Only Joel Vardy is allowed to use this
	if monzoAuthorised.UserId != os.Getenv("MONZO_JOEL_VARDY_USER_ID") {
		rw.WriteHeader(403)
		return
	}

	setMonzoUser(monzoAuthorised.AccessToken, monzoAuthorised.ClientId, time.Now().Add(time.Second * time.Duration(monzoAuthorised.ExpiresIn)).Format(time.RFC3339), monzoAuthorised.RefreshToken, monzoAuthorised.TokenType)

	rw.WriteHeader(201)
}

func buildHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	var circleCICallback CircleCICallback
	err = json.Unmarshal(requestBody, &circleCICallback)
	if err != nil {
		panic(err)
	}

	circleCIBuild := getCircleCiBuild(circleCICallback)

	if circleCIBuild.Failed && circleCIBuild.Username == "joelvardy" {
		monzoPot := payIntoPot(100, fmt.Sprintf("%s-%d", circleCIBuild.RepoName, circleCIBuild.BuildNum))
		log.Println(fmt.Sprintf("Looks like build %d on the %s repo failed - there is now £%d in the pot.", circleCIBuild.BuildNum, circleCIBuild.RepoName, monzoPot.Balance/100))
	} else {
		log.Println("Nothing wrong here :)")
	}

	rw.WriteHeader(201)
}

func main() {
	http.HandleFunc("/", healthHandler)
	http.HandleFunc("/monzo/login", monzoLoginHandler)
	http.HandleFunc("/monzo/login/callback", monzoLoginCallbackHandler)
	http.HandleFunc("/build", buildHandler)
	log.Fatal(http.ListenAndServe(":80", nil))
}
