package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Clients struct {
	Token    string
	Redirect string
	Expire   int64
	Login    bool
}

type Accounts struct {
	Hash string `json:"hash"`
	Uuid string `json:"uuid"`
}

var checkDur = 2 * time.Minute

// var checkDur = 1 * time.Second

var expireDur = 600

// var expireDur = 10

var l = log.Default()

var clients = make(map[string]Clients)

var accounts = make(map[string]Accounts)

var indexFile, _ = os.ReadFile("index.html")
var loginFile, _ = os.ReadFile("login.html")
var errorFile, _ = os.ReadFile("error.html")

var router = mux.NewRouter()

func auth(usr string, psw string) bool {
	user := accounts[usr]
	hash := sha256.New()
	hash.Write([]byte(usr + "||" + psw))
	if user.Hash == base64.URLEncoding.EncodeToString(hash.Sum(nil)) {
		return true
	} else {
		return false
	}
}

func getRoot(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write(indexFile)
}

func getAuth(w http.ResponseWriter, r *http.Request) {
	params, _ := url.ParseQuery(r.URL.RawQuery)
	token := params.Get("token")
	if entry, ok := clients[token]; ok {
		l.Println("client trying to login: " + entry.Token)
		_, _ = w.Write(loginFile)
	} else {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "This token does not exists or has already expired!")))
	}
}

func postAuth(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	usr := r.FormValue("usr")
	psw := r.FormValue("psw")
	params, _ := url.ParseQuery(r.URL.RawQuery)
	token := params.Get("token")
	if entry, ok := clients[token]; ok {
		if auth(usr, psw) == true {
			entry.Login = true
			l.Println("client successfully logged in: " + token)
			http.Redirect(w, r, strings.ReplaceAll(entry.Redirect, "{{token}}", token), http.StatusTemporaryRedirect)
		} else {
			_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "Failed to authorize!")))
		}
		clients[token] = entry
	} else {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "This token does not exists or has already expired!")))
	}
}

func addAuthClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	redirect := r.FormValue("redirect")
	_, err := url.ParseRequestURI(redirect)
	if err == nil {
		token := uuid.NewString()
		l.Printf("[%s]: add auth client: %s  redirect to: %s\n", r.RemoteAddr, token, redirect)
		clients[token] = Clients{
			Token:    token,
			Redirect: redirect,
			Expire:   time.Now().Unix() + int64(expireDur),
			Login:    false,
		}
		_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"" + token + "\"}"))
	} else {
		_, _ = w.Write([]byte("{\"status\": false, \"reason\": \"invalid redirect url\"}"))
	}
}

func queryLoginStatus(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := r.FormValue("token")
	if entry, ok := clients[token]; ok {
		if entry.Login {
			_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"user logged in\"}"))
		} else {
			_, _ = w.Write([]byte("{\"status\": false, \"reason\": \"user not logged in\"}"))
		}
	} else {
		_, _ = w.Write([]byte("{\"status\": false, \"reason\": \"token does not exists or has already expired\"}"))
	}
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "Page not found!")))
}

func expire() {
	for {
		for _, client := range clients {
			if client.Expire <= time.Now().Unix() {
				delete(clients, client.Token)
				log.Println("delete an expired client: " + client.Token)
			}
		}
		time.Sleep(checkDur)
	}
}

func loadAccount() {
	accountFile, _ := os.ReadFile("accounts.json")
	_ = json.Unmarshal(accountFile, &accounts)
}

func main() {
	l.Println("auth server starting")

	loadAccount()

	router.HandleFunc("/", getRoot).Methods("GET")
	router.HandleFunc("/auth", getAuth).Methods("GET")
	router.HandleFunc("/auth", postAuth).Methods("POST")
	router.HandleFunc("/add_auth", addAuthClient).Methods("POST")
	router.HandleFunc("/query_auth", queryLoginStatus).Methods("POST")
	router.NotFoundHandler = http.HandlerFunc(notFound)

	go expire()

	l.Println("auth server started")
	err := http.ListenAndServe(":3333", router)
	if err != nil {
		l.Fatalln(err)
	}
}
