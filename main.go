package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
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

var saveDur = 5 * time.Minute

var l = log.Default()
var cookieHandler = securecookie.New( // generate cookie key
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

var clients = make(map[string]Clients)

var accounts = make(map[string]Accounts)
var accountsLock = true

var indexFile, _ = os.ReadFile("templates/index.html")
var loginFile, _ = os.ReadFile("templates/login.html")
var errorFile, _ = os.ReadFile("templates/error.html")
var regFile, _ = os.ReadFile("templates/register.html")
var delFile, _ = os.ReadFile("templates/delete.html")

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
	mode := params.Get("mode")
	if entry, ok := clients[token]; ok {
		if cookie, err := r.Cookie("authG_session"); err == nil { // if the cookie of this session exists in local cookie pool
			cookieValue := make(map[string]string)                                                   // get encoded cookie value
			if err = cookieHandler.Decode("authG_session", cookie.Value, &cookieValue); err == nil { // decode cookie
				userName := cookieValue["name"] // get username
				fmt.Println(userName)
				if _, ok := accounts[userName]; ok {
					entry.Login = true
					l.Println("client successfully logged in: " + token)
					if mode == "api" {
						_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"ok\"}"))
					} else {
						r.Method = http.MethodGet
						http.Redirect(w, r, strings.ReplaceAll(entry.Redirect, "{{token}}", token), http.StatusSeeOther)
					}
				} else {
					l.Println("client trying to login: " + entry.Token)
					_, _ = w.Write(loginFile)
				}
			} else {
				_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "Cookie invalid!")))
			}
		} else {
			l.Println("client trying to login: " + entry.Token)
			_, _ = w.Write(loginFile)
		}
		clients[token] = entry
	} else {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "This token does not exists or has already expired!")))
	}
}

func postAuth(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	usr := r.FormValue("usr")
	psw := r.FormValue("psw")
	remember := r.FormValue("remember")
	params, _ := url.ParseQuery(r.URL.RawQuery)
	token := params.Get("token")
	mode := params.Get("mode")
	if entry, ok := clients[token]; ok {
		if auth(usr, psw) == true {
			entry.Login = true
			l.Println("client successfully logged in: " + token)
			if mode == "api" {
				_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"ok\"}"))
			} else {
				if remember == "true" {
					setSession(usr, w)
				}
				r.Method = http.MethodGet
				http.Redirect(w, r, strings.ReplaceAll(entry.Redirect, "{{token}}", token), http.StatusSeeOther)
			}
		} else {
			_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "Failed to authorize!")))
		}
		clients[token] = entry
	} else {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", "This token does not exists or has already expired!")))
	}
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	params, _ := url.ParseQuery(r.URL.RawQuery)
	redirect := params.Get("redirect")
	mode := params.Get("mode")
	clearSession(w)
	if mode == "api" {
		_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"ok\"}"))
	} else {
		if redirect == "" {
			_, _ = w.Write([]byte("You are now logged out!"))
		} else {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	}
}

func setSession(userName string, response http.ResponseWriter) {
	value := map[string]string{ // define a new cookie value structure
		"name": userName,
	}
	if encoded, err := cookieHandler.Encode("authG_session", value); err == nil {
		cookie := &http.Cookie{ // define a new cookie structure for current username
			Name:   "authG_session",
			Value:  encoded,
			Path:   "/",
			MaxAge: 86400,
		}
		http.SetCookie(response, cookie)
	}
}

func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{ // define an empty cookie structure
		Name:   "authG_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie) // set for current session
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

func getReg(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write(regFile)
}

func postReg(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	usr := r.FormValue("usr")
	psw := r.FormValue("psw")
	params, _ := url.ParseQuery(r.URL.RawQuery)
	redirect := params.Get("redirect")
	status, reason := addAccount(usr, psw)
	if status {
		if redirect == "" {
			_, _ = w.Write([]byte("Done! You can close this page now!"))
		} else {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	} else {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", reason)))
	}
}

func getDel(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write(delFile)
}

func postDel(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	usr := r.FormValue("usr")
	psw := r.FormValue("psw")
	params, _ := url.ParseQuery(r.URL.RawQuery)
	redirect := params.Get("redirect")
	status, reason := delAccount(usr, psw)
	if status {
		if redirect == "" {
			_, _ = w.Write([]byte("Done! You can close this page now!"))
		} else {
			http.Redirect(w, r, redirect, http.StatusSeeOther)
		}
	} else {
		_, _ = w.Write([]byte(strings.ReplaceAll(string(errorFile), "{{text}}", reason)))
	}
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
	accountsLock = false
}

func addAccount(usr string, psw string) (bool, string) {
	hash := sha256.New()
	hash.Write([]byte(usr + "||" + psw))
	_, ok := accounts[usr]
	if !ok {
		accounts[usr] = Accounts{Hash: base64.URLEncoding.EncodeToString(hash.Sum(nil)), Uuid: uuid.NewString()}
		l.Printf("Add an account: %s\n", usr)
		return true, "ok"
	} else {
		l.Printf("Account %s exists\n", usr)
		return false, "Account exists"
	}
}

func delAccount(usr string, psw string) (bool, string) {
	if auth(usr, psw) == true {
		delete(accounts, usr)
		return true, "ok"
	} else {
		return false, "Failed to authorize!"
	}
}

func flushAccount() {
	file, _ := json.MarshalIndent(accounts, "", " ")
	_ = ioutil.WriteFile("accounts.json", file, 0644)
}

func saveAccount() {
	defer flushAccount()
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		flushAccount()
		os.Exit(0)
	}()
	for {
		if !accountsLock {
			flushAccount()
		} else {
			for {
				if !accountsLock {
					flushAccount()
					break
				}
			}
		}
		time.Sleep(saveDur)
	}
}

func main() {
	l.Println("auth service starting")

	loadAccount()

	router.HandleFunc("/", getRoot).Methods("GET")
	router.HandleFunc("/auth", getAuth).Methods("GET")
	router.HandleFunc("/auth", postAuth).Methods("POST")
	router.HandleFunc("/logout", getLogout).Methods("GET")
	router.HandleFunc("/register", getReg).Methods("GET")
	router.HandleFunc("/register", postReg).Methods("POST")
	router.HandleFunc("/delete", getDel).Methods("GET")
	router.HandleFunc("/delete", postDel).Methods("POST")
	router.HandleFunc("/add_auth", addAuthClient).Methods("POST")
	router.HandleFunc("/query_auth", queryLoginStatus).Methods("POST")

	router.NotFoundHandler = http.HandlerFunc(notFound)

	go expire()
	go saveAccount()

	l.Println("auth service started")
	err := http.ListenAndServe(":3333", router)
	if err != nil {
		l.Fatalln(err)
	}
}
