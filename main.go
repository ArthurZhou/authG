package main

import (
	"fmt"
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
	Uuid     string
	Redirect string
	Expire   int64
	Login    bool
}

var l = log.Default()
var clients []Clients
var router = mux.NewRouter()

func lookup(id string) (bool, int) {
	for i, v := range clients {
		if id == v.Uuid {
			return true, i
		}
	}
	return false, -1
}

func auth(usr string, psw string) bool {
	l.Println(usr, psw)
	return true
}

func getRoot(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("auth server"))
}

func getAuth(w http.ResponseWriter, r *http.Request) {
	params, _ := url.ParseQuery(r.URL.RawQuery)
	id := params.Get("uuid")
	result, index := lookup(id)
	if result {
		client := clients[index]
		l.Println("client trying to login: " + client.Uuid)
		file, _ := os.ReadFile("login.html")
		_, _ = w.Write(file)
	} else {
		_, _ = w.Write([]byte("This uuid does not exists or has already expired!"))
	}
}

func postAuth(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	usr := r.FormValue("usr")
	psw := r.FormValue("psw")
	params, _ := url.ParseQuery(r.URL.RawQuery)
	id := params.Get("uuid")
	fmt.Println("aa: ", id)
	result, index := lookup(id)
	fmt.Println(result, index)
	if result {
		if auth(usr, psw) == true {
			clients[index].Login = true
			l.Println("client successfully logged in: " + id)
			http.Redirect(w, r, strings.ReplaceAll(clients[index].Redirect, "{{uuid}}", id), http.StatusTemporaryRedirect)
		} else {
			_, _ = w.Write([]byte("Failed to authorize!"))
		}
	} else {
		_, _ = w.Write([]byte("This uuid does not exists or has already expired!"))
	}
}

func addAuthClient(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	redirect := r.FormValue("redirect")
	_, err := url.ParseRequestURI(redirect)
	if err == nil {
		id := uuid.NewString()
		l.Printf("[%s]: add auth client: %s  redirect to: %s\n", r.RemoteAddr, id, redirect)
		clients = append(clients, Clients{
			Uuid:     id,
			Redirect: redirect,
			Expire:   time.Now().Unix() + 600,
			Login:    false,
		})
		_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"" + id + "\"}"))
	} else {
		_, _ = w.Write([]byte("{\"status\": false, \"reason\": \"invalid redirect url\"}"))
	}
}

func queryLoginStatus(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := r.FormValue("uuid")
	result, index := lookup(id)
	if result {
		if clients[index].Login {
			_, _ = w.Write([]byte("{\"status\": true, \"reason\": \"user logged in\"}"))
		} else {
			_, _ = w.Write([]byte("{\"status\": false, \"reason\": \"user not logged in\"}"))
		}
	} else {
		_, _ = w.Write([]byte("{\"status\": false, \"reason\": \"uuid does not exists or has already expired\"}"))
	}
}

func notFound(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("NOT FOUND"))
}

func expire() {
	for {
		for index, client := range clients {
			if client.Expire <= time.Now().Unix() {
				clients = append(clients[:index], clients[index+1:]...)
				log.Println("delete an expired client: " + client.Uuid)
			}
		}
		time.Sleep(60 * time.Second)
	}
}

func main() {
	l.Println("auth server starting")
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
