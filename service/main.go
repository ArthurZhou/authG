package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var router = mux.NewRouter()

type Response struct {
	Status bool   `json:"status"`
	Reason string `json:"reason"`
}

func addAuth(redirect string) (bool, string) {
	formData := url.Values{
		"redirect": {redirect},
	}

	client := &http.Client{}

	//Not working, the post data is not a form
	req, err := http.NewRequest("POST", "http://localhost:3333/add_auth", strings.NewReader(formData.Encode()))
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(string(body))

	var data Response
	_ = json.Unmarshal(body, &data)
	if data.Status == true {
		return true, data.Reason
	} else {
		return false, data.Reason
	}
}

func queryAuth(id string) (bool, string) {
	formData := url.Values{
		"token": {id},
	}

	client := &http.Client{}

	//Not working, the post data is not a form
	req, err := http.NewRequest("POST", "http://localhost:3333/query_auth", strings.NewReader(formData.Encode()))
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	data := &Response{}
	_ = json.Unmarshal(body, data)
	if data.Status == true {
		return true, data.Reason
	} else {
		return false, data.Reason
	}
}

func getRoot(w http.ResponseWriter, r *http.Request) {
	status, result := addAuth("http://localhost:8080/index?token={{token}}")
	if status {
		http.Redirect(w, r, "http://localhost:3333/auth?token="+result, http.StatusTemporaryRedirect)
	} else {
		_, _ = w.Write([]byte(result))
	}
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	params, _ := url.ParseQuery(r.URL.RawQuery)
	status, result := queryAuth(params.Get("token"))
	if status {
		_, _ = w.Write([]byte("success"))
	} else {
		_, _ = w.Write([]byte(result))
	}
}

func main() {
	router.HandleFunc("/", getRoot).Methods("GET")
	router.HandleFunc("/index", getIndex).Methods("GET")

	log.Println("sample service started")
	_ = http.ListenAndServe(":8080", router)
}
