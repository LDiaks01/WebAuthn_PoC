package main

import (
	"html/template"
	"net/http"

	"github.com/LDiaks01/WebAuthn_PoC/handlers"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/register.html")

	})

	http.HandleFunc("/register", handlers.RegisterUser)
	http.HandleFunc("/login", ServeLoginPage)
	http.HandleFunc("/postlogin", handlers.HandleLogin)
	http.HandleFunc("/home", HomeHandler)
	http.HandleFunc("/beginmobileregister", handlers.BeginMobileRegistration)
	http.HandleFunc("/finishmobileregister", handlers.FinishMobileRegistration)
	http.HandleFunc("/beginmobilelogin", handlers.BeginMobileLogin)
	http.HandleFunc("/finishmobilelogin", handlers.FinishMobileLogin)
	http.HandleFunc("/getusercredentials", handlers.GetUserCredentialsHandler)
	http.HandleFunc("/deletecredential", handlers.DeleteCredentialHandler)
	http.ListenAndServe(":8080", nil)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	username := r.URL.Query().Get("username")

	tmpl, err := template.ParseFiles("static/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		Email    string
		Username string
	}{
		Email:    email,
		Username: username,
	}
	tmpl.Execute(w, data)
}

func ServeLoginPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/login.html")
}
