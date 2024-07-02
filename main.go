package main

import (
	"html/template"
	"net/http"
	"webauthn-example/handlers"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/register.html")

	})

	http.HandleFunc("/register", handlers.RegisterUser)
	http.HandleFunc("/login", ServeLoginPage)
	http.HandleFunc("/postLogin", handlers.HandleLogin)
	http.HandleFunc("/home", HomeHandler)

	//http.HandleFunc("/registerPIN", handlers.CallWindowsHelloPIN)

	// Appeler la fonction Windows pour verrouiller l'écran
	http.HandleFunc("/registerPIN", handlers.BeginRegistration)
	http.HandleFunc("/finish", handlers.FinishRegistration)
	http.HandleFunc("/beginLogin", handlers.BeginLogin)
	http.HandleFunc("/finishLogin", handlers.FinishLogin)
	http.HandleFunc("/getUserCredentials", handlers.GetUserCredentialsHandler)
	http.HandleFunc("/deleteCredential", handlers.DeleteCredentialHandler)
	http.ListenAndServe(":8080", nil)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	username := r.URL.Query().Get("username")

	// You can pass the email and username to your template
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
	http.ServeFile(w, r, "login.html")
}
