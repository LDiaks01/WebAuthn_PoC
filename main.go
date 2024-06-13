package main

import (
	"html/template"
	"net/http"
	"webauthn-example/handlers"
)

/*
var (
	webAuthn *webauthn.WebAuthn
	err      error
)
*/
// Initialisez l'instance de WebAuthn

func main() {
	// Créer un objet User avec des données par défaut

	//db := database.InitDB()

	/*user := database.User{Email: "user@example.com", Username: "user1", Password: "password123"}

	result := db.Create(&user)
	if result.Error != nil {
		fmt.Println("Erreur lors de la création de l'utilisateur:", result.Error)
		return
	}
	fmt.Println("Utilisateur créé avec succès:", user)
	*/

	/*
		wconfig := &webauthn.Config{
			RPDisplayName: "Go Webauthn",                // Display Name for your site
			RPID:          "go-webauthn.local",          // Generally the FQDN for your site
			RPOrigins:     []string{"http://localhost"}, // The origin URLs allowed for WebAuthn requests
		}

		if webAuthn, err = webauthn.New(wconfig); err != nil {
			fmt.Println(err)
		}
	*/
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
