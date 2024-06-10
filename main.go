package main

import (
	"fmt"
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
		http.ServeFile(w, r, "login.html")

	})

	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		// Register
		// get the username and password from the form
		username := r.FormValue("username")
		password := r.FormValue("password")
		//send Hello Username
		fmt.Fprintf(w, "Hello Sirs %s %s", username, password)

	})

	//http.HandleFunc("/registerPIN", handlers.CallWindowsHelloPIN)

	// Appeler la fonction Windows pour verrouiller l'écran
	http.HandleFunc("/registerPIN", handlers.BeginRegistration)
	http.HandleFunc("/finish", handlers.FinishRegistration)

	http.ListenAndServe(":8080", nil)
}
