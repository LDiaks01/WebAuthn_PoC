package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"webauthn-example/database"
)

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	// hash the password
	hashStr := hashPassword(password)
	db := database.InitDB()
	newUser := database.User{Email: email, Username: username, Password: hashStr}
	result := db.Create(&newUser)
	if result.Error != nil {
		fmt.Println("Erreur lors de la création de l'utilisateur:", result.Error)
		return
	}
	fmt.Println("Utilisateur créé avec succès: ", newUser.Email)
	http.Redirect(w, r, "/login", http.StatusSeeOther)

}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")
	hashStr := hashPassword(password)
	db := database.InitDB()
	var user database.User
	result := db.Where("email = ? AND password = ?", email, hashStr).First(&user)
	if result.Error != nil {
		fmt.Println("Erreur lors de la recherche de l'utilisateur:", result.Error)
		return
	}
	if user.ID == 0 {
		fmt.Println("Utilisateur non trouvé")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	fmt.Println("Utilisateur trouvé: ", user.Email)
	http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusSeeOther)
}

func hashPassword(password string) string {
	hashBytes := sha256.Sum256([]byte(password))
	hashStr := hex.EncodeToString(hashBytes[:])
	return hashStr
}
