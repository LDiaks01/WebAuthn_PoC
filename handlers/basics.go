package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/LDiaks01/WebAuthn_PoC/database"
)

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	type RegisterUserBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	var userBody RegisterUserBody
	err := json.NewDecoder(r.Body).Decode(&userBody)
	// Décoder le JSON à partir du corps de la requête
	if err != nil {
		//http.Error(w, "Error decoding JSON content, verify the JSON Format"+err.Error(), http.StatusBadRequest)
		fmt.Println("Error decoding JSON:", err)
		JSONResponse(w, "Error decoding JSON content, verify the JSON Format"+err.Error(), http.StatusBadRequest)
		return
	}

	if userBody.Email == "" || userBody.Username == "" || userBody.Password == "" {
		JSONResponse(w, "Missing Fields", http.StatusBadRequest)
		return
	}

	hashStr := hashPassword(userBody.Password)
	db := database.InitDB()
	newUser := database.User{Email: userBody.Email, Username: userBody.Username, Password: hashStr}
	result := db.Create(&newUser)
	if result.Error != nil {
		fmt.Println("Erreur lors de la création de l'utilisateur:", result.Error)
		return
	}
	fmt.Println("Utilisateur créé avec succès: ", newUser.Email)
	// return a http response with a cookie

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"result": "Account created successfully",
		"status": "success",
	})

	//http.Redirect(w, r, "/login", http.StatusSeeOther)

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

	// return a http response with a cookie
	// http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token":  "SampleToken1234",
		"status": "success",
	})

}

func hashPassword(password string) string {
	hashBytes := sha256.Sum256([]byte(password))
	hashStr := hex.EncodeToString(hashBytes[:])
	return hashStr
}
