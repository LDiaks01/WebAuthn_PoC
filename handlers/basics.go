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

	db := database.InitDB()

	//first verify if the user already exists
	var user database.User
	result := db.Where("email = ?", userBody.Email).First(&user)
	if result.Error == nil {
		fmt.Println("Utilisateur déjà existant: ", user.Email)
		JSONResponse(w, "User already exists", http.StatusBadRequest)
		return
	}
	hashStr := hashPassword(userBody.Password)

	newUser := database.User{Email: userBody.Email, Username: userBody.Username, Password: hashStr}
	result = db.Create(&newUser)
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
	w.Header().Set("Content-Type", "application/json")
	type LoginUserBody struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	var userBody LoginUserBody
	err := json.NewDecoder(r.Body).Decode(&userBody)
	if err != nil {
		//http.Error(w, "Error decoding JSON content, verify the JSON Format"+err.Error(), http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		//http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusSeeOther)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "check the JSON format",
			"status":  "incorrect",
		})
		return
	}

	if userBody.Email == "" || userBody.Password == "" {
		//http.Error(w, "Error decoding JSON content, verify the JSON Format"+err.Error(), http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		//http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusSeeOther)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "check the JSON format",
			"status":  "incorrect",
		})
		return
	}

	hashStr := hashPassword(userBody.Password)
	db := database.InitDB()
	var user database.User
	fmt.Println("Email:", userBody.Email)
	result := db.Where("email = ? AND password = ?", userBody.Email, hashStr).First(&user)
	if result.Error != nil {
		fmt.Println("Erreur lors de la recherche de l'utilisateur:", result.Error)
		w.WriteHeader(http.StatusBadRequest)
		//http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusSeeOther)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "user/password incorrect",
			"status":  "incorrect",
		})
		return
	}
	if user.ID == 0 {
		w.WriteHeader(http.StatusBadRequest)
		//http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusSeeOther)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "user/password incorrect",
			"status":  "incorrect",
		})
		return
	}

	fmt.Println("Utilisateur trouvé: ", user.Email)

	// return a http response with a cookie
	// http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//http.Redirect(w, r, "/home?email="+user.Email+"&username="+user.Username, http.StatusSeeOther)
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Login success, nice buddy",
		"status":   "success",
		"email":    user.Email,
		"username": user.Username,
	})

}

func hashPassword(password string) string {
	hashBytes := sha256.Sum256([]byte(password))
	hashStr := hex.EncodeToString(hashBytes[:])
	return hashStr
}
