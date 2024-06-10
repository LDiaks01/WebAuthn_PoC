package datas

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-webauthn/webauthn/webauthn"
)

const sessionDataFile = "session_data.json"

// LoadSessionData reads the session data from the JSON file
func LoadSessionData() ([]webauthn.SessionData, error) {

	// Ouvrir le fichier JSON
	file, err := os.Open(sessionDataFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil, err
	}
	defer file.Close()

	// Lire le contenu du fichier
	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return nil, err
	}

	// Dé-sérialiser le contenu JSON dans une variable de type SessionData
	//var sessionData SessionData
	var sessionData2 []webauthn.SessionData
	err = json.Unmarshal(byteValue, &sessionData2)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return nil, err
	}

	// Afficher le contenu de la variable sessionData
	fmt.Printf("SessionData: %+v\n", sessionData2)
	//file, err := ioutil.ReadFile(sessionDataFile)
	//print the content of the file
	//fmt.Println(file)
	/*if err != nil {
		if os.IsNotExist(err) {
			return []webauthn.SessionData{}, nil // Retourner une slice vide en cas de fichier inexistant
		}
		return nil, err // Retourner à la fois nil et l'erreur
	}

	var sessionData []webauthn.SessionData
	err = json.Unmarshal(file, &sessionData)
	fmt.Println(sessionData)
	fmt.Println(err)
	if err != nil {
		return nil, err
	}
	*/
	return sessionData2, nil
}

// SaveSessionData writes the session data to the JSON file
func SaveSessionData(sessionData *webauthn.SessionData) error {
	data, err := json.MarshalIndent(sessionData, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(sessionDataFile, data, 0644)
	if err != nil {
		return err
	}

	return nil
}
