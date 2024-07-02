package database

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/xeipuuv/gojsonschema"
)

type AAGUIDItem struct {
	Name      string `json:"name"`
	IconDark  string `json:"icon_dark"`
	IconLight string `json:"icon_light"`
}

// Définir une structure pour l'objet racine JSON
type AAGUIDSchema struct {
	Items map[string]AAGUIDItem `json:"-"`
}

func AAGUIDJsonLoader() map[string]AAGUIDItem {
	schemaData, err := os.ReadFile("aaguid_schema.json")
	if err != nil {
		fmt.Println("Erreur lors de la lecture du fichier de schéma JSON : ", err)
		return nil
	}

	jsonData, err := os.ReadFile("combined_aaguid.json")
	if err != nil {
		fmt.Println("Erreur lors de la lecture du fichier JSON : ", err)
		return nil
	}

	schemaLoader := gojsonschema.NewBytesLoader(schemaData)

	// Charger les données JSON
	dataLoader := gojsonschema.NewBytesLoader(jsonData)

	// Valider le document JSON par rapport au schéma
	result, err := gojsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		fmt.Println("Erreur lors de la validation du document JSON : ", err)
		return nil
	}

	if !result.Valid() {
		fmt.Println("Le document JSON n'est pas valide par rapport au schéma :")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		return nil
	}

	// Si le document est valide, décoder le JSON dans une structure Go
	var aaguidSchema AAGUIDSchema
	if err := json.Unmarshal(jsonData, &aaguidSchema.Items); err != nil {
		log.Fatalf("Erreur lors du décodage JSON : %v", err)
	}

	return aaguidSchema.Items

}

func RetrieveAAGUIDInfo(aaguid string, aaguidSchema AAGUIDSchema) AAGUIDItem {

	item, ok := aaguidSchema.Items[aaguid]
	if !ok {
		return AAGUIDItem{}
	}
	return item
}
