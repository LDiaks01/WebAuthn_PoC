package handlers

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// Définir l'interface User
type User interface {
	WebAuthnID() []byte
	WebAuthnName() string
	WebAuthnDisplayName() string
	WebAuthnIcon() string
	WebAuthnCredentials() []webauthn.Credential

	AddCredential(cred webauthn.Credential)
}

// Implémenter une structure qui satisfait l'interface User avec des données par défaut
type DefaultUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Icon        string

	// d'autres champs si nécessaire
	Credentials []webauthn.Credential
}

// Implémenter les méthodes de l'interface User pour DefaultUser

func (u DefaultUser) WebAuthnID() []byte {
	return u.ID
}

func (u DefaultUser) WebAuthnName() string {
	return u.Name
}

func (u DefaultUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u DefaultUser) WebAuthnIcon() string {
	return u.Icon
}

func (u DefaultUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u DefaultUser) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}
