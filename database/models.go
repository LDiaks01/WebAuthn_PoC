package database

import (
	"fmt"
	"log"
	"sync"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email    string
	Username string
	Password string
}

type UserPasskey struct {
	gorm.Model
	UserID          string
	CredentialID    string
	PublicKey       []byte
	AttestationType string
	Transport       string
	UserPresent     bool
	UserVerified    bool
	BackupEligible  bool
	BackupState     bool
	AAGUID          []byte `gorm:"type:binary(16)"`
	SignCount       uint32
	Attachment      string
	ClientDataHash  string
}

type MobilePasskey struct {
	gorm.Model
	UserID       string
	CredentialID string
	Type         string
	Transport    string
	AuthData     string
}

var (
	db   *gorm.DB
	once sync.Once
)

// to iniiate the database by using the Singleton design pattern
// to ensure that the database is initiated only once
func InitDB() *gorm.DB {
	once.Do(func() {
		dsn := "root:@tcp(127.0.0.1:3306)/passkeys?charset=utf8mb4&parseTime=True&loc=Local"
		var err error
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			log.Fatal(err)
		}

		// Migrer les modèles
		err = db.AutoMigrate(&User{}, &UserPasskey{})
		if err != nil {
			fmt.Println("Erreur lors de la migration des modèles : ", err)
		}

	})

	return db
}
