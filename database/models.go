package database

import (
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
	CredentialID    []byte
	PublicKey       []byte `gorm:"type:blob;not null"`
	AttestationType string
	Transport       string
	UserPresent     bool
	UserVerified    bool
	BackupEligible  bool
	BackupState     bool
	AAGUID          []byte `gorm:"type:binary(16)"`
	SignCount       uint32
	Attachment      string
}

var (
	db   *gorm.DB
	once sync.Once
)

func InitDB() *gorm.DB {
	once.Do(func() {
		dsn := "root:@tcp(127.0.0.1:3306)/passkeys?charset=utf8mb4&parseTime=True&loc=Local"
		var err error
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			log.Fatal(err)
		}

		// Migrer les modèles
		db.AutoMigrate(&User{}, &UserPasskey{})
	})

	return db
}
