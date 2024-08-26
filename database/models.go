package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
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
	UserID              string // the email of the user
	CredentialID        string // base64urlEncoded
	PublicKey           string // base64urlEncoded
	AttestationType     string
	Transport           string
	UserPresent         bool
	UserVerified        bool
	BackupEligible      bool
	BackupState         bool
	AAGUID              string `gorm:"type:varchar(255)"` // base64urlEncoded
	SignCount           uint32
	Attachment          string
	LastAuthenticatedAt time.Time
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
	db          *gorm.DB
	redisClient *redis.Client
	onceDb      sync.Once
	onceRedis   sync.Once
	ctx         = context.Background() //
)

const RedisExpirationDuration = 3 * time.Minute

// to iniiate the database by using the Singleton design pattern
// to ensure that the database is initiated only once
func InitDB() *gorm.DB {
	onceDb.Do(func() {

		dbHost := os.Getenv("DB_HOST")
		dbPort := os.Getenv("DB_PORT")
		dbUser := os.Getenv("DB_USER")
		dbPass := os.Getenv("DB_PASS")
		dsn := dbUser + ":" + dbPass + "@tcp(" + dbHost + ":" + dbPort + ")/passkeys?charset=utf8mb4&parseTime=True&loc=Local"

		//dsn := "root:@tcp(127.0.0.1:3306)/passkeys?charset=utf8mb4&parseTime=True&loc=Local"
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

// same for redis database
// to iniiate the database by using the Singleton design pattern
// to ensure that the database is initiated only once
func InitRedis() *redis.Client {

	onceRedis.Do(func() {

		// Obtenez les variables d'environnement
		redisHost := os.Getenv("REDIS_HOST")
		redisPort := os.Getenv("REDIS_PORT")
		redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

		//fmt.Print("Redis Addr: ", redisAddr)

		// Configurez le client Redis
		redisClient = redis.NewClient(&redis.Options{
			Addr: redisAddr,
		})

		// Créez un contexte avec un délai d'attente pour tester la connexion
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		// Testez la connexion
		_, err := redisClient.Ping(ctx).Result()
		if err != nil {
			log.Fatalf("could not connect to Redis: %v", err)
		}

		fmt.Print("Connected to Redis ", redisAddr, "\n")
	})

	//fmt.Println("Connected to Redis!")
	return redisClient
}
