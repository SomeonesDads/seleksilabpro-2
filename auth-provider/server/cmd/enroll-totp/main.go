package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	appdb "github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/db"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/mfa"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/models"
	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/pquerna/otp/totp"
)

// enroll-totp provisions a user's TOTP credential.
// Required environment variables: DATABASE_URL, MFA_ENCRYPTION_KEY, EMAIL.
func main() {
	ctx := context.Background()
	databaseURL := os.Getenv("DATABASE_URL")
	keyText := os.Getenv("MFA_ENCRYPTION_KEY")
	email := os.Getenv("EMAIL")
	if databaseURL == "" || keyText == "" || email == "" {
		log.Fatal("DATABASE_URL, MFA_ENCRYPTION_KEY, and EMAIL are required")
	}
	key, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(key) != 32 {
		log.Fatal("MFA_ENCRYPTION_KEY must be base64-encoded 32 bytes")
	}

	gormDB, err := appdb.ConnectGORM(ctx, databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	sqlDB, err := gormDB.DB()
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()

	userRepo := repository.NewUserRepository(gormDB)
	user, err := userRepo.FindByEmail(ctx, email)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SeleksiLab",
		AccountName: user.Email,
		SecretSize:  20,
	})
	if err != nil {
		log.Fatal(err)
	}
	encrypted, err := mfa.EncryptSecret(key, keyData.Secret())
	if err != nil {
		log.Fatal(err)
	}
	if err := repository.NewTOTPRepository(gormDB).Upsert(ctx, &models.UserTOTP{UserID: user.ID, EncryptedSecret: encrypted}); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("TOTP enrolled for %s\n", user.Email)
	fmt.Printf("Secret: %s\n", keyData.Secret())
	fmt.Printf("URI: %s\n", keyData.URL())
}
