package mfa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"time"

	"github.com/SomeonesDads/seleksilabpro-2/auth-provider/server/internal/repository"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type TOTPVerifier struct {
	repo *repository.TOTPRepository
	key  []byte
}

func NewTOTPVerifier(repo *repository.TOTPRepository, key []byte) *TOTPVerifier {
	return &TOTPVerifier{repo: repo, key: append([]byte(nil), key...)}
}

func (v *TOTPVerifier) Verify(ctx context.Context, userID uuid.UUID, code string) bool {
	credential, err := v.repo.FindByUserID(ctx, userID)
	if err != nil {
		return false
	}
	secret, err := decrypt(v.key, credential.EncryptedSecret)
	if err != nil {
		return false
	}
	valid, err := totp.ValidateCustom(code, string(secret), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}

func EncryptSecret(key []byte, secret string) ([]byte, error) {
	return encrypt(key, []byte(secret))
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, io.ErrUnexpectedEOF
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}
