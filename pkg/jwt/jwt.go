package jwts

import (
	"JWT/pkg/pgsql"
	"crypto/rand"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var JwtSecret = []byte("fufelx")

func GenerateToken(userID, ip string) (string, error) {
	Claims := &pgsql.Claims{
		UserID: userID,
		IP:     ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)

	return token.SignedString(JwtSecret)
}

func GenerateRefresh() (string, string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", "", err
	}

	refreshToken := base64.URLEncoding.EncodeToString(tokenBytes)
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return refreshToken, string(hashedToken), nil
}
