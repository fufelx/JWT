package api

import (
	jwts "JWT/pkg/jwt"
	"JWT/pkg/pgsql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
)

var db, _ = pgsql.New()

func Token(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	ip := r.RemoteAddr

	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	accessToken, err := jwts.GenerateToken(userID, ip)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, hashedRefreshToken, err := jwts.GenerateRefresh()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	useridint, _ := strconv.Atoi(userID)

	err = db.AddUser(int64(useridint), ip, hashedRefreshToken)
	if err != nil {
		http.Error(w, "Failed to write new user in db", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := jwt.ParseWithClaims(reqBody.AccessToken, &pgsql.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwts.JwtSecret, nil
	})

	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(*pgsql.Claims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	userID := claims.UserID
	oldIP := claims.IP

	useridint, _ := strconv.Atoi(userID)
	refreshtoken, err := db.UserInfo(int64(useridint))
	if err != nil {
		log.Fatal(err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(refreshtoken), []byte(reqBody.RefreshToken))
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Проверка изменения IP
	newIP := r.RemoteAddr
	if newIP != oldIP {
		fmt.Printf("Warning: IP changed for user %s. Old IP: %s, New IP: %s. Email sent to: %s\n", userID, oldIP, newIP, "example")
	}

	// Генерация нового Access токена
	newAccessToken, err := jwts.GenerateToken(userID, newIP)
	if err != nil {
		http.Error(w, "Failed to generate new access token", http.StatusInternalServerError)
		return
	}

	refreshToken, hashedRefreshToken, err := jwts.GenerateRefresh()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	db.UpdateUser(int64(useridint), hashedRefreshToken)

	response := map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
