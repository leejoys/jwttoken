package main

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID       int
	Name     string
	IsAdmin  bool
	IsBanned bool
}

func main() {

	user := &User{
		ID:       1,
		Name:     "main",
		IsAdmin:  false,
		IsBanned: false,
	}

	token, err := generateToken(user)
	if err != nil {
		log.Println(err)
	}

	claims, err := verifyToken(token)
	if err != nil {
		log.Println(err)
	}

	log.Println(claims)
}

// Функция для генерации токена на основе данных пользователя
func generateToken(user *User) (string, error) {

	// Создаем новый токен с claims пользователя
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":        user.ID,
		"name":      user.Name,
		"is_admin":  user.IsAdmin,
		"is_banned": user.IsBanned,
		"exp":       time.Now().Add(time.Hour * 72).Unix(),
	})

	// Подписываем токен секретным ключом
	tokenString, err := token.SignedString([]byte("secret_key"))
	if err != nil {
		log.Println(1)
		return "", err
	}

	return tokenString, nil
}

// Функция для проверки токена, полученного от клиента
func verifyToken(tokenString string) (*jwt.MapClaims, error) {
	// Разбираем и проверяем токен с помощью секретного ключа
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "secret_key", nil
	})
	if err != nil {
		log.Println("jwt.ParseWithClaims error:")
		log.Println(err.Error())
		return nil, err
	}

	// Извлекаем claims из токена
	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok || !token.Valid {
		log.Println("token.Claims.(*jwt.MapClaims): !ok || !token.Valid")
		return nil, err
	}

	return claims, nil
}
