package main

import (
	"errors"
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

const secretKey = "secret_key"

func main() {

	user := &User{
		ID:       1,
		Name:     "main",
		IsAdmin:  false,
		IsBanned: false,
	}

	token, err := generateToken(user)
	if err != nil {
		log.Println("generateToken error:", err)
		return
	}

	log.Println(token)

	claims, err := verifyToken(token)
	if err != nil {
		log.Println("verifyToken error:", err)
		return
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
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		log.Println("token.SignedString error")
		return "", err
	}

	return tokenString, nil
}

// Функция для проверки токена, полученного от клиента
func verifyToken(tokenString string) (*jwt.MapClaims, error) {

	// Разбираем и проверяем токен с помощью секретного ключа
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		if err != nil {
			// Выводим причину невалидности токена или тип ошибки
			if errors.Is(err, jwt.ErrTokenMalformed) {
				log.Println("token is malformed")
			} else if errors.Is(err, jwt.ErrTokenExpired) {
				log.Println("token is expired")
			} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
				log.Println("token is not valid yet")
			} else {
				log.Println("token is not valid")
			}
			return nil, err
		}
	}

	// Извлекаем claims из токена
	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok || !token.Valid {
		log.Println("token claims are not valid")
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
