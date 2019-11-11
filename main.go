package main

import (
	"io/ioutil"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/xerrors"
)

func main() {
	privt, err := ioutil.ReadFile("example_rsa")
	if err != nil {
		panic(err)
	}
	publc, err := ioutil.ReadFile("example_rsa.pub.pkcs8")
	if err != nil {
		panic(err)
	}

	tkn, err := newJWT(privt)
	if err != nil {
		panic(err)
	}
	log.Printf("Token: %+v\n", tkn)

	claims, err := parseJWT(tkn, publc)
	if err != nil {
		panic(err)
	}
	log.Printf("Claims: %+v\n", claims)
}

func newJWT(privt []byte) (string, error) {
	vkey, err := jwt.ParseRSAPrivateKeyFromPEM(privt)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "hogehoge",
		"exp": time.Now().AddDate(1, 0, 0).Unix(),
	})
	tokenStr, err := token.SignedString(vkey)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func parseJWT(tokenStr string, publc []byte) (map[string]interface{}, error) {
	vkey, err := jwt.ParseRSAPublicKeyFromPEM(publc)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return vkey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, xerrors.New("parse claims error")
	}
	return claims, nil
}
