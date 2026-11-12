package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
)

type Config struct { BaseURL, DatabaseURL, AdminEmail, AdminPassword, SessionSecret, ListenAddr string; PrivateKey *rsa.PrivateKey; TokenTTL, RefreshTTL int64 }

func Load() (Config,error) {
	c:=Config{BaseURL:os.Getenv("IDP_BASE_URL"), DatabaseURL:get("IDP_DATABASE_URL","sqlite:///data/idp.db"), AdminEmail:os.Getenv("IDP_ADMIN_EMAIL"), AdminPassword:os.Getenv("IDP_ADMIN_PASSWORD"), SessionSecret:os.Getenv("IDP_SESSION_SECRET"), ListenAddr:get("IDP_LISTEN_ADDR",":8080"), TokenTTL:3600,RefreshTTL:2592000}
	if c.BaseURL==""||c.AdminEmail==""||c.AdminPassword==""||c.SessionSecret=="" { return c,fmt.Errorf("IDP_BASE_URL, IDP_ADMIN_EMAIL, IDP_ADMIN_PASSWORD and IDP_SESSION_SECRET are required") }
	if v:=os.Getenv("IDP_TOKEN_TTL");v!="" { n,e:=strconv.ParseInt(v,10,64);if e!=nil||n<1{return c,fmt.Errorf("invalid IDP_TOKEN_TTL")};c.TokenTTL=n }
	if v:=os.Getenv("IDP_REFRESH_TTL");v!="" { n,e:=strconv.ParseInt(v,10,64);if e!=nil||n<1{return c,fmt.Errorf("invalid IDP_REFRESH_TTL")};c.RefreshTTL=n }
	if raw:=os.Getenv("IDP_JWT_PRIVATE_KEY");raw!="" { b,_:=pem.Decode([]byte(raw));if b==nil{return c,fmt.Errorf("invalid IDP_JWT_PRIVATE_KEY PEM")};k,e:=x509.ParsePKCS1PrivateKey(b.Bytes);if e!=nil { if pk,pe:=x509.ParsePKCS8PrivateKey(b.Bytes);pe==nil { var ok bool;k,ok=pk.(*rsa.PrivateKey);if !ok{return c,fmt.Errorf("JWT key must be RSA")}}else{return c,e} };c.PrivateKey=k } else { k,e:=rsa.GenerateKey(rand.Reader,2048);if e!=nil{return c,e};c.PrivateKey=k }
	return c,nil
}
func get(k,d string)string{if v:=os.Getenv(k);v!=""{return v};return d}
