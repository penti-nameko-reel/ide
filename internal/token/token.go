package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"idp/internal/config"
	"idp/internal/db"
)
type Claims struct{ClientID string `json:"client_id"`;Scope string `json:"scope"`;Roles []string `json:"roles,omitempty"`;Groups []string `json:"groups,omitempty"`;jwt.RegisteredClaims}
type Service struct{cfg config.Config;store *db.Store;kid string}
func New(c config.Config,s *db.Store)*Service{return &Service{cfg:c,store:s,kid:"idp-rsa-1"}}
func(s *Service)makeToken(cl Claims)(string,error){t:=jwt.NewWithClaims(jwt.SigningMethodRS256,cl);t.Header["kid"]=s.kid;return t.SignedString(s.cfg.PrivateKey)}
func(s *Service)IDToken(uid,cid,scope,nonce string)(string,error){var email,username,name string;if e:=s.store.DB.QueryRow(`SELECT email,username,display_name FROM users WHERE id=? AND active=1`,uid).Scan(&email,&username,&name);e!=nil{return "",e};roles,groups:=s.attributes(uid);now:=time.Now();claims:=map[string]any{"iss":strings.TrimRight(s.cfg.BaseURL,"/"),"sub":uid,"aud":cid,"iat":now.Unix(),"exp":now.Add(time.Duration(s.cfg.TokenTTL)*time.Second).Unix()};if nonce!=""{claims["nonce"]=nonce};scopes:=strings.Fields(scope);if has(scopes,"email"){claims["email"]=email;claims["email_verified"]=true};if has(scopes,"profile"){claims["preferred_username"]=username;claims["name"]=name;claims["picture"]=strings.TrimRight(s.cfg.BaseURL,"/")+"/api/v1/users/"+username+"/avatar"};if has(scopes,"roles"){claims["roles"]=roles};if has(scopes,"groups"){claims["groups"]=groups};t:=jwt.NewWithClaims(jwt.SigningMethodRS256,jwt.MapClaims(claims));t.Header["kid"]=s.kid;signed,e:=t.SignedString(s.cfg.PrivateKey);return signed,e}
func(s *Service)AccessToken(uid,cid,scope string)(string,string,int64,error){now:=time.Now();jti:=random();c:=Claims{ClientID:cid,Scope:scope,RegisteredClaims:jwt.RegisteredClaims{Issuer:strings.TrimRight(s.cfg.BaseURL,"/"),Subject:uid,Audience:jwt.ClaimStrings{cid},IssuedAt:jwt.NewNumericDate(now),ExpiresAt:jwt.NewNumericDate(now.Add(time.Duration(s.cfg.TokenTTL)*time.Second)),ID:jti}};t,e:=s.makeToken(c);return t,jti,s.cfg.TokenTTL,e}
func(s *Service)ValidateAccess(raw string)(Claims,error){var c Claims;t,e:=jwt.ParseWithClaims(raw,&c,func(t *jwt.Token)(any,error){if t.Method.Alg()!=jwt.SigningMethodRS256.Alg(){return nil,errors.New("bad alg")};return &s.cfg.PrivateKey.PublicKey,nil},jwt.WithIssuer(strings.TrimRight(s.cfg.BaseURL,"/")),jwt.WithValidMethods([]string{"RS256"}));if e!=nil||!t.Valid{return c,errors.New("invalid token")};var revoked int;if e=s.store.DB.QueryRow(`SELECT revoked FROM access_tokens WHERE jti=? AND expires_at>?`,c.ID,time.Now()).Scan(&revoked);e!=nil||revoked!=0{return c,errors.New("inactive token")};return c,nil}
func(s *Service)Introspect(raw string)(bool,Claims){c,e:=s.ValidateAccess(raw);return e==nil,c}
func(s *Service)Revoke(raw string)error{c,e:=s.ValidateAccess(raw);if e!=nil{return nil};_,e=s.store.DB.Exec(`UPDATE access_tokens SET revoked=1 WHERE jti=?`,c.ID);return e}
func(s *Service)attributes(uid string)([]string,[]string){roles,groups:=[]string{},[]string{};r,e:=s.store.DB.Query(`SELECT role FROM user_roles WHERE user_id=? ORDER BY role`,uid);if e==nil{for r.Next(){var x string;if r.Scan(&x)==nil{roles=append(roles,x)}};_ = r.Close()};g,e:=s.store.DB.Query(`SELECT group_name FROM user_groups WHERE user_id=? ORDER BY group_name`,uid);if e==nil{for g.Next(){var x string;if g.Scan(&x)==nil{groups=append(groups,x)}};_ = g.Close()};return roles,groups}
func has(a []string,x string)bool{for _,v:=range a{if v==x{return true}};return false}
func(s *Service)JWKS()map[string]any{p:=s.cfg.PrivateKey.PublicKey;n:=base64.RawURLEncoding.EncodeToString(p.N.Bytes());e:=base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.E)).Bytes());return map[string]any{"keys":[]any{map[string]string{"kty":"RSA","use":"sig","alg":"RS256","kid":s.kid,"n":n,"e":e}}}}
func PKCE(v string)string{x:=sha256.Sum256([]byte(v));return base64.RawURLEncoding.EncodeToString(x[:])}
func random()string{b:=make([]byte,24);_,_=rand.Read(b);return base64.RawURLEncoding.EncodeToString(b)}
var _ *rsa.PrivateKey
