package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }
func Open(raw string)(*Store,error){ dsn:=raw;if strings.HasPrefix(raw,"sqlite:///"){path:=strings.TrimPrefix(raw,"sqlite://");if path=="/data/idp.db" { _=os.MkdirAll("/data",0700) } else if !strings.HasPrefix(path,"file:"){_ = os.MkdirAll(filepath.Dir(path),0700)};dsn=path } else if strings.HasPrefix(raw,"postgres://"){return nil,fmt.Errorf("PostgreSQL support is not enabled in this build; use SQLite")};if _,e:=url.Parse(dsn);e!=nil{return nil,e};d,e:=sql.Open("sqlite",dsn);if e!=nil{return nil,e};d.SetMaxOpenConns(1);s:=&Store{d};if e=s.migrate();e!=nil{d.Close();return nil,e};return s,nil }
func(s *Store)Close()error{return s.DB.Close()}
func(s *Store)migrate()error{_,e:=s.DB.Exec(`PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,display_name TEXT NOT NULL DEFAULT '',avatar BLOB,avatar_type TEXT,active INTEGER NOT NULL DEFAULT 1,created_at DATETIME NOT NULL,updated_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS user_roles(user_id TEXT NOT NULL REFERENCES users(id),role TEXT NOT NULL,PRIMARY KEY(user_id,role));
CREATE TABLE IF NOT EXISTS user_groups(user_id TEXT NOT NULL REFERENCES users(id),group_name TEXT NOT NULL,PRIMARY KEY(user_id,group_name));
CREATE TABLE IF NOT EXISTS oidc_clients(id TEXT PRIMARY KEY,secret_hash TEXT NOT NULL,name TEXT NOT NULL,redirect_uris TEXT NOT NULL,allowed_scopes TEXT NOT NULL,grant_types TEXT NOT NULL,created_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),client_id TEXT NOT NULL REFERENCES oidc_clients(id),scope TEXT NOT NULL,code_challenge TEXT,code_challenge_method TEXT,nonce TEXT,redirect_uri TEXT,expires_at DATETIME NOT NULL,created_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS refresh_tokens(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),client_id TEXT NOT NULL,scope TEXT NOT NULL,expires_at DATETIME NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,created_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS access_tokens(jti TEXT PRIMARY KEY,user_id TEXT NOT NULL,client_id TEXT NOT NULL,expires_at DATETIME NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS web_sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at DATETIME NOT NULL);`);return e}
func(s *Store)EnsureAdmin(email,password string)error{var n int;if e:=s.DB.QueryRow(`SELECT count(*) FROM users WHERE email=?`,email).Scan(&n);e!=nil{return e};if n>0{return nil};h,e:=bcrypt.GenerateFromPassword([]byte(password),12);if e!=nil{return e};base:=usernameFromEmail(email);candidate:=base;for i:=1;;i++{var count int;if e=s.DB.QueryRow(`SELECT count(*) FROM users WHERE username=?`,candidate).Scan(&count);e!=nil{return e};if count==0{break};candidate=fmt.Sprintf("%s%d",base,i)};id:=uuid.NewString();now:=time.Now().UTC();tx,e:=s.DB.Begin();if e!=nil{return e};defer tx.Rollback();_,e=tx.Exec(`INSERT INTO users(id,username,email,password,display_name,active,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)`,id,candidate,email,string(h),"Administrator",now,now);if e!=nil{return e};_,e=tx.Exec(`INSERT INTO user_roles(user_id,role) VALUES(?, 'admin'), (?, 'user')`,id,id);if e!=nil{return e};return tx.Commit()}
func usernameFromEmail(e string)string{v:=strings.SplitN(e,"@",2)[0];v=strings.ToLower(v);var b strings.Builder;for _,r:=range v{if r>='a'&&r<='z'||r>='0'&&r<='9'{b.WriteRune(r)}};if b.Len()==0{return "admin"};return b.String()}
