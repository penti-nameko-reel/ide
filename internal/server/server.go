package server

import (
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	idpassets "idp"
	"idp/internal/config"
	"idp/internal/db"
	"idp/internal/oidc"
	"idp/internal/token"
)

type Server struct{ cfg config.Config; store *db.Store; oidc *oidc.Service; tokens *token.Service; mux *http.ServeMux }
func New(c config.Config, s *db.Store)(*Server,error){ t:=token.New(c,s); o:=oidc.New(c,s,t);v:=&Server{cfg:c,store:s,oidc:o,tokens:t,mux:http.NewServeMux()};v.routes();return v,nil }
func(v *Server)Handler()http.Handler{return securityHeaders(v.mux)}
func(v *Server)routes(){m:=v.mux
	m.HandleFunc("GET /.well-known/openid-configuration",v.discovery);m.HandleFunc("GET /.well-known/jwks.json",v.jwks)
	m.HandleFunc("GET /oidc/authorize",v.authorize);m.HandleFunc("POST /oidc/token",v.token);m.HandleFunc("GET /oidc/userinfo",v.userinfo);m.HandleFunc("POST /oidc/introspect",v.introspect);m.HandleFunc("POST /oidc/revoke",v.revoke);m.HandleFunc("GET /oidc/end-session",v.endSession)
	m.HandleFunc("POST /api/v1/auth/login",v.login);m.HandleFunc("POST /api/v1/auth/logout",v.logout);m.HandleFunc("POST /api/v1/auth/change-password",v.changePassword);m.HandleFunc("GET /api/v1/auth/me",v.me)
	m.HandleFunc("GET /login",v.loginPage);m.HandleFunc("GET /admin",v.adminPage)
	m.HandleFunc("/api/v1/users",v.users);m.HandleFunc("/api/v1/users/",v.user);m.HandleFunc("/api/v1/clients",v.clients);m.HandleFunc("/api/v1/clients/",v.client)
	m.HandleFunc("/",v.adminUI)
}
func securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("X-Frame-Options","DENY");next.ServeHTTP(w,r)})}
func(v *Server)discovery(w http.ResponseWriter,r *http.Request){base:=strings.TrimRight(v.cfg.BaseURL,"/");writeJSON(w,200,map[string]any{"issuer":base,"authorization_endpoint":base+"/oidc/authorize","token_endpoint":base+"/oidc/token","userinfo_endpoint":base+"/oidc/userinfo","jwks_uri":base+"/.well-known/jwks.json","introspection_endpoint":base+"/oidc/introspect","revocation_endpoint":base+"/oidc/revoke","end_session_endpoint":base+"/oidc/end-session","response_types_supported":[]string{"code"},"subject_types_supported":[]string{"public"},"id_token_signing_alg_values_supported":[]string{"RS256"},"scopes_supported":[]string{"openid","profile","email","roles","groups"},"token_endpoint_auth_methods_supported":[]string{"client_secret_basic","client_secret_post"},"code_challenge_methods_supported":[]string{"S256","plain"},"grant_types_supported":[]string{"authorization_code","refresh_token"}})}
func(v *Server)jwks(w http.ResponseWriter,r *http.Request){writeJSON(w,200,v.tokens.JWKS())}
func(v *Server)authorize(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{method(w);return};q:=r.URL.Query();client,err:=v.oidc.Client(q.Get("client_id"));if err!=nil{http.Error(w,"invalid client",400);return};redir:=q.Get("redirect_uri");if !contains(client.RedirectURIs,redir){http.Error(w,"invalid redirect_uri",400);return};if q.Get("response_type")!="code"{http.Error(w,"unsupported response_type",400);return};scopes:=strings.Fields(q.Get("scope"));if !contains(scopes,"openid"){http.Error(w,"openid scope required",400);return};for _,s:=range scopes{if !contains(client.AllowedScopes,s){http.Error(w,"invalid scope",400);return}};challenge,methodName:=q.Get("code_challenge"),q.Get("code_challenge_method");if challenge!=""&&methodName!="S256"&&methodName!="plain"{http.Error(w,"invalid PKCE method",400);return};if challenge==""&&contains(client.GrantTypes,"authorization_code")==false{http.Error(w,"PKCE required",400);return}
	uid,ok:=v.sessionUser(r);if !ok{http.Redirect(w,r,"/login?return_to="+url.QueryEscape(r.URL.RequestURI()),http.StatusFound);return};code,err:=v.oidc.CreateCode(uid,client.ID,redir,strings.Join(scopes," "),challenge,methodName,q.Get("nonce"));if err!=nil{http.Error(w,"authorization failed",500);return};dest,_:=url.Parse(redir);params:=dest.Query();params.Set("code",code);if state:=q.Get("state");state!=""{params.Set("state",state)};dest.RawQuery=params.Encode();http.Redirect(w,r,dest.String(),http.StatusFound)}
func(v *Server)token(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{method(w);return};if err:=r.ParseForm();err!=nil{oauthError(w,"invalid_request");return};id,secret,ok:=r.BasicAuth();if !ok{id=r.Form.Get("client_id");secret=r.Form.Get("client_secret")};c,err:=v.oidc.AuthenticateClient(id,secret);if err!=nil{oauthError(w,"invalid_client");return};switch r.Form.Get("grant_type"){case "authorization_code":out,e:=v.oidc.ExchangeCode(c,r.Form.Get("code"),r.Form.Get("redirect_uri"),r.Form.Get("code_verifier"));if e!=nil{oauthError(w,"invalid_grant");return};writeJSON(w,200,out);case "refresh_token":out,e:=v.oidc.Refresh(c,r.Form.Get("refresh_token"));if e!=nil{oauthError(w,"invalid_grant");return};writeJSON(w,200,out);default:oauthError(w,"unsupported_grant_type")}}
func(v *Server)userinfo(w http.ResponseWriter,r *http.Request){raw:=bearer(r);claims,err:=v.tokens.ValidateAccess(raw);if err!=nil{oauthError(w,"invalid_token");return};u,e:=v.oidc.UserInfo(claims.Subject);if e!=nil{oauthError(w,"invalid_token");return};writeJSON(w,200,u)}
func(v *Server)introspect(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{method(w);return};_ = r.ParseForm();id,secret,ok:=r.BasicAuth();if !ok{id=r.Form.Get("client_id");secret=r.Form.Get("client_secret")};if _,e:=v.oidc.AuthenticateClient(id,secret);e!=nil{http.Error(w,"unauthorized",401);return};active,claims:=v.tokens.Introspect(r.Form.Get("token"));resp:=map[string]any{"active":active};if active{resp["sub"]=claims.Subject;resp["iss"]=claims.Issuer;resp["aud"]=claims.Audience;resp["exp"]=claims.ExpiresAt.Unix();resp["iat"]=claims.IssuedAt.Unix();resp["client_id"]=claims.ClientID;resp["scope"]=claims.Scope};writeJSON(w,200,resp)}
func(v *Server)revoke(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{method(w);return};_ = r.ParseForm();id,secret,ok:=r.BasicAuth();if !ok{id=r.Form.Get("client_id");secret=r.Form.Get("client_secret")};if _,e:=v.oidc.AuthenticateClient(id,secret);e!=nil{http.Error(w,"unauthorized",401);return};_ = v.tokens.Revoke(r.Form.Get("token"));w.WriteHeader(200)}
func(v *Server)endSession(w http.ResponseWriter,r *http.Request){if c,e:=r.Cookie("idp_session");e==nil{_,_=v.store.DB.Exec(`DELETE FROM web_sessions WHERE id=?`,c.Value)};http.SetCookie(w,&http.Cookie{Name:"idp_session",Value:"",Path:"/",MaxAge:-1,HttpOnly:true,Secure:true,SameSite:http.SameSiteLaxMode});dest:=r.URL.Query().Get("post_logout_redirect_uri");if dest!=""{http.Redirect(w,r,dest,302);return};w.WriteHeader(204)}
func(v *Server)login(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{method(w);return};var in struct{Login string `json:"login"`;Email string `json:"email"`;Password string `json:"password"`};if !readJSON(w,r,&in){return};if in.Login==""{in.Login=in.Email};uid,e:=v.oidc.Login(in.Login,in.Password);if e!=nil{http.Error(w,"invalid credentials",401);return};sid:=v.signSession(randomID(32));exp:=time.Now().Add(12*time.Hour);if _,e=v.store.DB.Exec(`INSERT INTO web_sessions(id,user_id,expires_at) VALUES(?,?,?)`,sid,uid,exp);e!=nil{http.Error(w,"server error",500);return};http.SetCookie(w,&http.Cookie{Name:"idp_session",Value:sid,Path:"/",Expires:exp,HttpOnly:true,Secure:true,SameSite:http.SameSiteLaxMode});writeJSON(w,200,map[string]string{"status":"ok"})}
func(v *Server)logout(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{method(w);return};if c,e:=r.Cookie("idp_session");e==nil&&v.validSession(c.Value){_,_=v.store.DB.Exec(`DELETE FROM web_sessions WHERE id=?`,c.Value)};http.SetCookie(w,&http.Cookie{Name:"idp_session",Value:"",Path:"/",MaxAge:-1,HttpOnly:true,Secure:true,SameSite:http.SameSiteLaxMode});writeJSON(w,200,map[string]string{"status":"ok"})}
func(v *Server)changePassword(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{method(w);return};uid,ok:=v.sessionUser(r);if !ok{http.Error(w,"unauthorized",401);return};var in struct{CurrentPassword string `json:"current_password"`;NewPassword string `json:"new_password"`};if !readJSON(w,r,&in){return};if len(in.NewPassword)<12{http.Error(w,"new password must be at least 12 characters",400);return};if e:=v.oidc.ChangePassword(uid,in.CurrentPassword,in.NewPassword);e!=nil{http.Error(w,"invalid current password",400);return};writeJSON(w,200,map[string]string{"status":"ok"})}
func(v *Server)me(w http.ResponseWriter,r *http.Request){uid,ok:=v.sessionUser(r);if !ok{http.Error(w,"unauthorized",401);return};info,e:=v.oidc.UserInfo(uid);if e!=nil{http.Error(w,"user not found",404);return};writeJSON(w,200,info)}
func(v *Server)sessionUser(r *http.Request)(string,bool){c,e:=r.Cookie("idp_session");if e!=nil||!v.validSession(c.Value){return "",false};var id string;e=v.store.DB.QueryRow(`SELECT user_id FROM web_sessions WHERE id=? AND expires_at>?`,c.Value,time.Now().UTC()).Scan(&id);return id,e==nil}
func(v *Server)isAdmin(uid string)bool{var n int;_ = v.store.DB.QueryRow(`SELECT count(*) FROM user_roles WHERE user_id=? AND role='admin'`,uid).Scan(&n);return n>0}
func(v *Server)adminUI(w http.ResponseWriter,r *http.Request){if r.URL.Path!="/"{http.NotFound(w,r);return};if r.Method!="GET"{method(w);return};v.servePage(w,"web/index.html")}
func(v *Server)servePage(w http.ResponseWriter,name string){b,e:=idpassets.WebFS.ReadFile(name);if e!=nil{http.Error(w,"page unavailable",500);return};w.Header().Set("Content-Type","text/html; charset=utf-8");_,_=w.Write(b)}
func(v *Server)loginPage(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{method(w);return};next:=r.URL.Query().Get("return_to");if !safeLocalPath(next){next="/"};w.Header().Set("Cache-Control","no-store");w.Header().Set("X-Login-Next",next);v.servePage(w,"web/login.html")}
func(v *Server)adminPage(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{method(w);return};uid,ok:=v.sessionUser(r);if !ok{http.Redirect(w,r,"/login?return_to=%2Fadmin",http.StatusFound);return};if !v.isAdmin(uid){http.Error(w,"admin role required",http.StatusForbidden);return};w.Header().Set("Cache-Control","no-store");v.servePage(w,"web/admin.html")}
func safeLocalPath(s string)bool{return strings.HasPrefix(s,"/")&&!strings.HasPrefix(s,"//")&&!strings.Contains(s,"\\")}
func bearer(r *http.Request)string{s:=r.Header.Get("Authorization");if strings.HasPrefix(s,"Bearer "){return strings.TrimPrefix(s,"Bearer ")};return r.URL.Query().Get("access_token")}
func randomID(n int)string{b:=make([]byte,n);if _,e:=rand.Read(b);e!=nil{return ""};return base64.RawURLEncoding.EncodeToString(b)}
func(v *Server)signSession(raw string)string{m:=hmac.New(sha256.New,[]byte(v.cfg.SessionSecret));_,_=m.Write([]byte(raw));return raw+"."+base64.RawURLEncoding.EncodeToString(m.Sum(nil))}
func(v *Server)validSession(s string)bool{parts:=strings.Split(s,".");if len(parts)!=2{return false};m:=hmac.New(sha256.New,[]byte(v.cfg.SessionSecret));_,_=m.Write([]byte(parts[0]));expected:=base64.RawURLEncoding.EncodeToString(m.Sum(nil));return hmac.Equal([]byte(expected),[]byte(parts[1]))}
func writeJSON(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ = json.NewEncoder(w).Encode(v)}
func readJSON(w http.ResponseWriter,r *http.Request,v any)bool{r.Body=http.MaxBytesReader(w,r.Body,1<<20);d:=json.NewDecoder(r.Body);d.DisallowUnknownFields();if e:=d.Decode(v);e!=nil{http.Error(w,"invalid JSON",400);return false};return true}
func method(w http.ResponseWriter){http.Error(w,"method not allowed",405)}
func oauthError(w http.ResponseWriter,e string){writeJSON(w,400,map[string]string{"error":e})}
func contains(ss []string,v string)bool{for _,x:=range ss{if x==v{return true}};return false}
func parseJSONList(s string)[]string{var a []string;_ = json.Unmarshal([]byte(s),&a);return a}
func stringJSON(v any)string{b,_:=json.Marshal(v);return string(b)}
func decodeBody(r *http.Request)([]byte,error){return io.ReadAll(io.LimitReader(r.Body,1<<20))}
func ensureURL(s string)bool{u,e:=url.Parse(s);return e==nil&&u.IsAbs()&&u.Host!=""}
var _=parseJSONList
var _=stringJSON
var _=decodeBody
var _=ensureURL
