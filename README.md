# IDP

Go製の単体OIDC Providerです。SQLiteにユーザー、クライアント、セッション、アイコンを保存します。

## 起動

Go 1.22以降が必要です。

初回は依存パッケージを取得して `go.sum` を生成します。

```powershell
go mod tidy
```

その後、環境変数を設定して `go run ./cmd/idp` を実行します。

```sh
export IDP_BASE_URL=https://idp.example.com
export IDP_ADMIN_EMAIL=admin@example.com
export IDP_ADMIN_PASSWORD='十分に長い初期パスワード'
export IDP_SESSION_SECRET='ランダムな32文字以上の値'
export IDP_DATABASE_URL=sqlite:///data/idp.db
go run ./cmd/idp
```

`IDP_JWT_PRIVATE_KEY`を省略するとRSA鍵を起動ごとに生成します。本番では鍵を指定し、再起動後も同じ鍵を使ってください。CookieのSecure属性を有効にするため、HTTPS終端の背後で運用してください。

## 対応機能

- OIDC Discovery、JWKS、Authorization Code + PKCE (S256/plain)、UserInfo
- JWT RS256、Introspection、Revocation、Refresh Token rotation
- 初期管理者、Cookieセッション、パスワード変更
- ユーザー・ロール・グループ・PNG/JPEGアバター管理API
- OIDCクライアント管理API

初期管理者は初回起動時に作成されます。APIと簡易ログインページは同じサーバーで配信されます。
