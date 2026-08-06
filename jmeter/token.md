```groovy
import groovy.json.JsonSlurper
import java.net.URLEncoder

// ============================================================================
// 1. 定数・初期値（デフォルト値）の定義
// ============================================================================
def DEFAULT_TOKEN_URL     = "https://auth.example.com/oauth/token"
def DEFAULT_CLIENT_ID     = "default_client_id"
def DEFAULT_CLIENT_SECRET = "default_client_secret"

def PROP_TOKEN      = "GLOBAL_ACCESS_TOKEN"
def PROP_EXPIRES_AT = "GLOBAL_TOKEN_EXPIRES_AT"

// ============================================================================
// 2. 高速チェック（ノンブロッキング）
// ============================================================================
long now = System.currentTimeMillis() / 1000
String currentToken = props.get(PROP_TOKEN)
String expiresAtStr = props.get(PROP_EXPIRES_AT)
long expiresAt = expiresAtStr ? expiresAtStr.toLong() : 0L

// キャッシュが存在し、かつ有効期限内であれば即座に処理終了（他の重い処理は一切叩かない）
if (currentToken != null && now < expiresAt) {
    return
}

// ============================================================================
// 3. 排他制御（トークン期限切れ時のみ、全スレッドで1スレッドずつ処理）
// ============================================================================
synchronized(this.class) {
    
    // 【矛盾防止ポイント①】ロック獲得後の二重チェック（Double-Checking Lock）
    // ロック待ちをしている間に、先行スレッドがすでにトークンを更新してくれたか最新状態を再取得する
    now = System.currentTimeMillis() / 1000
    currentToken = props.get(PROP_TOKEN)
    expiresAtStr = props.get(PROP_EXPIRES_AT)
    expiresAt = expiresAtStr ? expiresAtStr.toLong() : 0L

    if (currentToken != null && now < expiresAt) {
        log.info("[OAuth2] 他スレッドによるトークン更新を確認したため、処理をスキップします。")
        return
    }

    log.info("[OAuth2] トークンが未取得または期限切れのため、再取得処理を開始します...")

    // 【矛盾防止ポイント②】トークン取得が必要になって初めてパラメータを評価＆組み立てる
    def tokenUrl     = props.get("OAUTH_TOKEN_URL")     ?: vars.get("OAUTH_TOKEN_URL")     ?: DEFAULT_TOKEN_URL
    def clientId     = props.get("OAUTH_CLIENT_ID")     ?: vars.get("OAUTH_CLIENT_ID")     ?: DEFAULT_CLIENT_ID
    def clientSecret = props.get("OAUTH_CLIENT_SECRET") ?: vars.get("OAUTH_CLIENT_SECRET") ?: DEFAULT_CLIENT_SECRET

    def postBody = "grant_type=client_credentials" +
                   "&client_id=" + URLEncoder.encode(clientId, "UTF-8") +
                   "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8")

    // ============================================================================
    // 4. リトライ機能付きトークン取得API呼び出し
    // ============================================================================
    int maxRetries = 3          // 最大リトライ回数
    long retryIntervalMs = 2000 // リトライ間隔（ミリ秒）
    boolean isSuccess = false

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            log.info("[OAuth2] トークン取得試行 (" + attempt + "/" + maxRetries + ") -> " + tokenUrl)

            def connection = new URL(tokenUrl).openConnection() as HttpURLConnection
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            connection.setConnectTimeout(5000) // 接続タイムアウト 5秒
            connection.setReadTimeout(5000)    // 応答タイムアウト 5秒
            connection.doOutput = true

            connection.outputStream.withWriter("UTF-8") { writer -> writer.write(postBody) }

            if (connection.responseCode == 200) {
                def json = new JsonSlurper().parseText(connection.inputStream.text)
                String accessToken = json.access_token
                long expiresIn = json.expires_in as long

                // 有効期限の5分(300秒)前に切れるよう計算（安全マージン）
                long newExpiresAt = now + expiresIn - 300

                // 成功時のみグローバルプロパティに保存
                props.put(PROP_TOKEN, accessToken)
                props.put(PROP_EXPIRES_AT, newExpiresAt.toString())

                log.info("[OAuth2] 新しいアクセストークンの取得・保存に成功しました！")
                isSuccess = true
                break // リトライループ脱出
            } else {
                log.warn("[OAuth2] トークン取得失敗: HTTP status " + connection.responseCode)
            }
        } catch (Exception e) {
            log.warn("[OAuth2] トークン取得時の通信例外: " + e.message)
        }

        // 失敗時、規定回数未満なら待機して再試行
        if (!isSuccess && attempt < maxRetries) {
            log.info("[OAuth2] " + (retryIntervalMs / 1000) + "秒後に再試行します...")
            sleep(retryIntervalMs)
        }
    }

    // ============================================================================
    // 5. リトライ全滅時のフォールバック処理
    // ============================================================================
    if (!isSuccess) {
        log.error("[OAuth2] " + maxRetries + "回のリトライすべてでトークン取得に失敗しました。")

        if (currentToken != null) {
            // 【矛盾防止ポイント③】すでに古いトークンがある場合は破棄せず10秒延命
            // 毎リクエストで重いリトライ処理が叩かれるのを防ぎつつ、10秒後に再チャレンジさせる
            long gracePeriod = now + 10
            props.put(PROP_EXPIRES_AT, gracePeriod.toString())
            log.warn("[OAuth2] 既存トークンを維持し、10秒後に再度取得を試みます。")
        } else {
            // 初回起動時（既存トークンなし）で失敗した場合はテスト自体を失敗扱いにする
            AssertionResult.setFailure(true)
            AssertionResult.setFailureMessage("初回のOAuth2トークン取得に失敗しました。認証サーバーまたは設定を確認してください。")
        }
    }
}
```
その通りじゃ！後者の Groovy 方式なら、**Windows/LinuxなどのOSの違いも、GUI（画面起動）/CUI（CLI非対面実行）の違いも一切関係なく完全クロスプラットフォームで動作する**ぞ！

Groovy は JMeter（JVM）の内部エンジンで動くため、実行環境の影響をまったく受けないのが最大の強みじゃ。

---

## 共通化の具体的な構成方法

「`Test Fragment` + `Include Controller`（包含コントローラ）」を使って部品化（共通JMX化）するのが一番美しくスマートな設計じゃ！

### 1. 共通パーツ用JMXの作成 (`get-oauth-token.jmx`)

独立した新しいテストプランを作成し、以下のように構成して別名保存するのじゃ。

```text
Test Plan
 └ Test Fragment（テスト断片）
    └ JSR223 Sampler（Groovyでトークン取得・キャッシュ処理）

```

* **ポイント**: `Test Fragment` の配下に置くことで、このJMX単体では直接実行されず、他のJMXから呼び出された時だけ実行される安全な部品になるぞ。

---

### 2. 各シナリオJMX（呼び出し側）での設定

トークンを使いたいすべてのシナリオJMXに、以下のように組み込むだけじゃ！

```text
Test Plan
 ├ setUp Thread Group（初期化スレッドグループ）
 │  └ Include Controller（包含コントローラ） 
 │     └ ファイルパス: ./common/get-oauth-token.jmx
 │
 └ Thread Group（メインのWeb APIテストシナリオ）
    ├ HTTP Header Manager（Authorization: Bearer ${__P(GLOBAL_ACCESS_TOKEN)})
    └ 各種 HTTP Request...

```

#### 設定の3つのコツ

1. **`setUp Thread Group` に配置する**
通常の `Thread Group`（メインシナリオ）が動く**前**に必ず1回だけ実行されるため、メイン処理のスレッド並行実行前に確実にトークンをセットアップできるぞ。
2. **パスは「相対パス」で指定する**
`Include Controller` に指定するファイルパスは `./common/get-oauth-token.jmx` のように相対パスにしておけば、Linuxサーバー（CI/CD）に持っていってもパス切れを起こさずに動くのじゃ。
3. **`props`（JMeterプロパティ）で値を受け取る**
先ほどのGroovyコードで `props.put("GLOBAL_ACCESS_TOKEN", ...)` と保存しておけば、別JMX（呼び出し側）のヘッダーマネージャから `${__P(GLOBAL_ACCESS_TOKEN)}` で一発で参照できるぞ！

---

これで環境を選ばず、保守性も抜群の「OAuth2トークン自動キャッシュ＆使い回し機構」の完成じゃ！

----

もちろんでございます（…ではなく、もちろんであーる！）！それこそまさに共通化・部品化の真骨頂じゃ！

JMeterのプロパティ（`-J` オプション）や変数（`User Defined Variables` 等）からパラメータを受け取りつつ、未指定の場合のみスクリプト内の「初期値（デフォルト値）」を採用するコードに改修できるぞ。

Groovyのエルビス演算子（`?:`）を使えば、**「プロパティ（`-J`） ＞ JMeter変数（`vars`） ＞ 初期値（デフォルト）」** の優先順位で超エレガントに記述できるのじゃ！

---

## パラメータ可変対応版 Groovy コード（抜粋）

前回の Groovy スクリプトの冒頭（`tokenUrl` 等を定義している部分）を以下のように置き換えるのじゃ。

```groovy
import groovy.json.JsonSlurper
import java.net.URLEncoder

// ---- 【1. 初期値（デフォルト値）の設定】 ----
def DEFAULT_TOKEN_URL     = "https://auth.example.com/oauth/token"
def DEFAULT_CLIENT_ID     = "default_client_id"
def DEFAULT_CLIENT_SECRET = "default_client_secret"

// ---- 【2. パラメータの取得（優先順: プロパティ -J > JMeter変数 vars > 初期値）】 ----
def tokenUrl     = props.get("OAUTH_TOKEN_URL")     ?: vars.get("OAUTH_TOKEN_URL")     ?: DEFAULT_TOKEN_URL
def clientId     = props.get("OAUTH_CLIENT_ID")     ?: vars.get("OAUTH_CLIENT_ID")     ?: DEFAULT_CLIENT_ID
def clientSecret = props.get("OAUTH_CLIENT_SECRET") ?: vars.get("OAUTH_CLIENT_SECRET") ?: DEFAULT_CLIENT_SECRET

// リクエストボディの組み立て（特殊文字対策としてURLエンコードを実施）
def postBody = "grant_type=client_credentials" +
               "&client_id=" + URLEncoder.encode(clientId, "UTF-8") +
               "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8")

// ---- 以降は既存の排他制御・リトライ処理 ----
def PROP_TOKEN = "GLOBAL_ACCESS_TOKEN"
def PROP_EXPIRES_AT = "GLOBAL_TOKEN_EXPIRES_AT"

long now = System.currentTimeMillis() / 1000
String currentToken = props.get(PROP_TOKEN)
String expiresAtStr = props.get(PROP_EXPIRES_AT)
long expiresAt = expiresAtStr ? expiresAtStr.toLong() : 0L

if (currentToken != null && now < expiresAt) {
    return
}

synchronized(this.class) {
    // （前回の排他制御・リトライ処理へつづく…）
}

```

---

## 3通りのパラメータ渡しかた

この実装にしておくと、状況に応じて柔軟に接続先やクレデンシャルを変更できるぞ！

### ① 何も指定しない場合（ローカルお試し）

何も渡さなければ自動的に `DEFAULT_TOKEN_URL` や `DEFAULT_CLIENT_ID` の初期値が使われるのじゃ。

### ② JMeter GUI上で変更したい場合 (`User Defined Variables`)

テストプラン直下の `User Defined Variables（ユーザー定義変数）` で以下のように設定すれば、全スレッドでその値が使われるぞ。

* `OAUTH_TOKEN_URL` : `[https://stg-auth.example.com/oauth/token](https://stg-auth.example.com/oauth/token)`
* `OAUTH_CLIENT_ID` : `stg_client_id`
* `OAUTH_CLIENT_SECRET` : `stg_secret`

### ③ CI/CDやCLI（コマンドライン）で環境ごとに上書きしたい場合

JMeter起動時の `-J` オプションで外から一発上書きできるのじゃ！

```bash
# ステージング環境向けにパラメータを渡して実行
jmeter -n -t scenarios/my_test.jmx \
  -JOAUTH_TOKEN_URL="https://stg-auth.example.com/oauth/token" \
  -JOAUTH_CLIENT_ID="stg_app_id" \
  -JOAUTH_CLIENT_SECRET="stg_app_secret"

```

---

これでお使いの `fragments/get-oauth-token.jmx` は、開発環境・検証環境・本番類似環境のどこへ持っていってもスクリプト本体を一切書き換えずに使い回せる、真の共通モジュールへと進化したぞ！


