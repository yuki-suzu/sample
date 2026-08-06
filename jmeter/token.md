```groovy
import groovy.json.JsonSlurper

def PROP_TOKEN = "GLOBAL_ACCESS_TOKEN"
def PROP_EXPIRES_AT = "GLOBAL_TOKEN_EXPIRES_AT"

long now = System.currentTimeMillis() / 1000
String currentToken = props.get(PROP_TOKEN)
String expiresAtStr = props.get(PROP_EXPIRES_AT)
long expiresAt = expiresAtStr ? expiresAtStr.toLong() : 0L

// 1. 高速チェック（トークンがまだ有効なら即スキップ）
if (currentToken != null && now < expiresAt) {
    return
}

// 2. 排他制御（複数スレッドが一斉にトークン取得するのを防ぐ）
synchronized(this.class) {
    // ダブルチェック（他スレッドが更新完了していないか確認）
    now = System.currentTimeMillis() / 1000
    currentToken = props.get(PROP_TOKEN)
    expiresAtStr = props.get(PROP_EXPIRES_AT)
    expiresAt = expiresAtStr ? expiresAtStr.toLong() : 0L

    if (currentToken != null && now < expiresAt) {
        return
    }

    log.info("[ヒートラン] トークン更新処理を開始します...")

    def tokenUrl = "https://auth.example.com/oauth/token"
    def postBody = "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"

    int maxRetries = 3          // 最大リトライ回数
    long retryIntervalMs = 2000 // リトライ間隔（2秒）
    boolean isSuccess = false

    // ---- 【対策1】リトライループ ----
    for (int attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            log.info("[ヒートラン] トークン取得試行 (" + attempt + "/" + maxRetries + ")...")

            def connection = new URL(tokenUrl).openConnection() as HttpURLConnection
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            connection.setConnectTimeout(5000) // タイムアウト5秒
            connection.setReadTimeout(5000)
            connection.doOutput = true

            connection.outputStream.withWriter("UTF-8") { writer -> writer.write(postBody) }

            if (connection.responseCode == 200) {
                def json = new JsonSlurper().parseText(connection.inputStream.text)
                String accessToken = json.access_token
                long expiresIn = json.expires_in as long

                // 5分(300秒)前に切れるよう期限を計算
                long newExpiresAt = now + expiresIn - 300

                // 成功した時のみ、プロパティ（メモリ）を上書き更新
                props.put(PROP_TOKEN, accessToken)
                props.put(PROP_EXPIRES_AT, newExpiresAt.toString())

                log.info("[ヒートラン] トークンの取得・更新に成功しました！")
                isSuccess = true
                break // 成功したのでループ脱出
            } else {
                log.warn("[ヒートラン] トークン取得失敗: HTTP " + connection.responseCode)
            }
        } catch (Exception e) {
            log.warn("[ヒートラン] トークン取得時の通信例外: " + e.message)
        }

        // 失敗時、規定回数に達していなければ待機して再試行
        if (!isSuccess && attempt < maxRetries) {
            log.info("[ヒートラン] " + (retryIntervalMs / 1000) + "秒後に再試行します...")
            sleep(retryIntervalMs)
        }
    }

    // ---- 【対策2】全試行失敗時のフォールバック処理 ----
    if (!isSuccess) {
        log.error("[ヒートラン] " + maxRetries + "回のリトライすべてでトークン取得に失敗しました。")

        if (currentToken != null) {
            // 古いトークンが存在する場合、消さずに残す！
            // ただし、毎リクエストで即座にAPI取得へ突入するのを防ぐため、有効期限を「10秒後」に一時延命して次回ループで再挑戦させる
            long gracePeriod = now + 10
            props.put(PROP_EXPIRES_AT, gracePeriod.toString())
            log.warn("[ヒートラン] 既存のトークンを維持し、10秒後に再度トークン取得を試みます。")
        } else {
            // 初回起動時でトークンが一度も取れていない場合はテストをエラーにする
            AssertionResult.setFailure(true)
            AssertionResult.setFailureMessage("初回のOAuth2トークン取得に失敗しました。")
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


