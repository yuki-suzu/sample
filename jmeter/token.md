```groovy
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

// トークン保管用のプロパティキー
def PROP_TOKEN = "GLOBAL_ACCESS_TOKEN"
def PROP_EXPIRES_AT = "GLOBAL_TOKEN_EXPIRES_AT"

long now = System.currentTimeMillis() / 1000
String currentToken = props.get(PROP_TOKEN)
String expiresAtStr = props.get(PROP_EXPIRES_AT)
long expiresAt = expiresAtStr ? expiresAtStr.toLong() : 0L

// トークンがまだ有効なら何もしない（メモリ上のプロパティを再利用）
if (currentToken != null && now < expiresAt) {
    log.info("既存のキャッシュトークンを使用します。")
    return
}

// ---- トークンが未取得または期限切れの場合、OAuth2 APIを呼び出す ----
log.info("アクセストークンを取得/更新します...")

def tokenUrl = "https://auth.example.com/oauth/token"
def postBody = "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"

def connection = new URL(tokenUrl).openConnection() as HttpURLConnection
connection.setRequestMethod("POST")
connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
connection.doOutput = true

connection.outputStream.withWriter("UTF-8") { writer ->
    writer.write(postBody)
}

if (connection.responseCode == 200) {
    def responseText = connection.inputStream.text
    def json = new JsonSlurper().parseText(responseText)
    
    String accessToken = json.access_token
    long expiresIn = json.expires_in as long // 秒単位
    
    // 5分余裕をもって有効期限を設定
    long newExpiresAt = now + expiresIn - 300
    
    // 全スレッドグループで共有できる JMeter props に保存
    props.put(PROP_TOKEN, accessToken)
    props.put(PROP_EXPIRES_AT, newExpiresAt.toString())
    
    log.info("新しいトークンを取得し、プロパティに保存しました。")
} else {
    log.error("トークン取得失敗: HTTP " + connection.responseCode)
    AssertionResult.setFailure(true)
    AssertionResult.setFailureMessage("OAuth2トークンの取得に失敗しました。")
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


