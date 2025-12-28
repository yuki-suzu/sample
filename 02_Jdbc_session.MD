はい、その通りです。`spring.session.jdbc.cleanup-cron` は `application.yml` で設定します。

PostgreSQL を使った JDBC Session の場合、デフォルト設定のままだと**本番運用でパフォーマンス問題（DB負荷）を引き起こす可能性**があります。

特に気にしておくべき設定と、PostgreSQLならではの考慮ポイントをまとめました。

---

### 1. クリーンアップ設定 (パフォーマンスへの影響大)

デフォルトでは「1分に1回」期限切れセッションの削除処理（DELETE文）が走ります。セッション数が多いシステムでは、これがDBの負荷になります。

* **`spring.session.jdbc.cleanup-cron`**
* **デフォルト:** `0 * * * * *` (毎分0秒に実行)
* **推奨設定:** アクセスが多い場合、頻度を下げる（例: 深夜に1回、または1時間に1回）か、アプリ側では無効化してDB側のバッチに任せる。
* **無効化する方法:** 値に `-` を設定します。



```yaml
spring:
  session:
    jdbc:
      # 毎時0分に実行する場合の例
      cleanup-cron: "0 0 * * * *"
      # アプリ側での削除を無効化する場合（DBのpg_cronなどでやる場合）
      # cleanup-cron: "-"

```

### 2. スキーマ初期化設定 (本番事故防止)

開発中は自動作成が便利ですが、本番環境でアプリ起動時に勝手に `DROP` や `CREATE` が走ると危険です。

* **`spring.session.jdbc.initialize-schema`**
* **`always`**: 起動時にスクリプトを実行（開発時はこれでOK）。
* **`never`**: **本番環境推奨**。アプリはテーブル作成を行わない（DBAやマイグレーションツールで管理）。
* **`embedded`**: 組み込みDB（H2など）の場合のみ作成（デフォルト）。



```yaml
spring:
  session:
    jdbc:
      # 本番環境では never にして、DDLは別途Flyway等で管理する
      initialize-schema: never

```

### 3. テーブル名の変更 (既存システムとの共存)

デフォルトのテーブル名は `SPRING_SESSION` ですが、同じDB内に複数のSpringアプリが同居する場合や、命名規約がある場合は変更します。

* **`spring.session.jdbc.table-name`**

```yaml
spring:
  session:
    jdbc:
      table-name: MY_APP_SESSION # デフォルトは SPRING_SESSION

```

### 4. 保存タイミング (Flush Mode)

セッションへの変更を「いつ」DBに書き込むかの設定です。

* **`spring.session.jdbc.flush-mode`**
* **`on-save` (デフォルト・推奨)**: リクエスト処理がすべて終わり、レスポンスを返す直前にまとめてDBへ書き込みます。効率が良いです。
* **`immediate`**: `session.setAttribute()` を呼ぶたびに即座にDBへ書き込みます。DB負荷が高くなるため、よほどの理由（処理途中で落ちてもセッションを残したい等）がない限り使いません。



```yaml
spring:
  session:
    jdbc:
      flush-mode: on-save

```

---

### まとめ：本番用 application.yml 推奨例

PostgreSQLを使用した本番環境を想定した推奨設定は以下のようになります。

```yaml
spring:
  session:
    store-type: jdbc
    jdbc:
      # 【重要】本番ではアプリによるDDL実行を禁止
      initialize-schema: never
      
      # 【重要】クリーンアップ頻度を調整 (例: 毎時0分)
      # または "-" で無効化し、AWS RDS等のスケジューラでSQL実行させる
      cleanup-cron: "0 0 * * * *"
      
      # 基本はデフォルト(on-save)でOK
      flush-mode: on-save
      
      # 変更が必要な場合のみ
      # table-name: SPRING_SESSION

```

### 補足：PostgreSQL特有の注意点 (LOB)

Spring Session JDBC は、セッション属性（オブジェクト）をバイト列にシリアライズして `BYTEA` 型（または `OID`）のカラムに保存します。

* PostgreSQLでは、`BYTEA` 型のデータを大量に頻繁に更新すると、**VACUUM（不要領域の回収）が追いつかずにテーブルが肥大化する**ことがあります。
* **対策:** DB側の `autovacuum` 設定が適切か確認する、またはセッションには「必要最小限のデータ（今回でいうと `FRONT_SESSION_INFO` のみ）」を保存するように心がけることが重要です。巨大なオブジェクトをセッションに入れないでください。
