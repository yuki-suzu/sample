34箇所の横展開に向けて、非常に順調に進みそうですね！

しかし、現在は「総合フェーズ」というデリケートな時期**です。実作業に入る前に、1日での改修を安全にやり切るために**「盲点になりやすい4つの懸念事項と対策」を最終チェックリストとしてお伝えします。

特に1番目と2番目は、MyBatisの仕様上、実装中に「あれ？」となりやすいポイントです。

---

## 1. 【最大の盲点】XML内の動的SQL（`<if>` 句）への影響

既存のMapper XMLで、以下のように `<if>` 句を使って検索条件の制御（動的SQL）を行っている箇所はありませんか？

```xml
<if test="userName != null and userName != ''">
    AND user_name LIKE CONCAT('%', #{userName}, '%')
</if>

```

引数の型を `LikeContainsPattern` に変更した場合、MyBatis内部の式言語（OGNL）の書き方が変わります。Javaの `record` のフィールド値にアクセスするため、**.value** を指定する必要があります。

### 💡 対策

型を変更した箇所の `<if>` 句は、以下のように修正してください。これを忘れると判定が正しく動かなくなります。

```xml
<if test="userNamePattern != null and userNamePattern.value != ''">
    AND user_name LIKE #{userNamePattern} ESCAPE '\'
</if>

```

*(※Javaのrecordは `value()` メソッドですが、MyBatisのXML内（OGNL）ではプロパティ風に `.value` でアクセスできます)*

---

## 2. 型を変換する「レイヤー（場所）」の認識合わせ

34箇所の修正において、**「どこで `String` から `LikeContainsPattern` に変換するか」** をチーム内で統一しておかないと、思わぬ手戻りが発生します。

画面から受け取る DTO の型自体を `LikeContainsPattern` に変えてしまうと、Springの初期化（リクエストマッピング）や、JSR-303バリデーション（`@NotBlank` や `@Size` など）がエラーを吐くようになります。

### 💡 対策

**「DTOやService層までは `String` のまま扱い、Mapperを呼び出す直前で型を変換する」** のが最も安全です。

* **パターンA：Mapperインターフェースの引数で new する（おすすめ）**
```java
// Service層
List<User> users = userMapper.selectByName(new LikeContainsPattern(criteria.getUserName()));

```


* **パターンB：検索用DTOの「Getter」だけを改造する**
もし同一のDTOを多くの場所で使い回しているなら、DTOのフィールドは `String` のままにして、Mapperが参照する専用のGetterを追加する裏技もあります。
```java
public class UserSearchCriteria {
    private String userName; // 画面からは String で受ける

    // MyBatisのXMLからは #{userNamePattern} で呼び出してもらう
    public LikeContainsPattern getUserNamePattern() {
        return new LikeContainsPattern(this.userName);
    }
}

```



---

## 3. 空文字（`""`）が渡ってきたときの挙動

画面の検索フォームで、未入力のまま検索ボタンが押された際、バックエンドに `null` ではなく空文字（`""`）が届く仕様になっていることがあります。

もし、前述の `<if>` 句によるスキップをせず、空文字のまま `LikeContainsPattern` を通過してSQLを発行してしまうと、`LIKE '%%'` に変換されてしまい、**「条件を無視して全件ヒットする」** という挙動になります。

### 💡 対策

既存のロジックが「未入力（空文字）の時は、検索条件から除外する」という仕様になっているか、ステップ2のプロトタイプ検証時に必ず空文字（`""`）をフォームから送信して、意図通りのSQL（`AND` 句自体が消えるかなど）が生成されるか確認してください。

---

## 4. 総合フェーズ中の「先祖返り」リスク

34箇所を綺麗に直してテストが通っても、総合フェーズ中に**別の開発者が「新しく追加した検索機能」で、昔の癖で `String` のまま `LIKE` 検索を書いてしまう**と、そこだけバグが再発（先祖返り）します。

### 💡 対策

共通ライブラリをリリースするタイミングで、開発チーム全体に以下のアナウンス（ルール化）を徹底してください。

> **【開発ルール】**
> 今後、PostgreSQLに対して LIKE（部分一致）検索を行う場合は、SQLインジェクションや特殊文字バグを防ぐため、**String型をそのままMapperに渡すことを禁止します。**
> 必ず共通ライブラリの `LikeContainsPattern` 型に変換して、XML側は `ESCAPE '\'` を明記してください。

---

## まとめ

総合フェーズでの改修における最大の敵は、仕様の漏れではなく「一括置換による動的SQL（XML）の崩壊」です。

特に **「1. `<if>` 句の条件式の修正（`.value` の付与）」** だけ念頭に置いて作業を進めれば、1日での水平展開は非常に現実的ですし、今後のシステムの堅牢性は見違えるほど良くなります。

無事に改修が成功することを応援しております！
