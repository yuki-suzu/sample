これまでの議論を踏まえ、Java 21、Spring Boot 3.2、PostgreSQL 16 の環境に最適化し、かつ **MyBatisがないプロジェクトに導入されてもエラーにならない堅牢な共通ライブラリ（JAR）構成** として、すべてのソースコードと設定を整理しました。

---

## 📂 共通ライブラリ（JAR）側の実装

### 1. 値オブジェクト（Record）の定義

MyBatisがないプロジェクトでも使い回せるよう、純粋なJava標準機能のみのパッケージに配置します。

```java
package com.example.common.domain;

/**
 * LIKE演算子による部分一致（CONTAIN）検索用のパターン文字列を表現する値オブジェクト（不変）です。
 * <p>
 * 本クラスは、画面やAPIから入力された生の検索キーワード文字列を安全にカプセル化し、
 * PostgreSQL 16におけるLIKE検索の特殊文字（{@code %}, {@code _}, {@code \}）をエスケープした上で、
 * 前後にワイルドカード（{@code %}）を付与した「LIKEパターン文字列」を生成する責務を持ちます。
 * 既存の {@link String} 型に代わる安全なLIKE専用のデータ型として機能します。
 * </p>
 *
 * @param value 画面やAPIから入力された、エスケープ前の生の検索キーワード文字列
 */
public record LikeContainsPattern(String value) {

    /**
     * PostgreSQLの仕様に準拠した、部分一致検索用のLIKEパターン文字列を取得します。
     * <p>
     * 入力文字列に含まれる以下の特殊文字をエスケープした上で、前後に {@code %} を付与します。
     * <ul>
     * <li>{@code \} -> {@code \\}</li>
     * <li>{@code %} -> {@code \%}</li>
     * <li>{@code _} -> {@code \_}</li>
     * </ul>
     * 引数の文字列が null の場合は、SQLのNULLとして透過的に扱うため、エスケープ処理は行わず null を返します。
     * </p>
     *
     * @return サニタイズされ、前後に % が付与されたLIKE検索用パターン文字列。入力が null の場合は null
     */
    public String toLikePattern() {
        if (value == null) {
            return null;
        }
        // PostgreSQLのエスケープルールに基づき、エスケープ文字自身、%、_ の順で置換
        String escaped = value.replace("\\", "\\\\")
                              .replace("%", "\\%")
                              .replace("_", "\\_");
        return "%" + escaped + "%";
    }
}

```

### 2. MyBatis用カスタムTypeHandlerの実装

MyBatis依存のコードとなるため、ドメインとはパッケージを分離します。

```java
package com.example.common.mybatis;

import com.example.common.domain.LikeContainsPattern;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;
import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * {@link LikeContainsPattern} 型を MyBatis で透過的に扱うためのカスタム TypeHandler です。
 * <p>
 * Java 側の {@link LikeContainsPattern} オブジェクトをデータベースに設定する際、
 * 自動的に部分一致検索用（サニタイズ＋前後%付与）の文字列へ変換して PreparedStatement にバインドします。
 * </p>
 */
@MappedTypes(LikeContainsPattern.class)
public class LikeContainsPatternTypeHandler extends BaseTypeHandler<LikeContainsPattern> {

    /**
     * Java 側の {@link LikeContainsPattern} オブジェクトからLIKEパターン文字列を抽出し、PreparedStatement に設定します。
     *
     * @param ps        PreparedStatement オブジェクト
     * @param i         パラメータのバインドインデックス
     * @param parameter 設定対象の {@link LikeContainsPattern} オブジェクト
     * @param jdbcType  JDBC 型
     * @throws SQLException データベースアクセスエラーが発生した場合
     */
    @Override
    public void setNonNullParameter(PreparedStatement ps, int i, LikeContainsPattern parameter, JdbcType jdbcType)
            throws SQLException {
        ps.setString(i, parameter.toLikePattern());
    }

    /**
     * ResultSet からカラム名を指定して値を取得し、{@link LikeContainsPattern} に復元します。
     * <p>
     * ※本型は検索条件専用を想定しているため、再取得時は単純な詰め替えのみを行います。
     * </p>
     *
     * @param rs         ResultSet オブジェクト
     * @param columnName 取得対象のカラム名
     * @return 取得した文字列を格納した {@link LikeContainsPattern} オブジェクト。値が null の場合は null
     * @throws SQLException データベースアクセスエラーが発生した場合
     */
    @Override
    public LikeContainsPattern getNullableResult(ResultSet rs, String columnName) throws SQLException {
        String result = rs.getString(columnName);
        return result == null ? null : new LikeContainsPattern(result);
    }

    @Override
    public LikeContainsPattern getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
        String result = rs.getString(columnIndex);
        return result == null ? null : new LikeContainsPattern(result);
    }

    @Override
    public LikeContainsPattern getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
        String result = cs.getString(columnIndex);
        return result == null ? null : new LikeContainsPattern(result);
    }
}

```

### 3. 自動構成（Auto-Configuration）設定クラス

MyBatisが存在する場合のみ作動し、TypeHandlerを自動登録する仕組みです。

```java
package com.example.common.mybatis;

import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.boot.autoconfigure.ConfigurationCustomizer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;

/**
 * 共通ライブラリ内の MyBatis 関連コンポーネントを自動構成するための設定クラスです。
 * <p>
 * 本クラスは、利用側アプリケーションのクラスパス上に MyBatis（{@link SqlSessionFactory} および {@link ConfigurationCustomizer}）
 * が存在する場合にのみ有効化されます。MyBatis が存在しないプロジェクトにおいては、本設定全体の評価が安全にスクリップされるため、
 * 利用側での起動時エラー（{@link NoClassDefFoundError} など）を防止します。
 * </p>
 */
@AutoConfiguration
@ConditionalOnClass({SqlSessionFactory.class, ConfigurationCustomizer.class})
public class MyBatisCommonAutoConfiguration {

    /**
     * MyBatis の Configuration をカスタマイズし、型ハンドラーを明示的に登録します。
     *
     * @return MyBatis の設定をカスタマイズする {@link ConfigurationCustomizer} の Bean
     */
    @Bean
    public ConfigurationCustomizer commonConfigurationCustomizer() {
        return configuration -> {
            configuration.getTypeHandlerRegistry().register(LikeContainsPatternTypeHandler.class);
        };
    }
}

```

### 4. 共通ライブラリ側の設定ファイル

#### `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`

Spring Boot 3.2 の自動構成メカニズムに登録するための定義ファイルです。

```text
com.example.common.mybatis.MyBatisCommonAutoConfiguration

```

#### `build.gradle` (ライブラリ側)

MyBatisを二次配布しないよう、`compileOnly` で定義します。

```groovy
plugins {
    id 'java-library'
    id 'org.springframework.boot' version '3.2.2' apply false
    id 'io.spring.dependency-management' version '1.1.4'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

dependencies {
    // コンパイル時のみ使用し、利用側への強制配布を防ぐ（必須）
    compileOnly 'org.mybatis.spring.boot:mybatis-spring-boot-starter:3.0.3'
    compileOnly 'org.springframework.boot:spring-boot-starter:3.2.2'

    // ライブラリ自身のテスト用
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.mybatis.spring.boot:mybatis-spring-boot-starter-test:3.0.3'
}

```

---

## 🚀 利用側アプリケーションでの実装例（34箇所の横展開イメージ）

共通JARを取り込んだ後、既存のMapperやDTOを以下のように修正していきます。

### Mapper インターフェース

```java
package com.example.app.infrastructure.mapper;

import com.example.app.domain.entity.User;
import com.example.common.domain.LikeContainsPattern;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import java.util.List;

/**
 * ユーザー情報のデータベース操作を行う MyBatis の Mapper インターフェースです。
 */
@Mapper
public interface UserMapper {

    /**
     * ユーザー名を指定した部分一致検索を行い、該当するユーザーのリストを取得します。
     *
     * @param userNamePattern 部分一致検索用のユーザー名パターン（共通ライブラリの値オブジェクト）
     * @return 検索条件に合致するユーザー情報のリスト
     */
    List<User> selectByName(@Param("userNamePattern") LikeContainsPattern userNamePattern);
}

```

### Mapper XML

XML側は、型が自動で解決されるため `CONCAT` や `%` の手動結合が一切不要になり、非常にスッキリします。

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mapping.mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.infrastructure.mapper.UserMapper">

    <select id="selectByName" resultType="com.example.app.domain.entity.User">
        SELECT 
            id, 
            user_name, 
            email 
        FROM 
            users
        WHERE 
            user_name LIKE #{userNamePattern} ESCAPE '\'
    </select>

</mapper>

```

### Service層（呼び出し元）

画面などから受け取った生の文字列（`String`）を、New（またはコンストラクタ）してMapperに渡します。

```java
// DTOから受け取った生の検索文字（"50%" など）を安全な型に変換
LikeContainsPattern pattern = new LikeContainsPattern(criteria.getUserName());

// Mapperに渡す（自動的にエスケープと%付与が行われる）
List<User> users = userMapper.selectByName(pattern);

```


----

`of` を使うパターンも、Javaの標準ライブラリ（`List.of()` や `Optional.of()` など）で広く採用されているデザインパターン（静的ファクトリメソッド）なので、非常にスマートで直感的です！

もしクラス名を **`LikeEscapedString`** にするのであれば、`of` を使った場合のJavaソースの見え方は以下のようになります。

```java
// クラス名が「状態」を、メソッド名「of」がインスタンス生成を表す
LikeEscapedString escapedTestId = LikeEscapedString.of(testId);

```

---

## 💡 `of` を選ぶメリット

1. **コードが短く、流れるように読める**
`LikeEscapedString.escapeForLike(testId)` と書くよりも、`LikeEscapedString.of(testId)` の方が圧倒的にシンプルでタイピングも楽です。
2. **「型変換」の意図が明確になる**
モダンなJavaにおいて `型名.of(値)` は、「この値を元にして、この型のオブジェクト（値オブジェクト）を作ってね」という共通言語になっているため、ソースを読む人が一瞬で「あ、`String` から `LikeEscapedString` に型を変換しているんだな」と理解できます。

---

## 🛠️ `of` を採用した場合の最終形コード

もし `of` を採用される場合、Recordクラスの構造は以下のようになります。

```java
package com.example.common.mybatis;

/**
 * SQLのLIKE検索において、中間一致（Contains）等に使用するために
 * 特殊文字（{@code %}, {@code _}, {@code \}）を安全にエスケープした文字列を保持する値オブジェクトです。
 * <p>
 * 本クラスは純粋なエスケープ処理済みの文字列のみを保持し、ワイルドカード（{@code %Delta}）の付与は行いません。
 * ワイルドカードの結合は、MyBatisのXML側（{@code CONCAT}句など）で行う必要があります。
 * </p>
 *
 * @param value エスケープ処理が施された生の文字列
 */
public record LikeEscapedString(String value) {

    /**
     * 指定された検索クエリ文字列から、LIKE検索用に特殊文字をエスケープした {@link LikeEscapedString} を生成します。
     *
     * @param query 画面などから入力された生の検索クエリ（null許容）
     * @return エスケープ済みの文字列を保持する {@link LikeEscapedString} インスタンス。
     * 入力が null または空文字の場合は、中身が null または空文字のインスタンスを返します。
     */
    public static LikeEscapedString of(String query) {
        if (query == null) {
            return new LikeEscapedString(null);
        }
        
        // 特殊文字の退避処理（バックスラッシュを最優先で置換）
        String escaped = query
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
        
        return new LikeEscapedString(escaped);
    }
}

```

---

## 🏁 最終ジャッジ

* `LikeEscapedString.escapeForLike(testId)` ➔ **「エスケープするぞ」という動詞（処理）を強調したい場合**
* `LikeEscapedString.of(testId)` ➔ **「エスケープ済みの文字列型に変換するぞ」という名詞（型）を強調したい場合**

クラス名に `Escaped` と入っていて「エスケープ済みのオブジェクトであること」がすでに確定しているため、メソッド名はシンプルに **`of`** に留めるのが、最も引き締まった美しいコードになります。ユーザーさんの好みにバッチリハマると思います！


