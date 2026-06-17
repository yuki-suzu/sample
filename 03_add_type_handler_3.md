**結論から言うと、完全に同居（共存）できます！何の心配もありません。**

既存の `CommonUtilsMapperConfiguration` と、新しく追加する `MyBatisCommonAutoConfiguration` は、MyBatisに対して「全く異なる仕事（責務）」をしているため、お互いに干渉することなく両方とも正しく動作します。

それぞれの役割と、さらに安全に同居させるためのワンポイントアドバイスを整理しました。

---

## なぜ同居できるのか？（役割の違い）

2つのクラスは、MyBatisの初期化フローにおいて以下のように綺麗に役割が分かれています。

### 1. 既存の `CommonUtilsMapperConfiguration`

* **役割：** `@MapperScan` を使って、指定されたパッケージ（`...rdb.mapper`）配下にあるMapperインターフェースを検索し、SpringのBeanとして登録する。
* **動くタイミング：** アプリケーション起動時の、コンポーネントスキャンや通常の `@Configuration` が評価されるフェーズ。

### 2. 新規の `MyBatisCommonAutoConfiguration`

* **役割：** `ConfigurationCustomizer` を提供し、MyBatisの内部エンジンに `LikeContainsPatternTypeHandler`（データ型変換ルール）を覚え込ませる。
* **動くタイミング：** `META-INF/spring/...imports` 経由で読み込まれる自動構成（Auto-Configuration）フェーズ。

> 💡 **イメージで言うと：**
> 既存クラスが「どのMapper（ファイル）を使うか」を取りまとめていて、新規クラスが「MyBatis全体の翻訳ルール（TypeHandler）」を追加している状態です。パーツ集めとルール設定なので、衝突しません。

---

## 🛠️ さらに安全に同居させるための「ベストプラクティス」

既存のクラスに `@AutoConfigureAfter(MybatisAutoConfiguration.class)` が指定されているのを見て、非常に綺麗な設計をされているプロジェクトだと見受けられます。

新しく作る `MyBatisCommonAutoConfiguration` をより確実に、かつ美しく同居させるために、**「MyBatis公式の自動設定クラスよりも前に評価して、カスタムルールを確実に滑り込ませる」** 設定を1行追加することをおすすめします。

### 修正版：`MyBatisCommonAutoConfiguration.java`

```java
package com.example.common.mybatis;

import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.boot.autoconfigure.ConfigurationCustomizer;
import org.mybatis.spring.boot.autoconfigure.MybatisAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;

/**
 * 共通ライブラリ内の MyBatis 関連コンポーネントを自動構成するための設定クラスです。
 * <p>
 * 本クラスは、MyBatis公式の自動構成クラス（{@link MybatisAutoConfiguration}）が実行されて
 * {@link SqlSessionFactory} がビルドされるよりも「前」に評価されるように制御します。
 * これにより、提供する {@link ConfigurationCustomizer} が確実に MyBatis の初期化プロセスに組み込まれます。
 * </p>
 */
@AutoConfiguration
@ConditionalOnClass({SqlSessionFactory.class, ConfigurationCustomizer.class})
// ↓ ここを追加：公式のMybatisAutoConfigurationが動く「前」にこのクラスを評価させる
@AutoConfigureBefore(MybatisAutoConfiguration.class)
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

### 💡 これにより実現する起動順序の美しさ

1. **`MyBatisCommonAutoConfiguration`（新規）が動く**
* 「`LikeContainsPatternTypeHandler` を登録してね」という予約注文（Bean）をSpringに預ける。


2. **`MybatisAutoConfiguration`（公式）が動く**
* 1で預けられた注文（`ConfigurationCustomizer`）を回収して、MyBatisエンジンを組み立てる。


3. **`CommonUtilsMapperConfiguration`（既存）が動く**
* 公式の組み立てが終わった「後（`@AutoConfigureAfter`）」に、指定パッケージのMapperをスキャンして登録する。



このように、Spring Bootのライフサイクル上で完璧に一列に並ぶため、総合フェーズでの挙動も非常に安定します。安心してこのまま組み込んで大丈夫です！
