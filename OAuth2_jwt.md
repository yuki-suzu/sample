無駄なコードや不要な設定を徹底的に削ぎ落とし、**「Spring Boot 3.2 / Java 21 / PostgreSQL 16 / 外部 Tomcat（`bootWar`）環境」** において、M2M（Client Credentials）認証兼リソースサーバーを完全自律・最速で動かすための **最終確定版（全量）** を提示するぞ！

---

## 変更内容の全体サマリー

| 対象 | 変更内容 | 目的・理由 |
| --- | --- | --- |
| **① データベース (SQL)** | `oauth2_registered_client.token_settings` 内の `"reference"` を `"self-contained"` に置換 | クライアント設定を JWT 発行モードに変更 |
| **② `application.yml**` | `spring.security.oauth2.resourceserver` 関連の設定を**全削除** | メモリ直結検証のため、外部通信用設定は完全不要 |
| **③ `JwkConfig.java**` | `JWKSource`、`JwtDecoder`、`AuthorizationServerSettings` の Bean 定義 | メモリ上での署名生成と直接検証、認可サーバー標準設定の提供 |
| **④ `SecurityConfig.java**` | 画面用リダイレクト・`formLogin`・OIDC を全撤廃し、純粋な M2M + JWT 検証に最適化 | 余計なエラーハンドリングやセッション管理を排し、API 仕様（401/403）に準拠 |

---

## 1. データベース（SQL）の変更

`oauth2_registered_client` テーブルの対象レコードについて、`token_settings` カラム内のフォーマット指定を置換するのじゃ。

```sql
-- 対象の M2M クライアントID を指定して実行
UPDATE oauth2_registered_client
SET token_settings = REPLACE(token_settings, '"value":"reference"', '"value":"self-contained"')
WHERE client_id = 'YOUR_M2M_CLIENT_ID';

-- ※ JSON 内のスペース有無の差異を考慮する場合はこちらも確認
UPDATE oauth2_registered_client
SET token_settings = REPLACE(token_settings, '"value": "reference"', '"value": "self-contained"')
WHERE client_id = 'YOUR_M2M_CLIENT_ID';

```

---

## 2. `application.yml` の変更

`resourceserver` に関連する設定ブロック（`opaquetoken` や `jwt`）は**すべて削除**する。

```yaml
# resourceserver に関する外部問い合わせ設定（introspection-uri や jwk-set-uri）は
# 同一コンテキスト内のメモリ直結検証を行うため、一切の記述が不要！

```

---

## 3. Java 実装コード一式

### ① `JwkConfig.java`（暗号鍵・デコーダー・認可サーバー基本構成）

```java
package com.example.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * 認可サーバーおよびリソースサーバー向けの暗号鍵、JWT デコーダー、基本プロトコル設定を統括する構成クラス。
 * 
 * <p>同一 JVM 内での稼働を前提とし、外部 Tomcat デプロイ時でもネットワーク通信（HTTP による公開鍵取得）を
 * 発生させずに、メモリ上で直接 JWT 署名検証を行う {@link JwtDecoder} を Spring コンテキストに提供します。</p>
 */
@Configuration
public class JwkConfig {

    /**
     * JWT の電子署名および公開鍵情報配信を担う {@link JWKSource} を登録します。
     *
     * @return RSA キーペアを保持する不変の {@link JWKSource} インスタンス
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /**
     * リソースサーバーがメモリ上で JWT を直接検証するための {@link JwtDecoder} を登録します。
     * 
     * <p>同一コンテキスト内の {@link JWKSource} を直接参照するため、HTTP 通信（ポートや URL 設定）を
     * 一切行わずに、高速かつ確実に署名検証を実行します。</p>
     *
     * @param jwkSource 署名鍵を提供する {@link JWKSource}
     * @return メモリ参照型の {@link JwtDecoder} インスタンス
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 認可サーバーの標準エンドポイントおよびプロトコル構成（{@link AuthorizationServerSettings}）を登録します。
     *
     * @return デフォルト構成の {@link AuthorizationServerSettings} インスタンス
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    /**
     * RSA 2048bit の暗号鍵ペアを新規生成します。
     *
     * @return 生成された {@link KeyPair}（公開鍵および秘密鍵）
     * @throws IllegalStateException キーペアの初期化・生成処理に失敗した場合
     */
    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("RSA キーペアの生成に失敗しました", ex);
        }
    }
}

```

---

### ② `SecurityConfig.java`（M2M 特化セキュリティフィルターチェーン）

画面遷移用のコード（`formLogin` や `LoginUrlAuthenticationEntryPoint` 等）をすべて排除した、純粋な API / M2M 構成じゃ。

```java
package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * M2M（Client Credentials）通信専用の認可サーバー兼リソースサーバー向けセキュリティフィルターチェーン設定クラス。
 * 
 * <p>ブラウザ向けのログイン画面遷移やセッション管理を排し、ステートレスな API 認可制御と
 * 自己完結型 JWT（{@code SELF_CONTAINED}）の自律検証を構成します。</p>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 認可サーバー機能（{@code /oauth2/token} 等のエンドポイント）を提供するフィルターチェーンを構築します。
     * 
     * <p>Client Credentials グラント等のトークン発行要求を処理し、認証失敗時は HTTP 401 を返却します。</p>
     *
     * @param http セキュリティ構成ビルダー {@link HttpSecurity}
     * @return 構築された認可サーバー用 {@link SecurityFilterChain}
     * @throws Exception フィルターチェーン構築中に例外が発生した場合
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );

        return http.build();
    }

    /**
     * リソースサーバー機能（業務 API エンドポイント保護）を提供するフィルターチェーンを構築します。
     * 
     * <p>{@link JwkConfig} で登録された {@link org.springframework.security.oauth2.jwt.JwtDecoder}
     * を用いて Bearer JWT トークンをメモリ上で直接検証します。また、API に不要な CSRF およびセッション生成を無効化します。</p>
     *
     * @param http セキュリティ構成ビルダー {@link HttpSecurity}
     * @return 構築されたリソースサーバー用 {@link SecurityFilterChain}
     * @throws Exception フィルターチェーン構築中に例外が発生した場合
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // API のため CSRF を無効化
            .csrf(AbstractHttpConfigurer::disable)
            // ステートレスなセッション管理
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            // JWT 自律検証を有効化（JwkConfig の JwtDecoder が自動適用される）
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );

        return http.build();
    }
}

```

---

## 最終チェック・確認ポイント

1. **一切の無駄・ゴミ設定を排除**
画面ログイン用の `LoginUrlAuthenticationEntryPoint`、`formLogin()`、`MediaTypeRequestMatcher`、OIDC 設定はすべて完全撤去した。
2. **外部 Tomcat（WAR）の環境非依存**
URL やポート番号の指定がコード・設定ファイルから一切消えたため、Tomcat 側のポート変更やコンテキストパス変更にびくともしない。
3. **DB I/O の削減**
API 呼び出し時の `oauth2_authorization` テーブルへの SELECT（トークン問い合わせ）が完全ゼロになり、大幅なスループット向上が得られる。

これで完璧な布陣じゃ！迷わずこの構成で進めておくれ！
