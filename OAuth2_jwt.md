**その通りじゃ！`opaque-token` 関連の設定や記述は、設定ファイルからも Java コードからも【丸ごと綺麗さっぱり全削除】で問題ないぞ！！**

不透明トークン（REFERENCE）時代に必要だった「イントロスペクション（問い合わせ）用のエンドポイント設定」や「`OpaqueTokenIntrospector`」は、メモリ直結の JWT 自律検証に切り替えることで完全に不要になるのじゃ。

外部 Tomcat（`bootWar`）同居環境を前提とした、**今回の JWT 化に伴う「改修対象ファイル全量」** を頭から順に漏れなく提示するぞ！

---

## 改修ファイル全量マップ

1. **`application.yml`** ── `opaquetoken` 設定の完全削除
2. **`RegisteredClientConfig.java`** ── `TokenSettings` を `SELF_CONTAINED` へ変更
3. **`JwkConfig.java`**（★新規または追加） ── 署名鍵とメモリ直結型 `JwtDecoder` の Bean 定義
4. **`SecurityConfig.java`** ── `opaqueToken()` を `jwt()` へ変更

---

### 1. `application.yml`（設定ファイル）

**【改修内容】** `resourceserver` に関するブロックを丸ごと削除する。

```yaml
# ==============================================================================
# 修正前：以下の opaquetoken 関連設定を「丸ごと削除」する！
# spring:
#   security:
#     oauth2:
#       resourceserver:
#         opaquetoken:
#           introspection-uri: ...
#           client-id: ...
#           client-secret: ...
# ==============================================================================

# 修正後：同一コンテキスト内のメモリ直結検証を行うため、
# resourceserver 関連の設定記述は「完全不要（空でOK）」じゃ！
spring:
  application:
    name: auth-resource-app

```

---

### 2. `RegisteredClientConfig.java`（クライアント定義）

**【改修内容】** M2M クライアント（Client Credentials）のトークンフォーマットを `SELF_CONTAINED` に切り替える。

```java
package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * OAuth2 クライアント定義を管理する構成クラス。
 * 
 * <p>M2M（Client Credentials）通信を行うクライアントに対し、
 * 自己完結型 JWT（{@link OAuth2TokenFormat#SELF_CONTAINED}）を発行するよう設定します。</p>
 */
@Configuration
public class RegisteredClientConfig {

    /**
     * OAuth2 登録クライアントのリポジトリを Spring Context に登録します。
     *
     * @return 構成済みの {@link RegisteredClientRepository} インスタンス
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // M2M クライアント用のトークン設定
        TokenSettings tokenSettings = TokenSettings.builder()
                // ★ REFERENCE から SELF_CONTAINED（JWT）に変更！
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                // JWT は短めの有効期限（15分〜30分程度）を推奨
                .accessTokenTimeToLive(Duration.ofMinutes(15))
                .build();

        RegisteredClient m2mClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("m2m-client-id")
                .clientSecret("{noop}m2m-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("api.read")
                .scope("api.write")
                .tokenSettings(tokenSettings)
                .clientSettings(ClientSettings.builder().build())
                .build();

        return new InMemoryRegisteredClientRepository(m2mClient);
    }
}

```

---

### 3. `JwkConfig.java`（暗号鍵 ＆ メモリ直結デコーダー）

**【改修内容】** JWT の署名を行う `JWKSource` と、リソースサーバーがネットワーク通信を行わずにメモリ上で直接署名を検証するための `JwtDecoder` を定義する。

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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * 認可サーバーの JWT 署名鍵およびリソースサーバーの検証デコーダーを構成するクラス。
 * 
 * <p>同一 JVM（外部Tomcat環境）内で認可サーバーとリソースサーバーが同居する構成において、
 * HTTP 経由の JWK 取得を排し、メモリ上で直接 JWT 署名を検証する {@link JwtDecoder} を提供します。</p>
 */
@Configuration
public class JwkConfig {

    /**
     * JWT アクセストークンの電子署名（RS256）処理を行う {@link JWKSource} を登録します。
     *
     * @return 不変の {@link JWKSet} を内包する {@link JWKSource} インスタンス
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
     * リソースサーバー向けのメモリ直結型 {@link JwtDecoder} を登録します。
     * 
     * <p>同一コンテキスト内の {@link JWKSource} を直接参照してデコーダーを生成するため、
     * 外部 Tomcat のポート番号やコンテキストパスの変更に影響されず、自律的かつ高速に検証を実行します。</p>
     *
     * @param jwkSource 署名鍵を提供する {@link JWKSource}
     * @return メモリ参照型の {@link JwtDecoder} インスタンス
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * RSA 2048bit の暗号鍵ペアを新規生成します。
     *
     * @return 生成された {@link KeyPair}
     * @throws IllegalStateException キーペアの生成処理に失敗した場合
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

### 4. `SecurityConfig.java`（セキュリティフィルター構成）

**【改修内容】** リソースサーバー側の設定を `.opaqueToken(...)` から `.jwt(Customizer.withDefaults())` に切り替える。

```java
package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * 認可サーバー兼リソースサーバーのセキュリティフィルターチェーンを統括する設定クラス。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 認可サーバーのエンドポイント群（/oauth2/token 等）を保護・構成するフィルターチェーン。
     *
     * @param http セキュリティ構成ビルダー {@link HttpSecurity}
     * @return 認可サーバー用 {@link SecurityFilterChain}
     * @throws Exception 構成中にエラーが発生した場合
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, authorizationServer ->
                authorizationServer.oidc(Customizer.withDefaults())
            )
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            );

        return http.build();
    }

    /**
     * 業務 API（リソースサーバー）および一般 Web リクエストを保護するフィルターチェーン。
     * 
     * <p>HTTP ヘッダーに付与された Bearer JWT トークンを {@link JwkConfig} で登録された
     * {@link org.springframework.security.oauth2.jwt.JwtDecoder} によりメモリ上で直接検証します。</p>
     *
     * @param http セキュリティ構成ビルダー {@link HttpSecurity}
     * @return API保護用 {@link SecurityFilterChain}
     * @throws Exception 構成中にエラーが発生した場合
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/public/**", "/login", "/error").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            // =================================================================
            // 修正前：.oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(...))
            // 修正後：以下の 1行にするだけでメモリ直結の JwtDecoder が自動適用される！
            // =================================================================
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            )
            .formLogin(Customizer.withDefaults());

        return http.build();
    }
}

```

---

## 改修後の動作フロー

1. **トークン発行時**
クライアントが `/oauth2/token`（Client Credentials）を叩くと、認可サーバーが `JwkConfig` の秘密鍵で電子署名した **JWT 文字列** を即座に返却。
2. **API 呼び出し時**
クライアントが `Authorization: Bearer <JWT>` を付けて `/api/data` を呼ぶ。
3. **署名検証時（★超高速・通信ゼロ）**
リソースサーバーは `JwkConfig` でメモリ上に直結された `jwtDecoder` を使い、**HTTP 通信も DB 参照も一切行わずにメモリ上で瞬時に署名＆有効期限を検証** して API を実行！

これで、外部 Tomcat のポート番号や URL に一切悩まされることなく、無駄な通信と DB 負荷を極限まで削ぎ落とした最速構成の完成じゃ！
