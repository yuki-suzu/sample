ぐぬぬ……！痛いところを突かれたのじゃ！
おぬしの言う通り、完全にぐうの音も出ない正論じゃ……！`PasswordEncoder` の中でリクエストURIを文字列判定したりセッションをほじくり返したりするのは、オブジェクト指向的にも Spring Security のアーキテクチャ的にも完全に「力技（ゴリゴリ）のアンチパターン」じゃった！深く反省じゃ！

なぜあんな泥臭いことになったのかというと、**「文字列のハッシュ照合だけを行うべき `PasswordEncoder`」に、HTTPリクエストの解析やユーザー認証の振り分けという複数の責務を背負わせすぎたから** なのじゃ。

Spring Security の本来の設計思想に則った、**極めてスマートで美しい王道設計** に生まれ変わらせてみせるぞ！

---

## 本来あるべきスマートな設計の全体像

1. **`PasswordEncoder` は Spring 標準に戻す（自作しない！）**
Spring 標準の `PasswordEncoderFactories.createDelegatingPasswordEncoder()` をそのまま Bean 登録する。
👉 これだけで `{noop}`, `{bcrypt}`, `$2a$...` は Spring が勝手に自動判別して処理し、トークンエンドポイント（クライアント認証）も1ミリも壊れなくなる！
2. **ユーザー認証の動的分岐は `AuthenticationProvider` に任せる**
ユーザー認証（`/login`）のパイプラインにだけカスタムの `AuthenticationProvider` を挟む。
👉 ここにはクライアント認証（`OAuth2ClientAuthenticationProvider`）の通信が絶対に混ざってこないため、URL判定やBasicヘッダーのパースなどという不毛な泥臭いコードが**完全に消滅**するのじゃ！

---

## スマートな実装コード (Spring Boot 3.2 / Java 21)

### ① 設定クラス（`SecurityConfig.java`）

`PasswordEncoder` は Spring 標準の便利屋に任せ、ユーザー認証専用のプロバイダーをスッキリ登録するだけじゃ！

```java
package com.example.config;

import com.example.security.JsonUserDetailsService;
import com.example.security.SmartMockAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Spring Security の基本 Bean を定義する構成クラス。
 */
@Configuration
public class SecurityConfig {

    /**
     * Spring Security 標準の委譲型パスワードエンコーダーを登録します。
     * 
     * <p>{@code {noop}} や {@code {bcrypt}} プレフィックスを自動判別して検証を行うため、
     * クライアント認証および標準的なハッシュ照合を自作コードなしで安全に処理します。</p>
     *
     * @return 標準の {@link PasswordEncoder} インスタンス
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * クライアントIDに応じた動的検証を行うユーザー認証プロバイダーを登録します。
     *
     * @param userDetailsService ユーザー情報取得サービス
     * @param passwordEncoder     標準パスワードエンコーダー
     * @param strictClientId      厳格認証対象のクライアントID
     * @return 構成済みの {@link SmartMockAuthenticationProvider}
     */
    @Bean
    public AuthenticationProvider authenticationProvider(
            JsonUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            @Value("${mock.auth.strict-client-id:${STRICT_CLIENT_ID:ClientID-b}}") String strictClientId) {
        return new SmartMockAuthenticationProvider(userDetailsService, passwordEncoder, strictClientId);
    }
}

```

---

### ② ユーザー認証プロバイダー (`SmartMockAuthenticationProvider.java`)

`PasswordEncoder` を自作するのではなく、ユーザー認証（`UsernamePasswordAuthenticationToken`）の処理そのものを Spring の王道作法でオーバーライドするのじゃ。

```java
package com.example.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * OIDCモック環境用にクライアント別の認証ポリシーを適用する {@link AuthenticationProvider}。
 * 
 * <p>Spring Security 標準の {@link DaoAuthenticationProvider} を継承し、
 * 認可リクエスト元のクライアントIDが特定の厳格対象（{@link #strictClientId}）である場合のみ
 * 通常のパスワード照合を行い、それ以外のクライアントからの要求時はパスワード検証をバイパス（ダミー認証）します。</p>
 */
@RequiredArgsConstructor
public class SmartMockAuthenticationProvider extends DaoAuthenticationProvider {

    private final String strictClientId;

    /**
     * コンストラクタ。
     *
     * @param userDetailsService ユーザー詳細取得サービス
     * @param passwordEncoder     パスワードエンコーダー
     * @param strictClientId      厳格認証を行うクライアントID
     */
    public SmartMockAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            String strictClientId) {
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(passwordEncoder);
        this.strictClientId = strictClientId;
    }

    /**
     * ユーザー認証におけるパスワード追加検証を実行します。
     * 
     * <p>認可リクエストから解決されたクライアントIDを判定し、厳格認証対象外のクライアントであれば
     * パスワード不整合チェックをスキップして認証を通過させます。</p>
     *
     * @param userDetails    JSON等から取得された正規のユーザー詳細情報
     * @param authentication ユーザーが入力した認証情報トークン
     * @throws AuthenticationException 厳格認証対象クライアントにおいてパスワードが一致しない場合
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {

        String currentClientId = resolveClientIdFromSession();

        // 厳格認証対象（ClientID-b）の場合のみ、親クラス（標準のPasswordEncoder照合）を実行
        if (this.strictClientId != null && this.strictClientId.equals(currentClientId)) {
            super.additionalAuthenticationChecks(userDetails, authentication);
            return;
        }

        // 通常クライアント（ClientID-a等）の場合は、入力値の有無のみ確認してパスワード照合をバイパス
        if (authentication.getCredentials() == null) {
            throw new BadCredentialsException("パスワードが入力されていません。");
        }
    }

    /**
     * ログイン前の認可リクエスト（SavedRequest）から要求元の client_id を抽出します。
     *
     * @return 検出されたクライアントID。特定できない場合は {@code null}
     */
    private String resolveClientIdFromSession() {
        ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) return null;

        HttpServletRequest request = attributes.getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object savedRequestObj = session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
            if (savedRequestObj instanceof SavedRequest savedRequest) {
                String[] clientIds = savedRequest.getParameterValues("client_id");
                if (clientIds != null && clientIds.length > 0) {
                    return clientIds[0];
                }
            }
        }
        return request.getParameter("client_id");
    }
}

```

---

## ここが圧倒的にスマートになったポイント

* **`PasswordEncoder` の自作が完全に不要になった**
泥臭い自作クラスをまるごと削除できる。Spring 標準の `DelegatingPasswordEncoder` が動くので、クライアント認証（`client_secret`）も `{noop}` も `{bcrypt}` も余計なコードなしで完璧に動作する。
* **URL判定やBasic認証ヘッダーのデコードが全滅**
`SmartMockAuthenticationProvider` は画面からのログイン時（`UsernamePasswordAuthenticationToken`）しか絶対に動かないため、トークンエンドポイントの通信が混ざり込む心配が根本からゼロになった。
* **Spring Security の拡張ポイント（`additionalAuthenticationChecks`）を正しく利用**
「パスワードの照合をどうするか」を責務として持っているメソッドだけをきれいに上書きしているため、設計として非常に自然で読みやすい。

これぞ Spring Security の流儀に則ったスマートな構造じゃ！無駄な泥臭さが一掃されてスッキリしたじゃろ！
