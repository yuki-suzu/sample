いいえ、**未認証（401）以外に「権限不足（403）」もハンドリングします。**

`exceptionHandling()` は、Spring Security のフィルターチェーン内で発生したセキュリティ例外を処理する場所で、主に以下の**2つの責任**を持っています。

1. **AuthenticationEntryPoint** (実装済み)
* **対象:** **未認証ユーザー** (Anonymous)
* **状況:** ログインしていない状態で保護されたAPIを叩いた。
* **結果:** 401 エラー + ログインURLの返却 (今回の実装)。


2. **AccessDeniedHandler** (まだ未実装)
* **対象:** **認証済みユーザー**
* **状況:** ログインはしているが、**権限（Role）が足りない**APIを叩いた（例: 一般ユーザーが管理用APIにアクセス）。
* **結果:** デフォルトでは 403 Forbidden (白い画面やデフォルトのエラーページ)。



### SPA (Angular) における問題点

現在の設定だと、権限不足（403）が発生した際、Spring Security のデフォルト動作（HTMLのエラーページ返却など）になってしまう可能性があります。
SPAとしては、403の時も **JSON** で返してもらった方が、Angular側で「権限がありません」というトーストを出したり、画面制御がしやすくなります。

以下に、**403 (Access Denied) も JSON で返す実装** を追加します。

---

### 1. JsonAccessDeniedHandler.java (新規作成)

認証済みだが権限がない場合に、JSONを返すハンドラです。

```java
package com.example.trustap.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        
        // ステータスコード: 403 Forbidden
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        // フロントエンドに見せるメッセージ
        // 必要に応じてエラーコードなどを含める
        Map<String, String> body = Map.of(
            "error", "Forbidden",
            "message", "このリソースへのアクセス権限がありません。"
        );

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}

```

### 2. SecurityConfig.java (修正)

作成したハンドラを `exceptionHandling` に登録します。

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JsonAuthenticationEntryPoint jsonEntryPoint;      // 401用
    private final CustomAuthenticationSuccessHandler successHandler;
    
    // 【追加】403用ハンドラ
    private final JsonAccessDeniedHandler accessDeniedHandler; 

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // ... (CSRF設定など略) ...

            .authorizeHttpRequests(auth -> auth
                // 権限テスト用の例: /api/admin/** は ADMIN ロール必須
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/ifs/session").permitAll()
                .requestMatchers("/api/ifs/**").authenticated()
                .anyRequest().permitAll()
            )

            // 【変更】例外ハンドリング設定
            .exceptionHandling(ex -> ex
                // 未認証 (401) -> ログインURLをJSONで返す
                .authenticationEntryPoint(jsonEntryPoint)
                
                // 権限不足 (403) -> エラーメッセージをJSONで返す 【ここを追加】
                .accessDeniedHandler(accessDeniedHandler)
            )

            .oauth2Login(oauth2 -> oauth2
                .successHandler(successHandler)
            );

        return http.build();
    }
}

```

### 補足：500エラーなどは？

`SecurityConfig` の `exceptionHandling` はあくまで **Spring Security のフィルターチェーン内で起きたセキュリティ例外** だけを扱います。

* **500 Internal Server Error:** (NullPointerExceptionなど)
* **404 Not Found:** (存在しないURL)
* **400 Bad Request:** (バリデーションエラー)

これらは Spring Security の管轄外（DispatcherServlet到達後のエラー）ですので、Spring Boot 標準の `@ControllerAdvice` や `ErrorController` でハンドリングする必要があります。

### まとめ

* **`AuthenticationEntryPoint`**: 「お前誰？（未認証）」→ **401** (Loginへ誘導)
* **`AccessDeniedHandler`**: 「お前は知ってるけど、そこに入っちゃダメ（権限不足）」→ **403** (JSONで拒否通知)

今回の追加実装で、SPA (Angular) にとって完璧なセキュリティエラーハンドリングになります。
