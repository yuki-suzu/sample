ご提示いただいたフローは、**SPA（Angular）＋BFF（Spring Boot）** の構成において非常に理にかなった設計ですが、1点だけ**技術的な落とし穴（Step 2～3の挙動）**があります。

Ajax/Fetchリクエスト（AngularからのAPI呼び出し）に対して、サーバーが `302 Redirect` を返しても、**ブラウザは自動的にリダイレクト先（Cognito）のHTMLをAjaxのレスポンスとして取得しようとしてしまい、CORSエラーやパースエラーで失敗します**。画面遷移は起きません。

そのため、Step 2～4の部分を少し調整し、「APIが401を返したら、Angularがブラウザをリダイレクトさせる」または「Angularの起動時（Guard）にセッションチェックを行い、なければログインエンドポイントへ遷移させる」形にするのが定石です。

今回はご要望のフロー（特にStep 10以降のカスタムSuccessHandlerによるセッション構築）を実現するためのコードを提示します。

### 実装のポイント

1. **Spring (Backend):** `AuthenticationSuccessHandler` をカスタム実装し、認証後のリダイレクト先やフロント用セッション情報を制御します。
2. **Angular (Frontend):** アプリ起動時（`APP_INITIALIZER`）にセッション情報取得APIを呼び出し、未ログインなら何もしない（あるいはログインへ）、ログイン済みなら保存されたURLへ遷移させます。

---

### 1. Spring Boot 3.2 (Backend)

#### SecurityConfig.java

認証成功時のハンドラ（`customSuccessHandler`）を登録します。また、APIエンドポイント（`/ifs/**`）へのアクセスには認証を必須とします。

```java
package com.example.trustap.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationSuccessHandler customSuccessHandler;

    public SecurityConfig(AuthenticationSuccessHandler customSuccessHandler) {
        this.customSuccessHandler = customSuccessHandler;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // 必要に応じてCookieCsrfTokenRepositoryを設定
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/ifs/session").permitAll() // セッション確認用は許可（または401でも可）
                .requestMatchers("/ifs/**").authenticated()  // 業務APIは認証必須
                .anyRequest().permitAll()                    // その他（index.html等）
            )
            // 未認証時の挙動: Ajaxリクエストに対してはログインページHTMLではなく401を返す
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            )
            .oauth2Login(oauth2 -> oauth2
                // 認証成功時のカスタムハンドラを登録 (Step 10)
                .successHandler(customSuccessHandler)
            );

        return http.build();
    }
}

```

#### CustomAuthenticationSuccessHandler.java (Step 10の実装)

ここが核となる処理です。Cognitoからのコールバック後に実行されます。

```java
package com.example.trustap.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        HttpSession session = request.getSession();

        // Step 10-1: Cognito情報＋各種マスター情報の取得・作成
        // ここでDB検索などを行い、フロントエンドに必要な情報を詰め込む
        Map<String, Object> frontendSessionInfo = new HashMap<>();
        frontendSessionInfo.put("username", oAuth2User.getAttribute("username"));
        frontendSessionInfo.put("email", oAuth2User.getAttribute("email"));
        frontendSessionInfo.put("role", "ADMIN"); // 例: DBから取得した権限情報
        
        // Sessionに保存
        session.setAttribute("FRONT_SESSION_INFO", frontendSessionInfo);

        // Step 10-2: リダイレクト先URLの決定
        // 注: 認証フロー開始時にAngularから "redirect_uri" パラメータなどで渡してもらうか、
        // あるいはSessionに事前に保存しておいた "targetUrl" を取り出すのが一般的です。
        // ここでは仮にSessionに保存されていたとして取り出します。
        String targetUrl = (String) session.getAttribute("TARGET_URL");
        if (targetUrl == null || targetUrl.isEmpty()) {
            targetUrl = "/"; // デフォルト
        }
        
        // フロント用Session情報にもリダイレクト先を含める（Step 12で返却するため）
        frontendSessionInfo.put("redirectUrl", targetUrl);

        // Step 10-3: ルート(/)へリダイレクト
        // ブラウザのリダイレクトを行うため、ステータスコード200ではなく302でルートへ飛ばし、
        // そこでAngularを再起動させるのが最も確実です。
        response.sendRedirect("/");
    }
}

```

#### SessionController.java (Step 11, 12の実装)

Angularが起動時に叩くAPIです。

```java
package com.example.trustap.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/ifs")
public class SessionController {

    @GetMapping("/session")
    public ResponseEntity<?> getSessionInfo(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        
        if (session == null || session.getAttribute("FRONT_SESSION_INFO") == null) {
            // セッションがない、または認証済みフラグがない
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Sessionに保存しておいた情報を返却
        Map<String, Object> info = (Map<String, Object>) session.getAttribute("FRONT_SESSION_INFO");
        return ResponseEntity.ok(info);
    }
}

```

---

### 2. Angular 17.3 (Frontend)

Angularでは「起動時チェック」と「401ハンドリング」を実装します。

#### auth.interceptor.ts

API実行時に401が返ってきたら、現在のURLを保存してからログイン処理（バックエンドへのリダイレクト）を行います。

```typescript
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      // 401 Unauthorizedの場合
      if (error.status === 401) {
        // 現在のURL（本来行きたかった場所）を取得
        // 例: /hogehoge
        const targetUrl = window.location.pathname;

        // Step 1～4の修正案:
        // Ajaxで302は扱えないため、ここでブラウザをSpringのログインエンドポイントへ飛ばす
        // 同時にターゲットURLをクエリパラメータ等で渡す（Spring側でこれをSessionに詰める処理が必要）
        // 簡易実装として、SpringのLogin Endpointへ遷移
        
        // ※Spring側で事前にSession.setAttribute("TARGET_URL", targetUrl)するAPIを作って呼ぶか、
        // ログインURLに ?state=... を含めるなどの工夫が必要です。
        
        window.location.href = `/oauth2/authorization/cognito`; 
      }
      return throwError(() => error);
    })
  );
};

```

#### app.config.ts (Step 11: 起動時チェック)

`APP_INITIALIZER` を使い、Angularアプリが描画される前に `/ifs/session` を確認します。

```typescript
import { ApplicationConfig, APP_INITIALIZER } from '@angular/core';
import { provideRouter, Router } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { routes } from './app.routes';
import { authInterceptor } from './auth.interceptor';
import { HttpClient } from '@angular/common/http';
import { catchError, of, tap } from 'rxjs';

// セッション初期化ファクトリ
function initializeAppFactory(http: HttpClient, router: Router) {
  return () => {
    // Step 11: Session情報取得API呼び出し
    return http.get<any>('/api/ifs/session').pipe(
      tap(sessionInfo => {
        // Step 13: RedirectURLをもとに遷移
        if (sessionInfo && sessionInfo.redirectUrl) {
           // ルート(/)にいる場合のみリダイレクト（無限ループ防止）
           if (window.location.pathname === '/') {
             router.navigateByUrl(sessionInfo.redirectUrl);
           }
        }
      }),
      catchError((err) => {
        // 未認証(401)の場合は何もしない（画面コンポーネント側でガードするか、ログインへ飛ばす）
        // ここではアプリを通常起動させる
        return of(null);
      })
    );
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(withInterceptors([authInterceptor])),
    {
      provide: APP_INITIALIZER,
      useFactory: initializeAppFactory,
      deps: [HttpClient, Router],
      multi: true
    }
  ]
};

```

---

### 補足：Step 2, 10.2 の「元のURL」の受け渡しについて

ご要望のフローでは `Step 10.2` で Referer から取得とありますが、OAuth2のコールバック時のRefererは `cognito.amazon.com` になっているため、元の `/hogehoge` は取得できません。

これを実現するためには、以下のいずれかの方法を追加する必要があります。

**推奨パターン（Springの機能を利用）:**
Angularのインターセプターで401を検知した際、いきなり `/oauth2/authorization/cognito` へ飛ばすのではなく、**一度Springの「リダイレクト前処理エンドポイント」を叩く**ようにします。

1. **Angular**: APIエラー(401) -> `window.location.href = '/api/auth/login?target=/hogehoge'`
2. **Spring**: `/api/auth/login` コントローラー
* クエリパラメータ `target` を取得。
* `session.setAttribute("TARGET_URL", target)` を実行。
* `response.sendRedirect("/oauth2/authorization/cognito")` を返す。


3. **Spring**: (Step 10) `CustomSuccessHandler`
* `session.getAttribute("TARGET_URL")` で `/hogehoge` を取り出す。
* `frontendSessionInfo` に詰める。



これで、Step 13での正しい画面遷移が可能になります。
