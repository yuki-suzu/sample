package com.example.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * クライアントIDに応じて動的にパスワード検証ロジックを切り替えるカスタム {@link PasswordEncoder}。
 * 
 * <p>OIDCモックプロバイダーにおいて、通常の検証用クライアント（ClientID-a等）に対してはダミー認証を行い、
 * 特定の裏口・厳格検証用クライアント（ClientID-b）に対してはBCryptによるハッシュ一致検証を行います。</p>
 */
@Component
public class DynamicClientPasswordEncoder implements PasswordEncoder {

    /** 裏口・厳格認証を行うクライアントID */
    private static final String STRICT_CLIENT_ID = "ClientID-b";

    /** 厳格認証時に使用する BCrypt エンコーダー */
    private final PasswordEncoder bcryptEncoder = new BCryptPasswordEncoder();

    /** Spring Security のリクエストキャッシュハンドラー */
    private final RequestCache requestCache = new HttpSessionRequestCache();

    /**
     * パスワードを暗号化（ハッシュ化）します。
     * 
     * @param rawPassword 暗号化前の生パスワード
     * @return BCrypt によってハッシュ化されたパスワード文字列
     */
    @Override
    public String encode(CharSequence rawPassword) {
        return bcryptEncoder.encode(rawPassword);
    }

    /**
     * 入力された生パスワードと、保持されているハッシュ化パスワードの適合性を検証します。
     * 
     * <p>現在の HTTP リクエスト、またはセッションに退避された認可リクエスト（{@link SavedRequest}）から
     * {@code client_id} を抽出し、特定のクライアントID（{@value #STRICT_CLIENT_ID}）である場合は
     * BCrypt による厳格検証を行います。</p>

     * @param rawPassword ユーザーが入力した生パスワード
     * @param encodedPassword JSON等から取得した保持用パスワード（BCryptハッシュ）
     * @return 認証に成功した場合は {@code true}、失敗した場合は {@code false}
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || rawPassword.length() == 0) {
            return false;
        }

        // 現在または退避されたリクエストから client_id を取得
        String clientId = getCurrentClientId();

        // 裏口（STRICT_CLIENT_ID）の場合は、JSON保持の BCrypt ハッシュと厳格比較
        if (STRICT_CLIENT_ID.equals(clientId)) {
            if (encodedPassword == null || encodedPassword.isBlank()) {
                return false;
            }
            return bcryptEncoder.matches(rawPassword, encodedPassword);
        }

        // 通常のモック用クライアント（ClientID-a等）は入力さえあれば何でもOK
        return true;
    }

    /**
     * HTTP リクエストまたはセッション内の {@link SavedRequest} から {@code client_id} を抽出します。
     * 
     * <p>認可コードフローにおいて未認証ユーザーが {@code /oauth2/authorize} へアクセスした場合、
     * Spring Security は元のリクエストをセッション（{@link SavedRequest}）に退避して {@code /login} へリダイレクトします。
     * 本メソッドでは、直接のリクエストパラメータに加えて退避されたリクエスト情報からも {@code client_id} の検索を試みます。</p>
     *
     * @return 検出されたクライアントID文字列。取得できない場合は {@code null}
     */
    private String getCurrentClientId() {
        ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        
        if (attributes == null) {
            return null;
        }

        HttpServletRequest request = attributes.getRequest();
        HttpServletResponse response = attributes.getResponse();

        // 1. 直近のリクエストパラメータから client_id を探す（トークン直接リクエスト等の場合）
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            return clientId;
        }

        // 2. ログインフォーム送信時（/login）：退避されていた認可リクエスト (/oauth2/authorize) から client_id を取得
        if (response != null) {
            SavedRequest savedRequest = requestCache.getRequest(request, response);
            if (savedRequest != null) {
                String[] clientIds = savedRequest.getParameterValues("client_id");
                if (clientIds != null && clientIds.length > 0) {
                    return clientIds[0];
                }
            }
        }

        return null;
    }
}
}
