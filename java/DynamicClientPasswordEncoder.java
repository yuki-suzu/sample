package com.example.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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

    /**
     * パスワードを暗号化（ハッシュ化）します。
     * 
     * <p>モック用ユーザー情報の作成や更新時に利用され、内部で {@link BCryptPasswordEncoder} を呼び出します。</p>

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
     * <p>現在の HTTP リクエストに含まれる {@code client_id} を参照し、
     * 特定のクライアントID（{@value #STRICT_CLIENT_ID}）からの要求である場合は厳格な BCrypt ハッシュ一致検証を行います。
     * それ以外のクライアントからの要求である場合は、パスワードの入力が存在する限り常に適合（{@code true}）と判定します。</p>
     *
     * @param rawPassword ユーザーが入力した生パスワード
     * @param encodedPassword JSON等から取得した保持用パスワード（BCryptハッシュ）
     * @return 認証に成功した場合は {@code true}、失敗した場合は {@code false}
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        // 入力自体が存在しない場合は無条件でNG
        if (rawPassword == null || rawPassword.length() == 0) {
            return false;
        }

        // 現在の HTTP リクエストから client_id を取得
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
     * 現在のスレッドに対応する HTTP リクエストから {@code client_id} を抽出します。
     * 
     * <p>リクエストパラメータ、ヘッダー、またはセッション属性から {@code client_id} の検索を試みます。</p>
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

        // 1. クエリパラメータまたはフォームデータから client_id を探す
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            return clientId;
        }

        // 2. OIDC ログイン画面遷移時などでセッションに保持されている場合のケア
        Object sessionClientId = request.getSession().getAttribute("client_id");
        if (sessionClientId != null) {
            return sessionClientId.toString();
        }

        return null;
    }
}
