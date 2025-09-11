package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.google.common.net.HttpHeaders;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.TokenUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Teambition授权登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.9.0
 */
public class AuthTeambitionRequest extends AuthDefaultRequest {

    public AuthTeambitionRequest(AuthConfig config) {
        super(config, AuthDefaultSource.TEAMBITION);
    }

    public AuthTeambitionRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.TEAMBITION, authStateCache);
    }

    /**
     * @param authCallback 回调返回的参数
     * @return 所有信息
     */
    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> form = new HashMap<>(7);
        form.put(Keys.OAUTH2_CLIENT_ID, config.getClientId());
        form.put(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret());
        form.put(Keys.OAUTH2_CODE, authCallback.getCode());
        form.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_CODE);

        String response = new HttpUtils(config.getHttpConfig()).post(source.accessToken(), form, false).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .refreshToken(accessTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.oauth2(accessToken));

        String response = new HttpUtils(config.getHttpConfig())
                .get(source.userInfo(), null, httpHeader, false).getBody();
        JSONObject object = JSONObject.parseObject(response);

        this.checkResponse(object);

        authToken.setUid(object.getString("_id"));

        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString("_id"))
                .username(object.getString(Keys.NAME))
                .nickname(object.getString(Keys.NAME))
                .avatar(object.getString("avatarUrl"))
                .blog(object.getString("website"))
                .location(object.getString(Keys.LOCATION))
                .email(object.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        String uid = oldToken.getUid();
        String refreshToken = oldToken.getRefreshToken();

        Map<String, String> form = new HashMap<>(4);
        form.put("_userId", uid);
        form.put(Keys.OAUTH2_REFRESH_TOKEN, refreshToken);
        String response = new HttpUtils(config.getHttpConfig()).post(source.refresh(), form, false).getBody();
        JSONObject refreshTokenObject = JSONObject.parseObject(response);

        this.checkResponse(refreshTokenObject);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(refreshTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                        .refreshToken(refreshTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                        .build())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if ((object.containsKey(Keys.MESSAGE) && object.containsKey(Keys.NAME))) {
            throw new AuthException(object.getString(Keys.NAME) + ", " + object.getString(Keys.MESSAGE));
        }
    }
}
