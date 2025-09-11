package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthProginnScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * 程序员客栈
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.16.2
 */
public class AuthProginnRequest extends AuthDefaultRequest {

    public AuthProginnRequest(AuthConfig config) {
        super(config, AuthDefaultSource.PROGINN);
    }

    public AuthProginnRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.PROGINN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> params = new HashMap<>();
        params.put(Keys.OAUTH2_CODE, authCallback.getCode());
        params.put(Keys.OAUTH2_CLIENT_ID, config.getClientId());
        params.put(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret());
        params.put(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE);
        params.put(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri());
        String response = new HttpUtils(config.getHttpConfig()).post(AuthDefaultSource.PROGINN.accessToken(), params, false).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .refreshToken(accessTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .uid(accessTokenObject.getString(Keys.UID))
                .tokenType(accessTokenObject.getString(Keys.OAUTH2_TOKEN_TYPE))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);
        JSONObject object = JSONObject.parseObject(userInfo);
        this.checkResponse(object);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString(Keys.UID))
                .username(object.getString(Keys.NICKNAME))
                .nickname(object.getString(Keys.NICKNAME))
                .avatar(object.getString(Keys.AVATAR))
                .email(object.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if (object.containsKey(Keys.ERROR)) {
            throw new AuthException(object.getString(Keys.ERROR_DESCRIPTION));
        }
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(" ", true, AuthScopeUtils.getDefaultScopes(AuthProginnScope.values())))
                .build();
    }
}
