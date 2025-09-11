package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import com.google.common.net.HttpHeaders;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.constant.MediaType;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.scope.AuthFigmaScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.TokenUtils;
import me.zhyd.oauth.utils.UrlBuilder;

/**
 * Figma登录
 *
 * @author xiangqian
 * @since 1.16.6
 */
public class AuthFigmaRequest extends AuthDefaultRequest {
    public AuthFigmaRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FIGMA);
    }

    public AuthFigmaRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FIGMA, authStateCache);
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthFigmaScope.values())))
                .build();
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        HttpHeader header = new HttpHeader()
                .add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED)
                .add(HttpHeaders.AUTHORIZATION, TokenUtils.basic(config.getClientId(), config.getClientSecret()));

        String response = new HttpUtils(config.getHttpConfig()).post(super.accessTokenUrl(authCallback.getCode()), null, header, true).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);

        this.checkResponse(accessTokenObject);

        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .refreshToken(accessTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .scope(accessTokenObject.getString(Keys.OAUTH2_SCOPE))
                .userId(accessTokenObject.getString(Keys.VARIANT__USER_ID))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken authToken) {
        HttpHeader header = new HttpHeader().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
        String response = new HttpUtils(config.getHttpConfig()).post(this.refreshTokenUrl(authToken.getRefreshToken()), null, header, false).getBody();
        JSONObject dataObj = JSONObject.parseObject(response);

        this.checkResponse(dataObj);

        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(AuthToken.builder()
                        .accessToken(dataObj.getString(Keys.OAUTH2_ACCESS_TOKEN))
                        .openId(dataObj.getString(Keys.VARIANT__OPEN_ID))
                        .expireIn(dataObj.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                        .refreshToken(dataObj.getString(Keys.OAUTH2_REFRESH_TOKEN))
                        .scope(dataObj.getString(Keys.OAUTH2_SCOPE))
                        .build())
                .build();

    }

    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam(Keys.OAUTH2_CLIENT_ID, config.getClientId())
                .queryParam(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2_REFRESH_TOKEN, refreshToken)
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        HttpHeader header = new HttpHeader().add(HttpHeaders.AUTHORIZATION, TokenUtils.bearer(authToken.getAccessToken()));
        String response = new HttpUtils(config.getHttpConfig()).get(super.userInfoUrl(authToken), null, header, false).getBody();
        JSONObject dataObj = JSONObject.parseObject(response);

        this.checkResponse(dataObj);

        return AuthUser.builder()
                .rawUserInfo(dataObj)
                .uuid(dataObj.getString(Keys.ID))
                .username(dataObj.getString("handle"))
                .avatar(dataObj.getString("img_url"))
                .email(dataObj.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .token(authToken)
                .source(source.toString())
                .build();
    }


    /**
     * 校验响应结果
     *
     * @param object 接口返回的结果
     */
    private void checkResponse(JSONObject object) {
        if (object.containsKey(Keys.ERROR)) {
            throw new AuthException(object.getString(Keys.ERROR) + ":" + object.getString(Keys.MESSAGE));
        }
    }
}
