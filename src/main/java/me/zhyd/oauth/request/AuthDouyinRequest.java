package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthDouyinScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.UrlBuilder;


/**
 * 抖音登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.4.0
 */
public class AuthDouyinRequest extends AuthDefaultRequest {

    public AuthDouyinRequest(AuthConfig config) {
        super(config, AuthDefaultSource.DOUYIN);
    }

    public AuthDouyinRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.DOUYIN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getCode()));
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String response = doGetUserInfo(authToken);
        JSONObject userInfoObject = JSONObject.parseObject(response);
        this.checkResponse(userInfoObject);
        JSONObject object = userInfoObject.getJSONObject("data");
        authToken.setUnionId(object.getString("union_id"));
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString("union_id"))
                .username(object.getString("nickname"))
                .nickname(object.getString("nickname"))
                .avatar(object.getString("avatar"))
                .remark(object.getString("description"))
                .gender(AuthUserGender.getRealGender(object.getString("gender")))
                .location(String.format("%s %s %s", object.getString("country"), object.getString("province"), object.getString("city")))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    @Override
    public AuthResponse<AuthToken> refresh(AuthToken oldToken) {
        return AuthResponse.<AuthToken>builder()
                .code(AuthResponseStatus.SUCCESS.getCode())
                .data(getToken(refreshTokenUrl(oldToken.getRefreshToken())))
                .build();
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        String message = object.getString("message");
        JSONObject data = object.getJSONObject("data");
        int errorCode = data.getIntValue("error_code");
        if ("error".equals(message) || errorCode != 0) {
            throw new AuthException(errorCode, data.getString("description"));
        }
    }

    /**
     * 获取token，适用于获取access_token和刷新token
     *
     * @param accessTokenUrl 实际请求token的地址
     * @return token对象
     */
    private AuthToken getToken(String accessTokenUrl) {
        String response = new HttpUtils(config.getHttpConfig()).post(accessTokenUrl).getBody();
        JSONObject object = JSONObject.parseObject(response);
        this.checkResponse(object);
        JSONObject dataObj = object.getJSONObject("data");
        return AuthToken.builder()
                .accessToken(dataObj.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .openId(dataObj.getString("open_id"))
                .expireIn(dataObj.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .refreshToken(dataObj.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .refreshTokenExpireIn(dataObj.getIntValue("refresh_expires_in"))
                .scope(dataObj.getString(Keys.OAUTH2_SCOPE))
                .build();
    }

    /**
     * 返回带{@code state}参数的授权url，授权回调时会带上这个{@code state}
     *
     * @param state state 验证授权流程的参数，可以防止csrf
     * @return 返回授权地址
     * @since 1.9.3
     */
    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(source.authorize())
                .queryParam(Keys.OAUTH2_RESPONSE_TYPE, Keys.OAUTH2_CODE)
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2_REDIRECT_URI, config.getRedirectUri())
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(",", true, AuthScopeUtils.getDefaultScopes(AuthDouyinScope.values())))
                .queryParam(Keys.OAUTH2_STATE, getRealState(state))
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param code oauth的授权码
     * @return 返回获取accessToken的url
     */
    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
                .queryParam(Keys.OAUTH2_CODE, code)
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2_CLIENT_SECRET, config.getClientSecret())
                .queryParam(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE)
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken oauth返回的token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2_ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("open_id", authToken.getOpenId())
                .build();
    }

    /**
     * 返回获取accessToken的url
     *
     * @param refreshToken oauth返回的refreshtoken
     * @return 返回获取accessToken的url
     */
    @Override
    protected String refreshTokenUrl(String refreshToken) {
        return UrlBuilder.fromBaseUrl(source.refresh())
                .queryParam("client_key", config.getClientId())
                .queryParam(Keys.OAUTH2_REFRESH_TOKEN, refreshToken)
                .queryParam(Keys.OAUTH2_GRANT_TYPE, Keys.OAUTH2_REFRESH_TOKEN)
                .build();
    }
}
