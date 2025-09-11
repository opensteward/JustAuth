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
import me.zhyd.oauth.enums.scope.AuthWeiboScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.*;


/**
 * 微博登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.0.0
 */
public class AuthWeiboRequest extends AuthDefaultRequest {

    public AuthWeiboRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WEIBO);
    }

    public AuthWeiboRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WEIBO, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        if (accessTokenObject.containsKey(Keys.ERROR)) {
            throw new AuthException(accessTokenObject.getString(Keys.ERROR_DESCRIPTION));
        }
        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .uid(accessTokenObject.getString(Keys.UID))
                .openId(accessTokenObject.getString(Keys.UID))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String accessToken = authToken.getAccessToken();
        String uid = authToken.getUid();
        String oauthParam = String.format("uid=%s&access_token=%s", uid, accessToken);

        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(HttpHeaders.AUTHORIZATION, TokenUtils.oauth2(oauthParam));
        httpHeader.add("API-RemoteIP", IpUtils.getLocalIp());
        String userInfo = new HttpUtils(config.getHttpConfig())
                .get(userInfoUrl(authToken), null, httpHeader, false).getBody();
        JSONObject object = JSONObject.parseObject(userInfo);
        if (object.containsKey(Keys.ERROR)) {
            throw new AuthException(object.getString(Keys.ERROR));
        }
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString(Keys.ID))
                .username(object.getString(Keys.NAME))
                .avatar(object.getString("profile_image_url"))
                .blog(StringUtils.isEmpty(object.getString(Keys.URL)) ? "https://weibo.com/" + object.getString("profile_url") : object
                        .getString(Keys.URL))
                .nickname(object.getString("screen_name"))
                .location(object.getString(Keys.LOCATION))
                .remark(object.getString(Keys.DESCRIPTION))
                .gender(AuthUserGender.getRealGender(object.getString(Keys.GENDER)))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken authToken
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2_ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam(Keys.UID, authToken.getUid())
                .build();
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(super.authorize(state))
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthWeiboScope.values())))
                .build();
    }

    @Override
    public AuthResponse revoke(AuthToken authToken) {
        String response = doGetRevoke(authToken);
        JSONObject object = JSONObject.parseObject(response);
        if (object.containsKey(Keys.ERROR)) {
            return AuthResponse.builder()
                    .code(AuthResponseStatus.FAILURE.getCode())
                    .msg(object.getString(Keys.ERROR))
                    .build();
        }
        // 返回 result = true 表示取消授权成功，否则失败
        AuthResponseStatus status = object.getBooleanValue(Keys.RESULT) ? AuthResponseStatus.SUCCESS : AuthResponseStatus.FAILURE;
        return AuthResponse.builder().code(status.getCode()).msg(status.getMsg()).build();
    }
}
