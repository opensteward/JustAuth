package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.enums.scope.AuthFacebookScope;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.GlobalAuthUtils;
import me.zhyd.oauth.utils.UrlBuilder;

/**
 * Facebook登录
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @since 1.3.0
 */
public class AuthFacebookRequest extends AuthDefaultRequest {

    public AuthFacebookRequest(AuthConfig config) {
        super(config, AuthDefaultSource.FACEBOOK);
    }

    public AuthFacebookRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.FACEBOOK, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        this.checkResponse(accessTokenObject);
        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .tokenType(accessTokenObject.getString(Keys.OAUTH2_TOKEN_TYPE))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);
        JSONObject object = JSONObject.parseObject(userInfo);
        this.checkResponse(object);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString(Keys.ID))
                .username(object.getString(Keys.NAME))
                .nickname(object.getString(Keys.NAME))
                .blog(object.getString("link"))
                .avatar(getUserPicture(object))
                .location(object.getString("locale"))
                .email(object.getString(Keys.OAUTH2_SCOPE__EMAIL))
                .gender(AuthUserGender.getRealGender(object.getString("gender")))
                .token(authToken)
                .source(source.toString())
                .build();
    }

    private String getUserPicture(JSONObject object) {
        String picture = null;
        if (object.containsKey("picture")) {
            JSONObject pictureObj = object.getJSONObject("picture");
            pictureObj = pictureObj.getJSONObject(Keys.DATA);
            if (null != pictureObj) {
                picture = pictureObj.getString(Keys.URL);
            }
        }
        return picture;
    }

    /**
     * 返回获取userInfo的url
     *
     * @param authToken 用户token
     * @return 返回获取userInfo的url
     */
    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
                .queryParam(Keys.OAUTH2_ACCESS_TOKEN, authToken.getAccessToken())
                .queryParam("fields", "id,name,birthday,gender,hometown,email,devices,picture.width(400),link")
                .build();
    }

    @Override
    protected void checkConfig(AuthConfig config) {
        super.checkConfig(config);
        // facebook的回调地址必须为https的链接
        if (AuthDefaultSource.FACEBOOK == source && !GlobalAuthUtils.isHttpsProtocol(config.getRedirectUri())) {
            // Facebook's redirect uri must use the HTTPS protocol
            throw new AuthException(AuthResponseStatus.ILLEGAL_REDIRECT_URI, source);
        }
    }

    /**
     * 检查响应内容是否正确
     *
     * @param object 请求响应内容
     */
    private void checkResponse(JSONObject object) {
        if (object.containsKey(Keys.ERROR)) {
            throw new AuthException(object.getJSONObject(Keys.ERROR).getString(Keys.MESSAGE));
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
                .queryParam(Keys.OAUTH2_SCOPE, this.getScopes(",", false, AuthScopeUtils.getDefaultScopes(AuthFacebookScope.values())))
                .build();
    }
}
