package me.zhyd.oauth.request;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.constant.Keys;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;

/**
 * 阿里云登录
 *
 * @author snippet0809 (https://github.com/snippet0809)
 * @since 1.15.5
 */
public class AuthAliyunRequest extends AuthDefaultRequest {

    public AuthAliyunRequest(AuthConfig config) {
        super(config, AuthDefaultSource.ALIYUN);
    }

    public AuthAliyunRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.ALIYUN, authStateCache);
    }

    @Override
    public AuthToken getAccessToken(AuthCallback authCallback) {
        String response = doPostAuthorizationCode(authCallback.getCode());
        JSONObject accessTokenObject = JSONObject.parseObject(response);
        return AuthToken.builder()
                .accessToken(accessTokenObject.getString(Keys.OAUTH2_ACCESS_TOKEN))
                .expireIn(accessTokenObject.getIntValue(Keys.OAUTH2_EXPIRES_IN))
                .tokenType(accessTokenObject.getString(Keys.OAUTH2_TOKEN_TYPE))
                .idToken(accessTokenObject.getString(Keys.OIDC_ID_TOKEN))
                .refreshToken(accessTokenObject.getString(Keys.OAUTH2_REFRESH_TOKEN))
                .build();
    }

    @Override
    public AuthUser getUserInfo(AuthToken authToken) {
        String userInfo = doGetUserInfo(authToken);
        JSONObject object = JSONObject.parseObject(userInfo);
        return AuthUser.builder()
                .rawUserInfo(object)
                .uuid(object.getString("sub"))
                .username(object.getString("login_name"))
                .nickname(object.getString(Keys.NAME))
                .gender(AuthUserGender.UNKNOWN)
                .token(authToken)
                .source(source.toString())
                .build();
    }

}
