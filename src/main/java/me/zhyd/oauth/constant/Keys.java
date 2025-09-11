package me.zhyd.oauth.constant;

import com.alibaba.fastjson2.JSONObject;
import me.zhyd.oauth.utils.StringUtils;

/**
 * <p>Description: 字符串常量 </p>
 *
 * @author : gengwei.zheng
 * @date : 2025/9/11 11:22
 */
public interface Keys {

    String OAUTH2_ACCESS_TOKEN = "access_token";
    String OAUTH2_CLIENT_ID = "client_id";
    String OAUTH2_CLIENT_SECRET = "client_secret";
    String OAUTH2_CODE = "code";
    String OAUTH2_EXPIRES_IN = "expires_in";
    String OAUTH2_GRANT_TYPE = "grant_type";
    String OAUTH2_REDIRECT_URI = "redirect_uri";
    String OAUTH2_REFRESH_TOKEN = "refresh_token";
    String OAUTH2_RESPONSE_TYPE = "response_type";
    String OAUTH2_SCOPE = "scope";
    String OAUTH2_STATE = "state";
    String OAUTH2_TOKEN_TYPE = "token_type";
    String OIDC_ID_TOKEN = "id_token";

    String OAUTH2_GRANT_TYPE__AUTHORIZATION_CODE = "authorization_code";

    String OAUTH2_SCOPE__ADDRESS = "address";
    String OAUTH2_SCOPE__EMAIL = "email";
    String OAUTH2_SCOPE__OPENID = "openid";
    String OAUTH2_SCOPE__PHONE = "phone";
    String OAUTH2_SCOPE__PROFILE = "profile";


    String DATA = "data";
    String DESCRIPTION = "description";
    String ERROR = "error";
    String LOCATION = "location";
    String MESSAGE = "message";
    String NAME = "name";
    String RESULT = "result";
    String URL = "url";


    String ID = "id";
    String UID = "uid";
}
