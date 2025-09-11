package me.zhyd.oauth.utils;

/**
 * <p>Description: Token 工具类 </p>
 *
 * @author : gengwei.zheng
 * @date : 2025/9/11 11:37
 */
public class TokenUtils {

    private static final String BEARER = "Bearer ";
    private static final String BASIC = "Basic ";
    private static final String OAUTH2 = "OAuth2 ";
    private static final String TOKEN = "token ";

    private static String create(String prefix, String accessToken) {
        return prefix + accessToken;
    }

    /**
     * 转成完整的 Http Authorization 头携带 Basic Token 格式
     *
     * @param accessToken Token
     * @return 可放入 Authorization 头的 Basic 类型 Token
     */
    public static String basic(String accessToken) {
        return create(BASIC, accessToken);
    }

    /**
     * 将 ClientId 和 ClientSecret 组合成可以放入 Http Authorization 头的 Basic Token 格式
     *
     * @param clientId     OAuth2 ClientId
     * @param clientSecret OAuth2 ClientId
     * @return 可放入 Authorization 头的 Basic 类型 Token
     */
    public static String basic(String clientId, String clientSecret) {
        String token = Base64Utils.encode((clientId + ":" + clientSecret).getBytes());
        return basic(token);
    }

    /**
     * 转成完整的 Http Authorization 头携带 Bearer Token 格式
     *
     * @param accessToken Token
     * @return 可放入 Authorization 头的 Bearer 类型 Token
     */
    public static String bearer(String accessToken) {
        return create(BEARER, accessToken);
    }

    /**
     * 转成完整的 Http Authorization 头携带的以 OAuth2 为前缀的 Token 格式
     *
     * @param accessToken Token
     * @return 可放入 Authorization 头的 OAuth2 类型 Token
     */
    public static String oauth2(String accessToken) {
        return create(OAUTH2, accessToken);
    }

    /**
     * 转成完整的 Http Authorization 头携带的以 token 为前缀的 Token 格式
     *
     * @param accessToken Token
     * @return 可放入 Authorization 头的 token 类型 Token
     */
    public static String token(String accessToken) {
        return create(TOKEN, accessToken);
    }

}
