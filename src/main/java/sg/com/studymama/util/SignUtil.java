package sg.com.studymama.util;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.DigestUtils;
import org.springframework.util.StringUtils;

import java.util.SortedMap;

@Slf4j
public class SignUtil {
	
	private static final Logger LOG = LoggerFactory.getLogger(SignUtil.class);
	/**
     * @param params 所有的请求参数都会在这里进行排序加密
     * @return 验证签名结果
     */
    public static boolean verifySign(SortedMap<String, String> params) {

        String urlSign = params.get("sign");
        LOG.info("Url Sign : {}", urlSign);
        if (params == null || StringUtils.isEmpty(urlSign)) {
            return false;
        }
        //把参数加密
        String paramsSign = getParamsSign(params);
        LOG.info("Param Sign : {}", paramsSign);
        return !StringUtils.isEmpty(paramsSign) && urlSign.equals(paramsSign);
    }

    /**
     * @param params 所有的请求参数都会在这里进行排序加密
     * @return 得到签名
     */
    public static String getParamsSign(SortedMap<String, String> params) {
        //要先去掉 Url 里的 Sign
        params.remove("sign");
        String paramsJsonStr = JSONObject.toJSONString(params);
        return DigestUtils.md5DigestAsHex(paramsJsonStr.getBytes()).toUpperCase();
    }
}

