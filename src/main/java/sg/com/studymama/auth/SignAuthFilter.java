package sg.com.studymama.auth;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.SortedMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.alibaba.fastjson.JSONObject;

import lombok.extern.slf4j.Slf4j;
import sg.com.studymama.util.HttpUtils;
import sg.com.studymama.util.SignUtil;

@Slf4j
@Component 
public class SignAuthFilter implements Filter {
	private static final Logger LOG = LoggerFactory.getLogger(SignAuthFilter.class);
	
	 static final String FAVICON = "/favicon.ico";

	    @Override
	    public void init(FilterConfig filterConfig) {

	        LOG.info("initial SignAuthFilter");
	    }

	    @Override
	    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

	        HttpServletResponse response = (HttpServletResponse) res;
	        // 防止流读取一次后就没有了, 所以需要将流继续写出去
	        HttpServletRequest request = (HttpServletRequest) req;
	        HttpServletRequest requestWrapper = new BodyReaderHttpServletRequestWrapper(request);
	        //获取图标不需要验证签名
	        if (FAVICON.equals(requestWrapper.getRequestURI())) {
	            chain.doFilter(request, response);
	        } else {
	            //获取全部参数(包括URL和body上的)
	            SortedMap<String, String> allParams = HttpUtils.getAllParams(requestWrapper);
	            //对参数进行签名验证
	            boolean isSigned = SignUtil.verifySign(allParams);
	            if (isSigned) {
	                LOG.info("Sign parameters verified successed!");
	                chain.doFilter(requestWrapper, response);
	            } else {
	                LOG.info("The parameter verifaction is wrong.");
	                //校验失败返回前端
	                response.setCharacterEncoding("UTF-8");
	                response.setContentType("application/json; charset=utf-8");
	                PrintWriter out = response.getWriter();
	               JSONObject resParam = new JSONObject();
	                resParam.put("msg", "The parameters verifaction is not passed ...");
	                resParam.put("success", "false");
	                out.append(resParam.toJSONString());
	            }
	        }
	    }

	    @Override
	    public void destroy() {

	        LOG.info("destory SignAuthFilter");
	    }	
}
