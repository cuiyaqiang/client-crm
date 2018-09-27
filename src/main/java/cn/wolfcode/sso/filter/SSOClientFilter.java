package cn.wolfcode.sso.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;

import cn.wolfcode.sso.util.HttpUtil;
import cn.wolfcode.sso.util.SSOClientUtil;

public class SSOClientFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        HttpSession session = req.getSession();
        //1.判断是否有局部的会话
        Boolean isLogin = (Boolean) session.getAttribute("isLogin");
        if(isLogin!=null && isLogin){
            //有局部会话,直接放行.
            chain.doFilter(request, response);
            return;
        }
        //判断地址栏中是否有携带token参数.
        String token = req.getParameter("token");
        if(StringUtils.isNoneBlank(token)){
            //token信息不为null,说明地址中包含了token,拥有令牌.
            //判断token信息是否由认证中心产生的.
            String httpURL = SSOClientUtil.SERVER_URL_PREFIX+"/verify";
            Map<String,String> params = new HashMap<String,String>();
            params.put("token", token);
            params.put("clientUrl", SSOClientUtil.getClientLogOutUrl());
            params.put("jsessionid", session.getId());
            try {
                String isVerify = HttpUtil.sendHttpRequest(httpURL, params);
                if("true".equals(isVerify)){
                    //如果返回的字符串是true,说明这个token是由统一认证中心产生的.
                    //创建局部的会话.
                    session.setAttribute("isLogin", true);
                    //放行该次的请求
                    chain.doFilter(request, response);
                    return;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        //没有局部会话,重定向到统一认证中心,检查是否有其他的系统已经登录过.
        // http://www.sso.com:8443/checkLogin?redirectUrl=http://www.crm.com:8088
        SSOClientUtil.redirectToSSOURL(req, resp);
    }

    @Override
    public void destroy() {

    }

}

