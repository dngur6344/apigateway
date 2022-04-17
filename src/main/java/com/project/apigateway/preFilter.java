package com.project.apigateway;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.project.apigateway.security.JwtTokenProvider;
import io.jsonwebtoken.Jwts;
import org.apache.http.HttpStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestParam;

import javax.annotation.PostConstruct;
import java.util.Base64;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_DECORATION_FILTER_ORDER;
import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

public class preFilter extends ZuulFilter {
    @Value("${security.oauth2.resource.jwt.key-value}")
    private String secretKey;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    @Override
    public String filterType(){
        return PRE_TYPE;
    }

    @Override
    public int filterOrder(){
        return 1;
    }
    @Override
    public boolean shouldFilter(){
        return true;
    }
    @Override
    public Object run(){
        RequestContext context = RequestContext.getCurrentContext();

        if(context.getRequest().getRequestURI().split("/")[1].equals("auth")){
            //로그인하는 경우엔 Authorization header가 없어도 된다.
            return null;
        }
        if(context.getRequest().getHeader("Authorization")==null||
                Jwts.parser().setSigningKey(secretKey).parseClaimsJws(context.getRequest().getHeader("Authorization")).getBody().getSubject()==null){
            context.unset();
            context.setResponseStatusCode(HttpStatus.SC_UNAUTHORIZED);
        }
        else{
            System.out.println("Pre-filter pass");
        }
        return null;
    }
}
