package com.uou.security2.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        //토큰:코스
        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth : " + headerAuth);
            System.out.println("필터3");

            if(headerAuth != null){
                System.out.println("필터 3 인증이 되었음");
                chain.doFilter(req, res); //다음 필터를 타게 해줌
            }else{
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
                System.out.println("필터 3 인증 안됨");
            }
        }
    }
}
