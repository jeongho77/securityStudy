package com.uou.security2.filter;

import jakarta.servlet.*;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
public class MyFilter2 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("필터2");
        chain.doFilter(request, response);
    }
}
