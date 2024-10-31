package com.uou.security2.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.uou.security2.config.auth.PrincipalDetails;
import com.uou.security2.model.User;
import com.uou.security2.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안타요.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

        public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
            super(authenticationManager);
//            System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
            this.userRepository = userRepository;
        }

        // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게 됨.
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//            super.doFilterInternal(request, response, chain);
            System.out.println("인증이나 권한이 필요한 주소 요청이 됨");

            String jwtHeader = request.getHeader("Authorization");
            System.out.println("jwtHeader : " + jwtHeader);

            //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
            //header가 있는지 확인
            if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
                chain.doFilter(request, response);
                return;
            }

            //JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
            String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

            String username =
                    JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
            System.out.println("username :" + username);
            // 서명이 정상적으로 됨
            if(username != null) {
                System.out.println("username 정상");
                User userEntity = userRepository.findByUsername(username);

                PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

                // JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
                // 강제로 Authentication 객체를 만들어서 SecurityContext에 접근하게 만듬
                // 그러면 권한이나 인증이 필요한 주소에 접근을 할 수 있음.
                // Authentication 객체를 만들어줄 때 UserDetails 객체를 넣어줘야함.
                // UserDetails는 UserDetailsService를 통해서 리턴받은 객체임.
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

                //세션공간을 찾은거
                //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
            //항상 chain.doFilter(request, response)를 해줘야함.
            //항상 필터 체인을 타게 해줘야함.
            chain.doFilter(request,response);
        }
}
