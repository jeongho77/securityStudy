package com.uou.security2.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.uou.security2.config.auth.PrincipalDetails;
import com.uou.security2.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;

// JWT가 동작하기 위한 필터
// 기존에 UsernamePasswordAuthenticationFilter가 동작하던 로그인 요청시 /login으로 요청하면
// UsernamePasswordAuthenticationFilter가 동작하는데
// /login 요청시에 UsernamePasswordAuthenticationFilter 대신에 JwtAuthenticationFilter가 동작하도록 시큐리티 설정
// 그러기 위해서는 SecurityConfig에 UsernamePasswordAuthenticationFilter 대신에 JwtAuthenticationFilter를 등록
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행하는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도중");

        // 1. username, password 받아서
        try {
//            System.out.println(request.getInputStream().toString()); //주소값 request를 두번 못읽는거같음

            //웹일때는 이걸로하면 됨
//            BufferedReader br = request.getReader();
//            String input = null;
//
//            while((input = br.readLine()) != null) { // input이 null이 아닐때까지 계속 읽어들임
//                System.out.println(input);
//            }

            // JSON으로 받을때
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);


            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session 영역에 저장이 되어
            // 있음. => 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername()); // 로그인이 정상적으로 되었는지 확인

            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
