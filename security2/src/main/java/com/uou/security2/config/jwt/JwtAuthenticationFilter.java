package com.uou.security2.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uou.security2.config.auth.PrincipalDetails;
import com.uou.security2.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
import java.util.Date;

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

        User user;
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

            ObjectMapper om = new ObjectMapper(); // JSON 데이터를 파싱해줌
            user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);


            //id pwdw 일치하면 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨
            // DB에 있는 username과 password가 일치한다.
            // authenticationManager가 로그인을 진행하면 PrincipalDetailsService가 호출이 되고
            // loadUserByUsername() 함수가 실행이 됨.
            // 그 후에 PrincipalDetails를 세션에 담고 JWT 토큰을 만들어서 응답해주면 됨
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            //authentication 객체가 session 영역에 저장이 되어
            // 있음. => 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername()); // 로그인이 정상적으로 되었는지 확인
            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리때문에 session에 넣어줌

            // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임.");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니고 Hash암호방식
        String jwtToken = JWT.create() // pom.xml
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+(JwtProperties.EXPIRATION_TIME))) //1분 * 10
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // HMAC512는 시크릿 키가 있어야 함.

        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}
