package com.cos.security1.config;

import com.cos.security1.config.auth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 활성화 ,preAuthorize 활성화
//내가 이제부터 등록할 필터가 기본 필터체인에 통보가 됨
public class SecurityConfig{
    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable();
//        http.authorizeRequests()
//                .antMatchers("/user/*").authenticated()
//                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN' or hasRole('ROLE_MANAGER')")
//                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN')")
//                .anyRequest().permitAll()
//
//    }

    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
//    @Bean
//    public BCryptPasswordEncoder bCryptPasswordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    //SecurityFilterChain은 보안 필터의 체인을 나타내며, Spring Security가 모든 HTTP 요청을 처리할 때 사용하는 필터 체인을 구성합니다. http.build()를 호출하면 이 체인이 완성되고 반환됩니다.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        authorize -> authorize
                                // "/user/*" 경로에 대한 요청은 인증된 사용자만 접근할 수 있습니다. //로그인만되면됨
                                .requestMatchers("/user/**").authenticated()
                                // "/manager/**" 경로에 대한 요청은 "ROLE_ADMIN" 또는 "ROLE_MANAGER" 역할을 가진 사용자만 접근할 수 있습니다.
                                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                // "/admin/**" 경로에 대한 요청은 "ROLE_ADMIN" 역할을 가진 사용자만 접근할 수 있습니다.
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                //위에서 지정된 경로를 제외한 모든 다른 요청은 인증된 사용자만 접근할 수 있도록 설정합니다. 즉, 로그인된 사용자만 접근할 수 있습니다.
                                .anyRequest().permitAll()
                )// 폼 로그인 설정을 추가합니다.
                .formLogin(form -> form
                        // 사용자 정의 로그인 페이지를 설정합니다.
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login")
                        // 로그인 성공 후 리디렉션할 경로를 설정합니다.
                        .defaultSuccessUrl("/") //.defaultSuccessUrl("/", true) 이렇게 무조건 가게할지 아니면 이전에 검색했던 url로 가게 할지 정하는게 가능
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/loginForm")
                                //구글로그인이 완료된 뒤의 후처리가 필요함 근데 이상하게 /user가 들어가짐
                                .userInfoEndpoint(userInfo -> userInfo
                                        .userService(principalOauth2UserService)
                                )

/*                        1. 코드받기(인증)
                          2. 엑세스토큰(권한),
                          3. 사용자프로필정보를 가져오기
                          4-1. 그 정보를 토대로 회원가입을 자동으로 진행시킴
                          4-2. (이메일,전화번호,이름,아이디)쇼핑몰 -> (집주소),백화점몰 -> vip등급,일반등급
                          5.
                          구글 로그인이 완료되면 코드를 받는것이 아님 (엑세스 토큰 + 사용자 프로필정보를 받음)
                          다받아주기때문에 굉장히 편함!
 */

                );

        //이 메서드는 현재까지 구성된 HttpSecurity 객체를 빌드하여 최종적인 SecurityFilterChain을 생성합니다. 이 필터 체인은 Spring Security가 HTTP 요청을 처리할 때 적용됩니다.
        return http.build();
    }
}
