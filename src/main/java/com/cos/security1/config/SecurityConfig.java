package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됩니다.
//내가 이제부터 등록할 필터가 기본 필터체인에 통보가 됨
public class SecurityConfig{

//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable();
//        http.authorizeRequests()
//                .antMatchers("/user/*").authenticated()
//                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN' or hasRole('ROLE_MANAGER')")
//                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN')")
//                .anyRequest().permitAll()

//    }

    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    //SecurityFilterChain은 보안 필터의 체인을 나타내며, Spring Security가 모든 HTTP 요청을 처리할 때 사용하는 필터 체인을 구성합니다. http.build()를 호출하면 이 체인이 완성되고 반환됩니다.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                        authorize -> authorize
                                // "/user/*" 경로에 대한 요청은 인증된 사용자만 접근할 수 있습니다.
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
                        // 로그인 성공 후 리디렉션할 경로를 설정합니다.
                        .defaultSuccessUrl("/home", true)
                        // 로그인 실패 시 리디렉션할 경로를 설정합니다.
                        .failureUrl("/login?error")
                        // 로그인 페이지와 로그인 요청 URL에 대한 접근을 허용합니다.
                        .permitAll()
                );

        //이 메서드는 현재까지 구성된 HttpSecurity 객체를 빌드하여 최종적인 SecurityFilterChain을 생성합니다. 이 필터 체인은 Spring Security가 HTTP 요청을 처리할 때 적용됩니다.
        return http.build();
    }
}
