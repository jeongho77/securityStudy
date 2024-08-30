package com.cos.security1.config.auth;

// 시큐리티가 /login 주소요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 session에 만들어줍니다.
// 세션은 똑같은데 자신만의 세션 공간을 가짐 키값으로 구분함!! (Security ContextHolder)
//(Security ContextHolder) 여기에 들어갈수 있는 정보는 오브젝트 형식이 정해져있음 => Authentication 타입 객체
// Authentication 안에는 User 정보가 있어야 됨 이것도 정해져있는데 user 오브젝트의 타입은 => UserDetails 타입 객체

//Security Session => Authentication => UserDetails 를 꺼내면 유저 오브젝트에 접근할수있음


import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; //콤포지션
    private Map<String, Object> attributes;

    //일바 ㄴ로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.attributes = attributes;
        this.user = user;
    }

    //해당 User의 권한을 리턴하는 곳!!
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();

        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    //계정 기간이 지났는지
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //1년동안 회원이 로그인을 안하면 휴먼계정으로 하기로 함.
    //대충 entity에 loginDate 값 저장후 1년 시간 빼면 맞으면 false 하면댬
    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
//        return attributes.get("sub");
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
