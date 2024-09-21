package com.uou.security2.config.auth;

import com.uou.security2.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Data
public class PrincipalDetails implements UserDetails {

        private User user;

        public PrincipalDetails(User user) {
            this.user = user;
        };

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            user.getRoleList().forEach(r -> {
                authorities.add(() -> r);
            });
        return authorities;
    }

    @Override
        public String getPassword() {
            return user.getPassword();
        }

        @Override
        public String getUsername() {
            return user.getUsername();
        }

        // 계정이 만료되지 않았는지 리턴한다. (true: 만료안됨)
        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        // 계정이 잠기지 않았는지 리턴한다. (true: 잠기지 않음)
        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        // 비밀번호가 만료되지 않았는지 리턴한다. (true: 만료안됨)
        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        // 계정이 활성화(사용가능)인지 리턴한다. (true: 활성화)
        @Override
        public boolean isEnabled() {
            return true;
        }
}
