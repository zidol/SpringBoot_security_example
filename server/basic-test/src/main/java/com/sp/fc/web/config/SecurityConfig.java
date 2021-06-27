package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)//프리 포스트로 권한 체크를 하겠다 선언
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //허용하는 유저를 간단히 만들기위해
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                .username("user2")
                    .password(passwordEncoder().encode("2222"))
                    .roles("USER")
                ).withUser(User.builder()
                    .username("admin")
                    .password(passwordEncoder().encode("3333"))
                    .roles("ADMIN"))
                ;

    }

    /**
     * 패스워드를 인코딩
     * @return
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) ->
                requests.antMatchers("/").permitAll()   // "/" 해당 url엔 모든 사람에게 접근 허용
                        .anyRequest().authenticated()
        );
        http.formLogin();
        http.httpBasic();
    }
}
