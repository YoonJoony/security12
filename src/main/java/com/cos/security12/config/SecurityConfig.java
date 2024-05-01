package com.cos.security12.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록이 된다.
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured... : 컨트롤러에 단일 권한 접속 허가
                                                                    // prePost... : 컨트롤러에 다중 권한 접속 허가
public class SecurityConfig {
    // 패스워드 인코딩(암호화)
    @Bean
    public BCryptPasswordEncoder encoderPwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("/user/**").authenticated()
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()

        );
        http.formLogin((form) ->             // 폼 로그인을 사용하며, 로그인 페이지와 관련된 설정을 함.
                form
                        .loginPage("/loginForm") // 인증이 필요한 페이지에 대한 모든 접근은 해당 페이지로 리다이렉트 된다.
                        .permitAll()         // 모든 사용자가 로그인 페이지에 접근할 수 있도록 한다.
                        .loginProcessingUrl("/login") // 시큐리티가 이 주소를 낚아채서 대신 로그인을 진행한다.
                        .defaultSuccessUrl("/") // 로그인 완료 시 기본 주소
        );
        return http.build();
    }
}
