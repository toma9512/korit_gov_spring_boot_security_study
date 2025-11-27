package com.korit.security_study.config;

import com.korit.security_study.security.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    // 비밀번호를 안전하게 암호화하고, 검증하는 역할
    // 단방향 해시 적용, 복호화 불가능
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    };

    /*
    CORS(Cross-origin Resource Sharing)
    브라우저가 보안상 다른 도메인의 리소스 요청을 제한하는 정책
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        // 요청을 보내는 쪽의 도메인(사이트 주소)을 허용
        corsConfiguration.addAllowedOriginPattern(CorsConfiguration.ALL);
        // 요청을 보내는 쪽에서 Request, Response Header 정보에 대한 제약을 모두 허용
        corsConfiguration.addAllowedHeader(CorsConfiguration.ALL);
        // 요청 보내는 쪽의 메소드들에 대해 모두 허용
        corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);

        // 요청 URL에 대한 CORS 설정을 적용하기 위해 객체
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors(Customizer.withDefaults()); // 위에서 만든 CORS 정책을 security에 적용
        http.csrf(csrf -> csrf.disable());
        /*
        CSRF
        사용자가 의도하지 않은 요청을 공격자가 유도해서 서버에 전달하도록 하는 공격
        JWT 방식 그리고 무상태(Stateless) 방식의 인증을 하기 때문에
        세션도 없고, 쿠키도 없기 때문에 CSRF 공격 자체가 성립되지 않는다.
         */

        // 서버 사이드 렌더링 로그인 방식 비활성화
        http.formLogin(formLogin -> formLogin.disable());
        // HTTP 프로토콜 기본 로그인 방식 비활성화
        http.httpBasic(httpBasic -> httpBasic.disable());
        // 서버 사이드 렌더링 로그아웃 방식 비활성화
        http.logout(logout -> logout.disable());

        // 세션 무상태 방식 변경
        http.sessionManagement(Session -> Session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // 특정 요청 URL에 대한 권한 설정
        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/auth/signup", "/auth/signin").permitAll();
            auth.anyRequest().authenticated();
        });

        return http.build();
    }
}
