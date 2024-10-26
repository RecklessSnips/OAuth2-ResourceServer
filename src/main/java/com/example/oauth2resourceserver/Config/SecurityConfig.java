package com.example.oauth2resourceserver.Config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Value("${jwksUri}")
    private String jwksUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return
                http
                .cors(withDefaults())
                .authorizeHttpRequests(
                    auth -> auth.anyRequest().authenticated()
                )
                .oauth2ResourceServer(
                    oauth2 -> oauth2.jwt(
                        jwt -> jwt.decoder(jwtDecoder())
                    )  // 使用自定义 JwtDecoder
                )
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // 配置你的 JWK Set URI
        return NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); // 允许发送 Cookie
        config.addAllowedOrigin("http://localhost:5173");
        config.addAllowedHeader("*"); // 允许所有请求头
        config.addAllowedMethod("*"); // 允许所有 HTTP 方法（GET, POST, PUT, DELETE, OPTIONS, etc.）

        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
