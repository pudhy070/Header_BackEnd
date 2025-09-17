package com.security.test1.controller;

import com.security.test1.dto.ApiResponse;
import com.security.test1.dto.OAuthAttributes;
import com.security.test1.dto.SmsLoginRequest;
import com.security.test1.service.OAuthService;
import com.security.test1.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;
    private final OAuthService oAuthService;

    @Value("${app.frontend.url:http://localhost:5173}")
    private String frontendUrl;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String kakaoClientId;

    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String naverClientId;

    @GetMapping("/google")
    public RedirectView initiateGoogleLogin() {
        log.info("Google OAuth 로그인 시작");

        String googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
                "?client_id=" + googleClientId +
                "&redirect_uri=http://localhost:8080/api/auth/google/callback" +
                "&response_type=code" +
                "&scope=openid+profile+email" +
                "&access_type=offline" +
                "&prompt=consent";

        log.info("Google 인증 URL로 리디렉션: {}", googleAuthUrl);
        return new RedirectView(googleAuthUrl);
    }

    @GetMapping("/google/callback")
    public RedirectView handleGoogleCallback(@RequestParam String code) {
        log.info("Google OAuth 콜백 처리 시작 - code: {}", code);

        try {
            OAuthAttributes oAuthAttributes = oAuthService.processGoogleCallback(code);
            String token = jwtUtil.generateToken(
                    oAuthAttributes.getEmail(),
                    oAuthAttributes.getName(),
                    oAuthAttributes.getPicture()
            );

            log.info("Google 로그인 성공 - email: {}, name: {}",
                    oAuthAttributes.getEmail(), oAuthAttributes.getName());

            String redirectUrl = frontendUrl + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8) + "&status=success";
            return new RedirectView(redirectUrl);

        } catch (Exception e) {
            log.error("Google OAuth 처리 실패", e);
            String redirectUrl = frontendUrl + "?status=error&message=" +
                    URLEncoder.encode("Google 로그인 실패: " + e.getMessage(), StandardCharsets.UTF_8);
            return new RedirectView(redirectUrl);
        }
    }

    @GetMapping("/kakao")
    public RedirectView initiateKakaoLogin() {
        log.info("Kakao OAuth 로그인 시작");

        // URL 인코딩 없이 리디렉션 URI 설정
        String redirectUri = "http://localhost:8080/api/auth/kakao/callback";

        String kakaoAuthUrl = "https://kauth.kakao.com/oauth/authorize" +
                "?client_id=" + kakaoClientId +
                "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&scope=" + URLEncoder.encode("profile_nickname,profile_image,account_email", StandardCharsets.UTF_8);

        log.info("Kakao 인증 URL로 리디렉션: {}", kakaoAuthUrl);
        return new RedirectView(kakaoAuthUrl);
    }

    @GetMapping("/kakao/callback")
    public RedirectView handleKakaoCallback(@RequestParam String code) {
        log.info("Kakao OAuth 콜백 처리 시작 - code: {}", code);

        try {
            OAuthAttributes oAuthAttributes = oAuthService.processKakaoCallback(code);
            String token = jwtUtil.generateToken(
                    oAuthAttributes.getEmail(),
                    oAuthAttributes.getName(),
                    oAuthAttributes.getPicture()
            );

            log.info("Kakao 로그인 성공 - email: {}, name: {}",
                    oAuthAttributes.getEmail(), oAuthAttributes.getName());

            String redirectUrl = frontendUrl + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8) + "&status=success";
            return new RedirectView(redirectUrl);

        } catch (Exception e) {
            log.error("Kakao OAuth 처리 실패", e);
            String redirectUrl = frontendUrl + "?status=error&message=" +
                    URLEncoder.encode("카카오 로그인 실패: " + e.getMessage(), StandardCharsets.UTF_8);
            return new RedirectView(redirectUrl);
        }
    }

    @GetMapping("/naver")
    public RedirectView initiateNaverLogin() {
        log.info("Naver OAuth 로그인 시작");

        String state = UUID.randomUUID().toString(); // 랜덤 state 생성
        String redirectUri = URLEncoder.encode("http://localhost:8080/api/auth/naver/callback", StandardCharsets.UTF_8);

        String naverAuthUrl = "https://nid.naver.com/oauth2.0/authorize" +
                "?client_id=" + naverClientId +
                "&response_type=code" +
                "&redirect_uri=" + redirectUri +
                "&state=" + state +
                "&scope=name,email,profile_image";

        log.info("Naver 인증 URL로 리디렉션: {}", naverAuthUrl);
        return new RedirectView(naverAuthUrl);
    }

    @GetMapping("/naver/callback")
    public RedirectView handleNaverCallback(@RequestParam String code, @RequestParam String state) {
        log.info("Naver OAuth 콜백 처리 시작 - code: {}, state: {}", code, state);

        try {
            OAuthAttributes oAuthAttributes = oAuthService.processNaverCallback(code, state);
            String token = jwtUtil.generateToken(
                    oAuthAttributes.getEmail(),
                    oAuthAttributes.getName(),
                    oAuthAttributes.getPicture()
            );

            log.info("Naver 로그인 성공 - email: {}, name: {}",
                    oAuthAttributes.getEmail(), oAuthAttributes.getName());

            String redirectUrl = frontendUrl + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8) + "&status=success";
            return new RedirectView(redirectUrl);

        } catch (Exception e) {
            log.error("Naver OAuth 처리 실패", e);
            String redirectUrl = frontendUrl + "?status=error&message=" +
                    URLEncoder.encode("네이버 로그인 실패: " + e.getMessage(), StandardCharsets.UTF_8);
            return new RedirectView(redirectUrl);
        }
    }

    @PostMapping("/sms")
    public ResponseEntity<ApiResponse> smsLogin(@RequestBody SmsLoginRequest request) {
        log.info("SMS 로그인 요청 - phone: {}", request.getPhone());

        try {
            String token = jwtUtil.generateToken(request.getPhone() + "@sms.com", "SMS User", null);
            ApiResponse response = new ApiResponse(true, "SMS 로그인 성공", Map.of("token", token));

            log.info("SMS 로그인 성공");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("SMS 로그인 실패", e);
            ApiResponse response = new ApiResponse(false, "SMS 로그인 실패: " + e.getMessage(), null);
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<ApiResponse> verifyToken(@RequestParam String token) {
        log.info("토큰 검증 요청");

        if (jwtUtil.validateToken(token)) {
            Map<String, Object> userInfo = Map.of(
                    "email", jwtUtil.extractEmail(token),
                    "name", jwtUtil.extractName(token),
                    "picture", jwtUtil.extractPicture(token)
            );

            log.info("토큰 검증 성공 - email: {}", userInfo.get("email"));
            ApiResponse response = new ApiResponse(true, "토큰이 유효합니다", userInfo);
            return ResponseEntity.ok(response);
        } else {
            log.warn("토큰 검증 실패 - 유효하지 않은 토큰");
            ApiResponse response = new ApiResponse(false, "유효하지 않은 토큰입니다", null);
            return ResponseEntity.status(401).body(response);
        }
    }
}