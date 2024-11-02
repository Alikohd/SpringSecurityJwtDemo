package example.oleevych.springsecurityjwtdemo.controller;

import example.oleevych.springsecurityjwtdemo.dto.JwtRefreshDto;
import example.oleevych.springsecurityjwtdemo.dto.SignInDto;
import example.oleevych.springsecurityjwtdemo.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody SignInDto signInDto) {
        return authService.verify(signInDto);
    }

    @PostMapping("/token")
    public ResponseEntity<?> getNewAccessToken(@RequestBody JwtRefreshDto refreshToken) {
        return authService.getAccessToken(refreshToken.getRefreshToken());
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> getNewRefreshToken(@RequestBody JwtRefreshDto refreshToken) {
        return authService.refreshTokens(refreshToken.getRefreshToken());
    }
}
