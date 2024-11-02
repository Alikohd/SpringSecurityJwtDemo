package example.oleevych.springsecurityjwtdemo.service;

import example.oleevych.springsecurityjwtdemo.dto.JwtResponseDto;
import example.oleevych.springsecurityjwtdemo.dto.SignInDto;
import example.oleevych.springsecurityjwtdemo.exception.AppError;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    public ResponseEntity<?> verify(SignInDto signInDto) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signInDto.getUsername(), signInDto.getPassword()));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new AppError(HttpStatus.UNAUTHORIZED.value(),
                    "Неправильный логин или пароль"), HttpStatus.UNAUTHORIZED);
        }

        UserDetails user = userService.loadUserByUsername(signInDto.getUsername());
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        return ResponseEntity.ok(new JwtResponseDto(accessToken, refreshToken));
    }

    public ResponseEntity<?> getAccessToken(String refreshToken) {
        if (jwtService.validateRefreshToken(refreshToken)) {
            Claims claims = jwtService.getRefreshClaims(refreshToken);
            String username = claims.getSubject();
            UserDetails user = userService.loadUserByUsername(username);
            return ResponseEntity.ok(jwtService.generateAccessToken(user));
        }
        return new ResponseEntity<>(new AppError(HttpStatus.UNAUTHORIZED.value(),
                "Invalid refresh token"), HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> refreshTokens(String refreshToken) {
        if (jwtService.validateRefreshToken(refreshToken)) {
            Claims claims = jwtService.getRefreshClaims(refreshToken);
            String username = claims.getSubject();
            UserDetails user = userService.loadUserByUsername(username);
            JwtResponseDto jwtResponseDto = new JwtResponseDto(
                    jwtService.generateAccessToken(user), jwtService.generateRefreshToken(user)
            );
            return ResponseEntity.ok(jwtResponseDto);
        }
        return new ResponseEntity<>(new AppError(HttpStatus.UNAUTHORIZED.value(),
                "Invalid refresh token"), HttpStatus.UNAUTHORIZED);
    }

//    метод регистрации...

}
