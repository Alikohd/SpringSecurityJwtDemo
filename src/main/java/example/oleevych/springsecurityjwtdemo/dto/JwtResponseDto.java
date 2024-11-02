package example.oleevych.springsecurityjwtdemo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class JwtResponseDto {
    private String accessToken;
    private String refreshToken;
}
