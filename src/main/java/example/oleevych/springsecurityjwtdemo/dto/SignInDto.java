package example.oleevych.springsecurityjwtdemo.dto;

import lombok.Data;

@Data
public class SignInDto {
    private String username;
    private String password;

}
