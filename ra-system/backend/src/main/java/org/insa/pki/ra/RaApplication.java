package org.insa.pki.ra;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.Security;

@SpringBootApplication
public class RaApplication {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(RaApplication.class, args);
    }

    @Bean
    org.springframework.boot.CommandLineRunner bootstrapAdmin(
            org.insa.pki.ra.service.UserService userService,
            org.springframework.core.env.Environment environment) {
        return args -> userService.bootstrapAdmin(
                environment.getProperty("app.bootstrap.admin-username"),
                environment.getProperty("app.bootstrap.admin-email"),
                environment.getProperty("app.bootstrap.admin-password"));
    }
}
