package com.firebase.demo.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.IOException;

@Configuration
public class FirebaseConfiguration {
    @Bean
    public FirebaseApp getApp(GoogleCredentials credentials) throws IOException {
        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(credentials)
                .build();
        return FirebaseApp.initializeApp(options);
    }

    @Bean
    public GoogleCredentials getCredentials() throws IOException {
        return GoogleCredentials.fromStream(
            new FileInputStream("/home/vuser/Projects/Spring/FirebaseTest/token.json")
        );
    }

    @Bean
    public FirebaseAuth getAuth(FirebaseApp app)
    {
        return FirebaseAuth.getInstance(app);
    }
}
