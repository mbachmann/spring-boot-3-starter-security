package com.example.starter;

import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;

import java.util.Arrays;

@AllArgsConstructor
@SpringBootApplication
public class StarterApplication {

    private Environment env;

    public static void main(String[] args) {
        SpringApplication.run(StarterApplication.class, args);
    }

    @PostConstruct
    public void afterInit() {
        boolean hasDevProfile = Arrays.asList(env.getActiveProfiles()).contains("dev");
        boolean hasH2Database = Arrays.asList(env.getActiveProfiles()).contains("h2");
        String applicationName = env.getProperty("spring.application.name");
        String appUrl = env.getProperty("app.server");
        String swaggerHtml = env.getProperty("springdoc.swagger-ui.path");
        String swaggerUrl = env.getProperty("springdoc.swagger-ui.url");

        String openApiInfo="";
        String h2ConsoleInfo="";
        String actuatorInfo="" +
                appUrl + "/actuator/info"  + System.lineSeparator() +
                appUrl + "/actuator/health"  + System.lineSeparator() +
                appUrl + "/actuator/health/readiness"  + System.lineSeparator() +
                appUrl + "/actuator/health/liveness"  + System.lineSeparator() +
                "";
        if (hasDevProfile) {
            openApiInfo = "" +
                appUrl + swaggerUrl + System.lineSeparator() +
                appUrl + swaggerUrl + ".yaml -> yaml file is downloaded -> https://editor.swagger.io/" + System.lineSeparator() +
                appUrl + swaggerHtml + System.lineSeparator() +
                "";
        }
        if (hasH2Database) {
            h2ConsoleInfo= appUrl + "/h2-console  " + "" +
                "-> mit Generic H2 (Embedded), org.h2.Driver, jdbc:h2:mem:testdb und sa \n";
        }
        System.out.println("\n\nApplication [" + applicationName + "] - Enter in Browser:\n" + appUrl + "\n" +
            openApiInfo +
            h2ConsoleInfo + "\n" +
            actuatorInfo + "\n" +
            "Active Profiles: " + Arrays.toString(env.getActiveProfiles()) + "\n\n");
    }
}
