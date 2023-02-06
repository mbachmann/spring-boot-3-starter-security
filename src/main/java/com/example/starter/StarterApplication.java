package com.example.starter;

import jakarta.annotation.PostConstruct;
import java.util.Arrays;
import lombok.AllArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;

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
        if (hasDevProfile) {
            openApiInfo = "" +
                appUrl + swaggerUrl + System.lineSeparator() +
                appUrl + swaggerUrl + ".yaml -> yaml file is downloaded -> https://editor.swagger.io/" + System.lineSeparator() +
                appUrl + swaggerHtml + System.lineSeparator() +
                "";
        }
        if (hasH2Database) {
            h2ConsoleInfo= "http://localhost:8080/h2-console  " + "" +
                "-> mit Generic H2 (Embedded), org.h2.Driver, jdbc:h2:mem:testdb und sa \n";
        }
        System.out.println("\n\nApplication [" + applicationName + "] - Enter in Browser:\nhttp://localhost:8080 \n" +
            openApiInfo +
            h2ConsoleInfo + "\n" +
            "Active Profiles: " + Arrays.toString(env.getActiveProfiles()) + "\n\n");
    }

}
