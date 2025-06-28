package com.example.starter.utils;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Properties;

public final class StringUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(StringUtils.class.getName());

    private StringUtils() {
    }

    public static String convertStringArrayToString(String[] strArr, String delimiter) {
        StringBuilder sb = new StringBuilder();
        for (String str : strArr)
            sb.append(str).append(delimiter);
        return sb.substring(0, sb.length() - 1);
    }

    public static Properties fetchProperties(){
        Properties properties = new Properties();
        try {
            File file = ResourceUtils.getFile("classpath:application.properties");
            InputStream in = new FileInputStream(file);
            properties.load(in);
        } catch (IOException e) {
            LOGGER.error(e.getMessage());
        }
        return properties;
    }

    public static String getResourceFileAsString(String resourcePathAndName){
        String content = null;
        try {
            File file = ResourceUtils.getFile("classpath:" + resourcePathAndName);
            content = new String(Files.readAllBytes(file.toPath()));
        } catch (IOException e) {
            LOGGER.error(e.getMessage());
        }
        return content;
    }
}
