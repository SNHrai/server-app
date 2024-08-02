package com.jewellery.server_app.utils;


import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;

public class CookieUtils {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static String serialize(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to serialize object", e);
        }
    }

    public static <T> T deserialize(Cookie cookie, Class<T> clazz) {
        try {
            return objectMapper.readValue(cookie.getValue(), clazz);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to deserialize cookie", e);
        }
    }
}
