package me.kimyounghan.springsecurity.common;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityLogger {

    public static void log(String message) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Object principal = authentication.getPrincipal();

        System.out.println(message);
        System.out.println("==========");
        System.out.println("Thread : " + Thread.currentThread().getName());
        System.out.println("Principal : " + principal);
        System.out.println("==========");
        System.out.println();
    }

}
