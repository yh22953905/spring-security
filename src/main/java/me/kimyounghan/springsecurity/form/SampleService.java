package me.kimyounghan.springsecurity.form;

import me.kimyounghan.springsecurity.account.Account;
import me.kimyounghan.springsecurity.account.AccountContext;
import me.kimyounghan.springsecurity.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.annotation.security.RolesAllowed;
import java.util.Collection;

@Service
public class SampleService {

//    public void dashboard() {
//        // SecurityContextHolder와 Authentication
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Object principal = authentication.getPrincipal();
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Object credentials = authentication.getCredentials();
//        boolean authenticated = authentication.isAuthenticated();
//
//        Account account = AccountContext.getAccount();
//        System.out.println("==========");
//        System.out.println(account.getUsername());
//    }

    @Secured("ROLE_USER") // 메소드 호출 이전 권한 검사
//    @RolesAllowed("ROLE_USER") // 메소드 호출 이전 권한 검사
//    @PreAuthorize("hasRole('USER')") // 메소드 호출 이전 권한 검사
//    @PostAuthorize() // 메소드 호출 이후 권한 검사
    public void dashboard() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        System.out.println("==========");
        System.out.println(authentication);
        System.out.println(userDetails.getUsername());
    }

    @Async
    public void asyncService() {
        SecurityLogger.log("Async Service");
        System.out.println("Async Service is called");
    }
}
