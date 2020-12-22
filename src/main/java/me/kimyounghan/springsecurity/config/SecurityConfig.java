package me.kimyounghan.springsecurity.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.Arrays;
import java.util.List;

// 스프링 시큐리티 아키텍처 참고
// https://spring.io/guides/topicals/spring-security-architecture
// https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#overall-architecture
@Configuration
// @EnableWebSecurity // annotation 추가하지 않아도 security 자동 설정이 설정해준다.
// filter chain 을 만들 때 사용된다.
@Order(Ordered.LOWEST_PRECEDENCE - 50)
public class SecurityConfig extends WebSecurityConfigurerAdapter { // WebSecurityConfigurerAdapter : WebSecurity 를 만들어 filter chain 을 만드는 클래스

    // 인가 : FilterChainProxy -> FilterSecurityInterceptor(filter) -> AbstractSecurityInterceptor -> accessDecisionManager.decide)
    // ExceptionTranslationFilter -> AuthenticationException, AccessDeniedException / UsernamePasswordAuthenticationFilter 의 인증 에러는 별도 처리
    public AccessDecisionManager accessDecisionManager() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);

        WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
        webExpressionVoter.setExpressionHandler(handler);
        List<AccessDecisionVoter<? extends Object>> voters = Arrays.asList(webExpressionVoter);
        return new AffirmativeBased(voters);
    }

    public SecurityExpressionHandler securityExpressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    // 인증, 인가가 필요한 요청
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
                .mvcMatchers("/user").hasRole("USER")
                .mvcMatchers("/admin").hasRole("ADMIN")
//                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll() // 불필요하게 filter chain 을 다 거쳐야 함.
                .anyRequest().authenticated()
//                .accessDecisionManager(accessDecisionManager())
                .expressionHandler(securityExpressionHandler());
        http.formLogin();
        http.httpBasic();
//        http.csrf().disable(); // form 기반의 인증에서는 반드시 사용하는 게 좋다. REST API 의 경우 csrf 토큰을 매번 보내주는 게 번거로울 수 있기 때문에 disabled 시키고 사용할 수 있다.

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    // 인증, 인가가 필요하지 않은 요청
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // filter chain 을 거치지 않아도 됨.
    }

//    인메모리 유저 추가
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("younghan").password("{noop}1234").roles("USER")
//                    .and()
//                .withUser("admin").password("{noop}1234!").roles("ADMIN");
//    }


//    UserDetailsService를 구현한 클래스가 빈으로 등록되어 있으면 따로 설정하지 않아도 됨. PasswordEncoder도 마찬가지.
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(accountService);
//    }
}
