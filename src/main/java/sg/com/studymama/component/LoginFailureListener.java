package sg.com.studymama.component;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import es.moki.ratelimitj.core.limiter.request.RequestLimitRule;
import es.moki.ratelimitj.core.limiter.request.RequestRateLimiter;
import es.moki.ratelimitj.inmemory.request.InMemorySlidingWindowRequestRateLimiter;

@Component
public class LoginFailureListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

    private static final Logger LOG = LoggerFactory.getLogger(LoginFailureListener.class);

    //错误了第四次返回true,然后锁定账号,第五次即使密码正确也会报账户锁定
    Set<RequestLimitRule> rules = Collections.singleton(RequestLimitRule.of(10, TimeUnit.MINUTES,3)); // 3 request per 10 minute, per key
    RequestRateLimiter limiter = new InMemorySlidingWindowRequestRateLimiter(rules);

    //UserDetailsManager userDetailsManager;

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        if (event.getException().getClass().equals(UsernameNotFoundException.class)) {
            return;
        }

        String userName = event.getAuthentication().getName();

        boolean reachLimit = limiter.overLimitWhenIncremented(userName);

        if(reachLimit){
           // User user = (User) userDetailsManager.loadUserByUsername(userName);

            //LOG.info("user:{} is locked",user);

            //User updated  = new User(user.getUsername(),user.getPassword(),user.isEnabled(),user.isAccountNonExpired(),user.isCredentialsNonExpired(),false,user.getAuthorities());

            //userDetailsManager.updateUser(updated);
        }
    }
}
