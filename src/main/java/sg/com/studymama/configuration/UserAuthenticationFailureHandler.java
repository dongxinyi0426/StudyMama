package sg.com.studymama.configuration;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import es.moki.ratelimitj.core.limiter.request.RequestLimitRule;
import es.moki.ratelimitj.core.limiter.request.RequestRateLimiter;
import es.moki.ratelimitj.inmemory.request.InMemorySlidingWindowRequestRateLimiter;

@Component
public class UserAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler implements AuthenticationFailureHandler {
	
	private static final Logger LOG = LoggerFactory.getLogger(UserAuthenticationFailureHandler.class);
	@Autowired
    UserDetailsManager userDetailsManager;
	
	@Autowired
    private UserDetailsService userDetailsService;
	
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    //规则定义：1小时之内5次机会，就触发限流行为
    Set<RequestLimitRule> rules = 
            Collections.singleton(RequestLimitRule.of(1 * 60, TimeUnit.MINUTES,5)); 
    RequestRateLimiter limiter = new InMemorySlidingWindowRequestRateLimiter(rules);

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		     
		   String message = exception.getMessage();
		   
		   String userName = request.getParameter("userName");
		   boolean reachLimit = limiter.overLimitWhenIncremented(userName);
		   
		 //如果触发了锁定规则，通过UserDetails告知Spring Security锁定账户
		   if(reachLimit){  
			   UserDetails user = this.userDetailsService.loadUserByUsername(userName);
               //User user = (User) userDetailsManager.loadUserByUsername(userName);
               user.isAccountNonLocked();
               LOG.info("user:{} is locked",user);  
               User updated = new User(user.getUsername(),user.getPassword(),user.isEnabled(),user.isAccountNonExpired(),user.isCredentialsNonExpired(),false,user.getAuthorities());
               userDetailsManager.updateUser(updated);
        }
				
				if(exception.getClass().equals(UsernameNotFoundException.class) 
						|| exception.getClass().equals(BadCredentialsException.class)
						|| message.contains("No AuthenticationProvider found")) {
					
					logger.info("class type = " + exception.getClass().getName() + ", message = " + message);
					redirectStrategy.sendRedirect(request, response, "/login?invalid");
				} else if(exception.getClass().equals(LockedException.class)) {
					redirectStrategy.sendRedirect(request, response, "/login?locked");
				} else if(exception.getClass().equals(AuthenticationServiceException.class)) {
					redirectStrategy.sendRedirect(request, response, "/login?code=" + exception.getMessage());
				} else if(message.contains("Maximum sessions")) {
					redirectStrategy.sendRedirect(request, response, "/login?exceed");
				} else {
					logger.info("Message = " + message);
					exception.printStackTrace();
					redirectStrategy.sendRedirect(request, response, "/login?undefined");
				}
		
	}

}
