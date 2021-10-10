package sg.com.studymama.configuration;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;


public class UserLogoutSuccessHandler implements LogoutSuccessHandler {
	
	final Logger LOG = LoggerFactory.getLogger(UserLogoutSuccessHandler.class);

	 @Autowired
	    private SessionRegistry sessionRegistry;

	    @Override
	    public void onLogoutSuccess(HttpServletRequest httpServletRequest,
	                                HttpServletResponse httpServletResponse,
	                                Authentication authentication)
	            throws IOException, ServletException {
	    	
	        if (authentication != null && authentication.getDetails() != null) {
	            removeAuthSession(authentication, sessionRegistry);
	            httpServletRequest.getSession().invalidate();
				for(Cookie cookie : httpServletRequest.getCookies()) {
	            	cookie.setMaxAge(0);
	            	httpServletResponse.addCookie(cookie);
	            }
	            httpServletResponse.sendRedirect("login?logout");
	        }
	    }

	    private void removeAuthSession(Authentication authentication, SessionRegistry sessionRegistry) {
	        List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
	        if(!sessions.isEmpty()) {
	        	sessionRegistry.removeSessionInformation(sessions.get(0).getSessionId());
	        	LOG.info("User " + " logout, removing session from registry");
	        }
	    }
	}
