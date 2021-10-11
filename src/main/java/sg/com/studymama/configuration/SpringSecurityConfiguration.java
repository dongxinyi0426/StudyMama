package sg.com.studymama.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;


import sg.com.studymama.component.CustomJwtAuthenticationFilter;
import sg.com.studymama.component.JwtAuthenticationEntryPoint;
import sg.com.studymama.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	CustomUserDetailsService userDetailsService;

	@Autowired
	private CustomJwtAuthenticationFilter customJwtAuthenticationFilter;

	@Autowired
	private JwtAuthenticationEntryPoint unauthorizedHandler;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/swagger-ui/**", "/v3/api-docs/**");
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}
	
	//configuration for maximum sessions
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
    
  //configuration for maximum sessions
    @Bean
    public HttpSessionEventPublisher getHttpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    
    //to destroy session when logout
    @Bean
    protected LogoutSuccessHandler appLogoutSuccessHandler() {
        return new UserLogoutSuccessHandler();
    }
    
    //to show different type of error in login page
    @Bean
    protected AuthenticationFailureHandler authenticationFailureHandler() {
        return new UserAuthenticationFailureHandler();
    }

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	@Override
	public UserDetailsService userDetailsService() {
	    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
	    manager.createUser(User.withUsername("user").password("password").roles("USER").build());
	    manager.createUser(User.withUsername("admin").password("admin").roles("USER","ADMIN").build());
	    manager.createUser(User.withUsername("user1@example.com").password("user1").roles("USER").build());
	    manager.createUser(User.withUsername("admin1@example.com").password("admin1").roles("USER","ADMIN").build());
	    return manager;
	}
	
	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf().disable().authorizeRequests().antMatchers("/helloadmin").hasRole("ADMIN")
				.antMatchers("/hellouser", "/updateProfile", "/getProfile", "/categoryList", "/profilePicture")
				.hasAnyRole("ADMIN", "USER")
				.antMatchers("/authenticate", "/register", "/search", "/postDelete", "/post", "/post/*", "/postData",
						"/postFormSubmit", "/fakecategorysearch", "/commentSubmit", "/commentDelete/*", "/rateSubmit",
						"/Recommendation", "/greeting", "/demo", "/initPostData/*", "/postService/*",
						"/actuator/health", "/v2/api-docs", // for swagger stuff
						"/configuration/ui", "/swagger-resources/**", "/configuration/security", "/swagger-ui.html",
						"/swagger-ui/*", "/swagger-ui/index.html", "/v3/api-docs/", "/webjars/**")
				.permitAll().anyRequest().authenticated().and().exceptionHandling().and().httpBasic()
				.authenticationEntryPoint(unauthorizedHandler).and()
				.formLogin()
				.loginPage("/login")
				.permitAll()
				//.successForwardUrl("/home")
				.failureHandler(authenticationFailureHandler())
				.and()
				.logout()
				.logoutSuccessHandler(appLogoutSuccessHandler())
				.permitAll()
				.and()
				// make sure we use stateless session; session won't be used to
				// store user's state.

				//sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
				.sessionManagement()
				//.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.maximumSessions(1).maxSessionsPreventsLogin(true)
				.sessionRegistry(sessionRegistry()).
				and().invalidSessionUrl("/login");
		httpSecurity.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues());
		// Add a filter to validate the tokens with every request
		httpSecurity.addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}
}
