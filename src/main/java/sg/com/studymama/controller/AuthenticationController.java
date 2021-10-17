package sg.com.studymama.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import sg.com.studymama.DTO.UserDTO;
import sg.com.studymama.model.AuthenticationRequest;
import sg.com.studymama.model.AuthenticationResponse;
import sg.com.studymama.service.CustomUserDetailsService;
import sg.com.studymama.service.JwtUtil;

import org.springframework.http.HttpStatus;

@CrossOrigin(origins = "*")
@RestController
public class AuthenticationController {

	private static final Logger LOG = LoggerFactory.getLogger(AuthenticationController.class);

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomUserDetailsService userDetailsService;

	@Autowired
	private JwtUtil jwtTokenUtil;

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	@ApiResponses(value = { 
			@ApiResponse(code = 500, message = "log in failed, please contact admin.")})
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest)
			throws Exception {
		try {
			LOG.info("New authentication request: " + authenticationRequest.toString());
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		} catch (DisabledException e) {
			LOG.error("DisabledException", e);
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			LOG.error("BadCredentialsException", e);
			throw new Exception("INVALID_CREDENTIALS", e);
		}
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		return ResponseEntity.ok(new AuthenticationResponse(token));
	}

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<?> saveUser(@RequestBody UserDTO user) throws Exception {
		LOG.info("New registration: " + user.toString());
		return ResponseEntity.ok(userDetailsService.save(user));
	}

	@CrossOrigin(origins = "*")
	@RequestMapping(value = "/refreshtoken", method = RequestMethod.GET)
	public ResponseEntity<?> refreshtoken(HttpServletRequest request) throws Exception {

		final String authHeader = request.getHeader("Authorization");
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			throw new ServletException("Missing or invalid Authorization header.");
		}

		final String token = authHeader.substring(7);
		try {
			final Claims claims = Jwts.parser().setSigningKey(jwtTokenUtil.getSecret()).parseClaimsJws(token).getBody();
			request.setAttribute("claims", claims);
		} catch (final SignatureException e) {
			throw new ServletException("Invalid token.");
		}

		// From the HttpRequest get the claims
		DefaultClaims claims = (io.jsonwebtoken.impl.DefaultClaims) request.getAttribute("claims");
		Map<String, Object> expectedMap = getMapFromIoJsonwebtokenClaims(claims);
		String tokenNew = jwtTokenUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
		LOG.info("Token refresh request: " + tokenNew);
		return ResponseEntity.ok(new AuthenticationResponse(tokenNew));
	}

	public Map<String, Object> getMapFromIoJsonwebtokenClaims(DefaultClaims claims) {
		Map<String, Object> expectedMap = new HashMap<String, Object>();
		for (Entry<String, Object> entry : claims.entrySet()) {
			expectedMap.put(entry.getKey(), entry.getValue());
		}
		return expectedMap;
	}
	
	@GetMapping("/session/invalid")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String sessionInvalid(){
        return "session invalid, try again";
    }
}
