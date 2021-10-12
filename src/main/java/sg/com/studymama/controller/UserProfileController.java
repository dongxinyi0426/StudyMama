package sg.com.studymama.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;

import sg.com.studymama.DTO.UserDTO;
import sg.com.studymama.DTO.UserProfileDTO;
import sg.com.studymama.model.DAOUser;
import sg.com.studymama.service.CustomUserDetailsService;
import sg.com.studymama.service.UserProfileService;


@CrossOrigin(origins = "*")
@RestController
public class UserProfileController {
	
	private static final Logger LOG = LoggerFactory.getLogger(UserProfileController.class);
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Autowired
	private UserProfileService userProfileService;
	
	@RequestMapping(value = "/updateProfile", method = RequestMethod.POST)
	@PreAuthorize("hasRole('USER')")
	public ResponseEntity<?> updateProfile(@RequestBody UserProfileDTO userProfile) throws Exception {
		LOG.info("Update profile: " + userProfile.toString());
		DAOUser user = userDetailsService.find(userProfile.getUsername());
		return ResponseEntity.ok(userProfileService.update(userProfile, user.getUser_profile_id()));
	}
	
	@RequestMapping(value = "/getProfile", method = RequestMethod.POST)
	public ResponseEntity<?> getProfile(@RequestBody UserDTO userDTO) throws Exception {
		LOG.info("Get profile: " + userDTO.toString());
		DAOUser user = userDetailsService.find(userDTO.getUsername());
		return ResponseEntity.ok(userProfileService.get(user.getUser_profile_id()));
	}


}
