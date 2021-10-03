package sg.com.studymama.service;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import sg.com.studymama.DTO.UserProfileDTO;
import sg.com.studymama.Entity.UserData;
import sg.com.studymama.model.DAOUserProfile;
import sg.com.studymama.repository.RecommendationRepository;
import sg.com.studymama.repository.UserProfileRepository;

@Service
public class UserProfileService {

	private static final Logger LOG = LoggerFactory.getLogger(UserProfileService.class);
	
	@Autowired
	private UserProfileRepository userProfileDao;
	
	@Autowired
	private PasswordEncoder bcryptEncoder;
	
	public DAOUserProfile update(UserProfileDTO userProfile, long user_profile_id) {
		Optional<DAOUserProfile> tempProfile = userProfileDao.findById(user_profile_id);
		DAOUserProfile updateProfile = tempProfile.orElse(null);
		if(updateProfile!=null) {
			updateProfile.setAddress(bcryptEncoder.encode(userProfile.getAddress()));
			updateProfile.setContact(bcryptEncoder.encode(userProfile.getContact()));
			updateProfile.setFirstName(userProfile.getFirstName());
			updateProfile.setLastName(userProfile.getLastName());
			LOG.info("update " + updateProfile.toString());
			return userProfileDao.save(updateProfile);
		}
		return null;
	}
	
	public DAOUserProfile get(long user_profile_id) {
		Optional<DAOUserProfile> tempProfile = userProfileDao.findById(user_profile_id);
		DAOUserProfile updateProfile = tempProfile.orElse(null);
		if(updateProfile!=null) {
			return updateProfile;
		}
		return null;
	}
}
