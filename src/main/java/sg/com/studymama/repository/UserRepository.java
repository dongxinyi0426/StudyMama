package sg.com.studymama.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import sg.com.studymama.model.DAOUser;

@Repository
public interface UserRepository extends JpaRepository<DAOUser, Long>  {
	DAOUser findByUsername(String username);
	
	DAOUser findByPassword(String password);
}
