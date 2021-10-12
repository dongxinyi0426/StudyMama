package sg.com.studymama.controller;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import sg.com.studymama.DTO.PostsDTO;
import sg.com.studymama.Entity.Post;
import sg.com.studymama.Entity.PostsEntity;
import sg.com.studymama.model.PostData;
import sg.com.studymama.repository.RecommendationRepository;
import sg.com.studymama.service.PostService;
import sg.com.studymama.service.RecommendationService;
import sg.com.studymama.service.SpringDataPostService;
@CrossOrigin(origins = "*")
@RestController
public class PostsController {
	
	private static final Logger LOG = LoggerFactory.getLogger(PostsController.class);
	
	@Autowired
	private PostService postService;


	@Autowired
	private SpringDataPostService springDataPostService;
	
	@Autowired
	private RecommendationRepository recommendService;


	@GetMapping("post")
	@PreAuthorize("hasRole('USER')")
	public String postList() {
		return "/PostList";//overall post page include some basic info
	}
    
	@GetMapping("/postData")
	@PreAuthorize("hasRole('USER')")
	@ResponseBody
	public List<PostsDTO> getPostData(@RequestParam(value = "accountId", required = false) Integer accountId) {

		List<PostsDTO> postDTOList = new ArrayList<PostsDTO>();
		postDTOList = postService.getPosts(accountId);

		return postDTOList;
	}
    
	@GetMapping("/post/{postId}")
	@PreAuthorize("hasRole('USER')")
	public PostsDTO postData(@PathVariable("postId")Integer id, Model model) {
		
		PostsDTO postDTO = null;
		if(id != null && id>0 ) {
			postDTO = postService.findById(id);
		} else {
			postDTO = new PostsDTO();
		}
		
		model.addAttribute("DTO", postDTO);
		return postDTO;
	}

	@PostMapping("/postFormSubmit")
	@PreAuthorize("hasRole('USER')")
	public ResponseEntity<PostsDTO> postFormSubmit(@RequestBody PostsDTO postDTO, BindingResult bindingResult,
			RedirectAttributes redirectAttributes, Model model) {
		
		try {
			PostsEntity post=postService.save(postDTO);
			redirectAttributes.addAttribute("notificationType", "success");
			redirectAttributes.addAttribute("notificationMessage", "Success");
			LOG.info(postDTO.toString());
			springDataPostService.createPost(new PostData(post));
			recommendService.save(new Post(post));//neo4j?
			return ResponseEntity.ok(postDTO);
		} catch (Exception e) {
			e.printStackTrace();
			redirectAttributes.addFlashAttribute("submittedDTO", postDTO);
			redirectAttributes.addAttribute("notificationType", "error");
			redirectAttributes.addAttribute("notificationMessage", e.getMessage());
			return null;
		}

	}
	@RequestMapping(value = "/postDelete",produces = "application/json; charset=UTF-8")
	@PreAuthorize("hasRole('USER')")
	public void postDelete(@RequestParam(name="postId")Integer postId) { 
		LOG.info("POST ID IS " + postId);
		
		postService.deletePost(postId);
	}
}