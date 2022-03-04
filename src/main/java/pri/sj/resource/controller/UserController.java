package pri.sj.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/v1")
public class UserController {
	
	@GetMapping("/users")
	public String findUserAll() {
		return "Success";
	}

}
