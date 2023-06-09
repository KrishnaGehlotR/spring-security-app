package org.dev.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

	@GetMapping("/")
	public String home() {
		return "<h1>Welcome</h1>";
	}

	@GetMapping("/user")
	public String user() {
		return "<h1>Hi, User</h1>";
	}

	@GetMapping("/manager")
	public String manager() {
		return "<h1>Hi, Manager</h1>";
	}

	@GetMapping("/admin")
	public String admin() {
		return "<h1>Hi, Admin</h1>";
	}

}
