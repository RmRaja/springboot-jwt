package com.jwtexample.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HelloController {

    /**
     * API does not require Authentication
     */
    @GetMapping("hello-world")
    public ResponseEntity<?> sayHelloWorld() {
        return new ResponseEntity<>("Hello World", HttpStatus.OK);
    }

    /**
     * Secured by Authentication Filter.
     */
    @GetMapping("secured/hello-world")
    public ResponseEntity<?> saySecuredHelloWorld() {
        return new ResponseEntity<>("Secured Hello World", HttpStatus.OK);
    }
}
