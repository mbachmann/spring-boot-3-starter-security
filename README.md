# Spring Boot 3 + JPA + Auth JWT

- Backend: https://github.com/mbachmann/spring-boot-3-starter-security.git
- Frontend: https://github.com/mbachmann/angular-15-jwt-auth-starter.git

The back-end server uses Spring Boot with Spring Security for JWT Authentication & Role based Authorization, 
Spring Data JPA for interacting with database. 

The front-end will be built using Angular 15 with HttpInterceptor & Form validation.

## Flow for User Registration and User Login
For JWT – Token based Authentication with Rest API, we’re gonna call 2 endpoints:
- POST `api/auth/signup` for User Registration
- POST `api/auth/signin` for User Login
- POST `api/auth/signout` for User Logout