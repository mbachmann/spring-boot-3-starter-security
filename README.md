# Spring Boot 3.2 + JPA + Auth JWT

- Backend:  https://github.com/mbachmann/spring-boot-3-starter-security.git
- Frontend: https://github.com/mbachmann/angular-20-jwt-auth-starter-standalone.git
- Frontend (deprecated): https://github.com/mbachmann/angular-17-jwt-auth-starter-no-standalone.git

The back-end server uses Spring Boot with Spring Security for JWT Authentication & Role based Authorization, 
Spring Data JPA for interacting with database. 

The front-end will be built using Angular 17 with HttpInterceptor & Form validation.

## Flow for User Registration and User Login
For JWT – Token-based Authentication with Rest API, we’re gonna call 2 endpoints:
- POST `api/auth/signup` for User Registration
- POST `api/auth/signin` for User Login
- POST `api/auth/signout` for User Logout


## Creating and deploying a container

### Build run and publish the todo-app project

Use a Mac, Linux, WSL2 or git bash console.

<br/>

```
git clone https://github.com/mbachmann/spring-boot-3-starter-security
cd spring-boot-3-starter-security
./mvnw clean package
java -jar target/starter-*.jar
```

<br/>

###  Create a Docker Container, Run and Publish to Docker

Create first a jar with the build instruction. To create a container. Replace **uportal** with your **dockerhub id**.

<br/>

For local platform

```
$  docker build -t uportal/spring-boot-3-starter-security  .
```

Windows Intel and target platform

```
$  docker buildx build --platform linux/amd64 -t uportal/spring-boot-3-starter-security -f Dockerfile .
```

For Mac or ARM Windows

```
$  docker buildx build --platform linux/arm64 -t uportal/spring-boot-3-starter-security -f Dockerfile .
```

Run the image

```
$  docker run -p 8080:8080 --rm -it  -e ACTIVE_PROFILES=dev,h2 uportal/spring-boot-3-starter-security
```


<br/>

_Ctrl c_ will stop and delete the container.

<br/>

Replace **uportal** with your **dockerhub id**.

<br/>

```
$  docker login
$  docker login --username uportal --password 
$  docker push uportal/spring-boot-3-starter-security
```
<br/>


Alternative way for login:

```
cat ~/.key/my_password.txt | docker login --username uportal --password-stdin
```

Login to deployment platform with a container infrastructure:

<br/>

Replace **uportal** with your **dockerhub id**.

<br/>

```
$  docker pull uportal/spring-boot-3-starter-security 
```

<br/>

###  docker-compose

Start the files with:

<br/>

Start with log output in the console:

```
$  docker compose -f docker-compose-h2.yml up
$  docker compose -f docker-compose-postgres.yml up
```

<br/>

Start in detached mode

```
$  docker compose -f docker-compose-h2.yml up -d
$  docker compose -f docker-compose-postgres.yml up -d
```

<br/>

Delete containers:

```
$  docker-compose -f docker-compose-h2.yml rm
$  docker-compose -f docker-compose-postgres.yml rm
```

<br/>
