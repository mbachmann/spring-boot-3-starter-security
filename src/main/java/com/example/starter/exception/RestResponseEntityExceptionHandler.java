package com.example.starter.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@ControllerAdvice
@Slf4j
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @Value("${app.urn}")
    private String urn;

    @ExceptionHandler({ AccessDeniedException.class })
    protected ResponseEntity<Object> handleAccessDeniedException(
            Exception ex, WebRequest request) {
        String error = "No access the desired resource. Full Authorization required. Please use a Bearer token or a session Cookie with a valid JWT token";
        ProblemDetail body = createProblemDetail(ex, error);
        return handleExceptionInternal(ex, body, new HttpHeaders(), HttpStatus.UNAUTHORIZED, request);
    }


    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(code = HttpStatus.BAD_REQUEST)
    public ResponseEntity<Object> handleConstraintViolatedException(ConstraintViolationException ex, WebRequest request) {
        Set<ConstraintViolation<?>> constraintViolations = ex.getConstraintViolations();

        List<String> errors = new ArrayList<>(constraintViolations.size());
        String error;
        for (ConstraintViolation<?> constraintViolation : constraintViolations) {

            error = constraintViolation.getMessage();
            errors.add(error);
        }

        ProblemDetail body = createProblemDetail(ex, StringUtils.join(errors, ", "));
        return handleExceptionInternal(ex, body, new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
    }

    @ExceptionHandler(ResourceAlreadyExistsException.class)
    @ResponseStatus(code = HttpStatus.CONFLICT)
    public ResponseEntity<Object> handleResourceAlreadyExists(ResourceAlreadyExistsException ex, WebRequest request) {
        String unsupported = "Conflict: " + ex.getMessage();
        ProblemDetail body = createProblemDetail(ex, unsupported);
        return handleExceptionInternal(ex, body, new HttpHeaders(), HttpStatus.CONFLICT, request);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(code = HttpStatus.NOT_FOUND)
    public ResponseEntity<Object> handleResourceNotFound(ResourceNotFoundException ex, WebRequest request) {
        String unsupported = "Resource Not Found: " + ex.getMessage();
        ProblemDetail body = createProblemDetail(ex, unsupported);
        return handleExceptionInternal(ex, body, new HttpHeaders(), HttpStatus.NOT_FOUND, request);
    }

    private ProblemDetail createProblemDetail (Exception ex, String error) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, error);
        problemDetail.setTitle(ex.getMessage());
        problemDetail.setType(URI.create("urn:" + urn));
        return problemDetail;
    }

}
