package org.insa.pki.ca.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;

@RestControllerAdvice
public class ApiExceptionHandler {
    public record ErrorResponse(Instant timestamp, int status, String error, String message, String path) {}

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<ErrorResponse> status(ResponseStatusException exception, HttpServletRequest request) {
        HttpStatus status = HttpStatus.valueOf(exception.getStatusCode().value());
        return ResponseEntity.status(status).body(new ErrorResponse(Instant.now(), status.value(), status.getReasonPhrase(),
                exception.getReason(), request.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ErrorResponse> validation(MethodArgumentNotValidException exception, HttpServletRequest request) {
        String message = exception.getBindingResult().getFieldErrors().stream().map(error -> error.getField() + " " + error.getDefaultMessage())
                .distinct().collect(java.util.stream.Collectors.joining("; "));
        return ResponseEntity.badRequest().body(new ErrorResponse(Instant.now(), 400, "Bad Request", message, request.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorResponse> unexpected(Exception exception, HttpServletRequest request) {
        return ResponseEntity.internalServerError().body(new ErrorResponse(Instant.now(), 500, "Internal Server Error",
                "Request could not be completed", request.getRequestURI()));
    }
}
