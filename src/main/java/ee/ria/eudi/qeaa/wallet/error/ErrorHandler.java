package ee.ria.eudi.qeaa.wallet.error;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Slf4j
@ControllerAdvice
public class ErrorHandler {

    @ExceptionHandler({WalletException.class})
    public void handleWalletException(WalletException ex, HttpServletResponse response) throws IOException {
        if (ex.getCause() == null) {
            StackTraceElement stackElem = ex.getStackTrace()[0];
            log.error("Wallet exception: {} - {}:LN{}", ex.getMessage(), stackElem.getClassName(), stackElem.getLineNumber());
        } else {
            log.error("Wallet exception: {}", getCauseMessages(ex), ex);
        }
        response.sendError(ex.getErrorCode().getHttpStatusCode());
    }

    @ExceptionHandler({HttpClientErrorException.class})
    public void handleHttpClientErrorException(HttpClientErrorException ex, HttpServletResponse response) throws IOException {
        log.error("Client exception: {}", getCauseMessages(ex), ex);
        response.sendError(ex.getStatusCode().value());
    }

    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Unexpected exception: {}", getCauseMessages(ex), ex);
        response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

    public String getCauseMessages(Exception ex) {
        return ExceptionUtils.getThrowableList(ex).stream()
            .map(Throwable::getMessage)
            .filter(Objects::nonNull)
            .filter(Predicate.not(String::isBlank))
            .collect(Collectors.joining(" --> "));
    }
}
