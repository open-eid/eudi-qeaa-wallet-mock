package ee.ria.eudi.qeaa.wallet.error;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Map;

@Component
public class ErrorAttributes extends DefaultErrorAttributes {
    public static final String ERROR_ATTR_ERROR = "error";
    public static final String ERROR_ATTR_ERROR_DESCRIPTION = "error_description";

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options);
        Throwable error = getError(webRequest);
        HttpStatus status = HttpStatus.resolve((int) attr.get("status"));

        if (error instanceof WalletException walletException) {
            setAttributes(attr, walletException.getErrorCode(), walletException.getMessage());
        } else if (status != null && status.is4xxClientError()) {
            setAttributes(attr, ErrorCode.INVALID_REQUEST, error.getMessage());
        } else {
            setAttributes(attr, ErrorCode.SERVICE_EXCEPTION, error.getMessage());
        }

        return attr;
    }

    private void setAttributes(Map<String, Object> attr, ErrorCode errorCode, String errorDescription) {
        attr.replace(ERROR_ATTR_ERROR, errorCode.name().toLowerCase());
        attr.put(ERROR_ATTR_ERROR_DESCRIPTION, errorDescription);
        attr.remove("message");
    }
}
