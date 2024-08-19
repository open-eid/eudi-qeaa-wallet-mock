package ee.ria.eudi.qeaa.wallet.error;

import lombok.Getter;

@Getter
public class WalletException extends RuntimeException {
    private final ErrorCode errorCode;

    public WalletException(String message) {
        super(message);
        errorCode = ErrorCode.INVALID_REQUEST;
    }

    public WalletException(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public WalletException(Throwable cause) {
        super(cause);
        errorCode = ErrorCode.SERVICE_EXCEPTION;
    }

    public WalletException(String message, Throwable cause) {
        super(message, cause);
        errorCode = ErrorCode.SERVICE_EXCEPTION;
    }
}
