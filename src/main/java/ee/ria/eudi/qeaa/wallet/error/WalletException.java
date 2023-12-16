package ee.ria.eudi.qeaa.wallet.error;

public class WalletException extends RuntimeException {

    public WalletException(String message) {
        super(message);
    }

    public WalletException(Throwable cause) {
        super(cause);
    }

    public WalletException(String message, Throwable cause) {
        super(message, cause);
    }
}
