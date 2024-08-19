package ee.ria.eudi.qeaa.wallet.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    SERVICE_EXCEPTION(500),
    INVALID_REQUEST(400),
    INVALID_SCOPE(400),
    INVALID_CLIENT(400),
    VP_FORMATS_NOT_SUPPORTED(400),
    INVALID_PRESENTATION_DEFINITION_URI(400),
    INVALID_PRESENTATION_DEFINITION_REFERENCE(400);

    private final int httpStatusCode;
}
