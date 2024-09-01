package ee.ria.eudi.qeaa.wallet.service;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialErrorResponse(
    String cNonce,
    Long cNonceExpiresIn) {

}
