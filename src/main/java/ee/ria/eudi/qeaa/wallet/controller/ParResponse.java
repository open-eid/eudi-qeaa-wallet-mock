package ee.ria.eudi.qeaa.wallet.controller;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ParResponse(
    String requestUri,
    long expiresIn) {

}
