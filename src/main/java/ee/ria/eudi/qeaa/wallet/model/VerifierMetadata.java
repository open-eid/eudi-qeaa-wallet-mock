package ee.ria.eudi.qeaa.wallet.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

import java.util.Map;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public final class VerifierMetadata {
    private String clientName;
    private String clientUri;
    private String logoUri;
    private Map<String, Object> vpFormats;

}
