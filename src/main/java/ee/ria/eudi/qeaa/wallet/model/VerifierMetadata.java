package ee.ria.eudi.qeaa.wallet.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Transient;
import lombok.Data;

import java.util.Map;

@Embeddable
@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public final class VerifierMetadata {
    private String clientName;
    private String clientUri;
    private String logoUri;
    @Transient
    private Map<String, Object> vpFormats;

}
