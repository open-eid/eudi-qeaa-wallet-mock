package ee.ria.eudi.qeaa.wallet.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
public class PresentationConsent {
    private List<PresentationClaim> claims;
}
