package ee.ria.eudi.qeaa.wallet.controller;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PresentationClaim {
    private String inputDescriptorId;
    private String path;
    private String displayValue;
    private boolean intentToRetain;
    private boolean selected;
}
