package ee.ria.eudi.qeaa.wallet.controller;

import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.factory.VpTokenFactory;
import ee.ria.eudi.qeaa.wallet.model.Credential;
import ee.ria.eudi.qeaa.wallet.model.PresentationConsent;
import ee.ria.eudi.qeaa.wallet.model.PresentationDefinition;
import ee.ria.eudi.qeaa.wallet.model.PresentationDefinition.InputDescriptor;
import ee.ria.eudi.qeaa.wallet.model.RequestObject;
import ee.ria.eudi.qeaa.wallet.model.ResponseObjectResponse;
import ee.ria.eudi.qeaa.wallet.repository.CredentialRepository;
import ee.ria.eudi.qeaa.wallet.repository.RequestObjectRepository;
import ee.ria.eudi.qeaa.wallet.service.RelyingPartyService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;
import java.util.UUID;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;

@Controller
@RequiredArgsConstructor
public class ConsentController {
    public static final String CONSENT_ACCEPT_REQUEST_MAPPING = "/consent/{presentationDefinitionId}";
    public static final String CONSENT_REJECT_REQUEST_MAPPING = "/consent/{presentationDefinitionId}";
    private final CredentialRepository credentialRepository;
    private final VpTokenFactory vpTokenFactory;
    private final RelyingPartyService relyingPartyService;
    private final RequestObjectRepository requestObjectRepository;

    @PostMapping(path = CONSENT_ACCEPT_REQUEST_MAPPING)
    public ResponseEntity<Object> acceptConsent(@PathVariable("presentationDefinitionId") String presentationDefinitionId,
                                                @ModelAttribute PresentationConsent presentationConsent) {
        RequestObject requestObject = requestObjectRepository.findByPresentationDefinitionId(presentationDefinitionId)
            .orElseThrow(() -> new WalletException("Presentation request not found"));
        String credentialDoctype = getRequestedCredentialDoctype(requestObject.getPresentationDefinition());
        List<Credential> credentials = credentialRepository.findByDoctypeOrderByIssuedAtDesc(credentialDoctype);
        if (credentials.isEmpty()) {
            throw new WalletException("Credential not found");
        }
        Credential credential = credentials.getFirst();
        ResponseObjectResponse responseObjectResponse = postResponseObject(requestObject, credential, presentationConsent);
        return ResponseEntity.status(HttpStatus.FOUND).location(responseObjectResponse.redirectUri()).build();
    }

    @DeleteMapping(path = CONSENT_REJECT_REQUEST_MAPPING)
    public ResponseEntity<Object> rejectConsent(@PathVariable("presentationDefinitionId") String presentationDefinitionId) {
        RequestObject requestObject = requestObjectRepository.findByPresentationDefinitionId(presentationDefinitionId)
            .orElseThrow(() -> new WalletException("Presentation request not found"));
        ResponseObjectResponse responseObjectResponse = relyingPartyService.postErrorResponse(requestObject.getResponseUri(),
            "invalid_request", "Consent request rejected");
        return ResponseEntity.status(HttpStatus.FOUND).location(responseObjectResponse.redirectUri()).build();
    }

    private String getRequestedCredentialDoctype(PresentationDefinition presentationDefinition) {
        List<InputDescriptor> inputDescriptors = presentationDefinition.getInputDescriptors();
        return inputDescriptors.stream()
            .flatMap(i -> i.getConstraints().getFields().stream())
            .filter(f -> f.getPath().contains("$.type") && f.getFilter() != null)
            .map(f -> f.getFilter().getPattern())
            .findFirst()
            .orElseThrow(() -> new WalletException("Requested credential type not found"));
    }

    private ResponseObjectResponse postResponseObject(RequestObject requestObject, Credential credential, PresentationConsent presentationConsent) {
        String credentialWithConsentedClaims = vpTokenFactory.create(credential, presentationConsent, requestObject.getClientId(), requestObject.getNonce());
        String presentationSubmission = getPresentationSubmission(requestObject.getPresentationDefinition().getId());
        return relyingPartyService.postResponseObject(requestObject.getResponseUri(),
            credentialWithConsentedClaims, presentationSubmission, requestObject.getState());
    }

    private String getPresentationSubmission(String presentationDefinitionId) {
        return """
            {"definition_id":"%s","id":"%s","descriptor_map":[{"id":"%s","format":"%s","path":"$"}]}
            """.formatted(presentationDefinitionId, UUID.randomUUID(), UUID.randomUUID(), CREDENTIAL_FORMAT_MSO_MDOC);
    }
}
