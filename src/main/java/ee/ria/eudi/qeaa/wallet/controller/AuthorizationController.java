package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.Credential;
import ee.ria.eudi.qeaa.wallet.model.PresentationDefinition;
import ee.ria.eudi.qeaa.wallet.model.RequestObject;
import ee.ria.eudi.qeaa.wallet.model.ResponseObjectResponse;
import ee.ria.eudi.qeaa.wallet.repository.CredentialRepository;
import ee.ria.eudi.qeaa.wallet.repository.RequestObjectRepository;
import ee.ria.eudi.qeaa.wallet.service.CredentialPresentationFactory;
import ee.ria.eudi.qeaa.wallet.service.RelyingPartyService;
import ee.ria.eudi.qeaa.wallet.validation.AuthorizationRequestValidator;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;

@Controller
@RequiredArgsConstructor
public class AuthorizationController {
    private final AuthorizationRequestValidator authorizationRequestValidator;
    private final CredentialRepository credentialRepository;
    private final RelyingPartyService relyingPartyService;
    private final CredentialPresentationFactory credentialPresentationFactory;
    private final RequestObjectRepository requestObjectRepository;

    @GetMapping(path = "/authorize")
    public ResponseEntity<Object> authorize(@RequestParam(name = "client_id") String clientId,
                                            @RequestParam(name = "request_uri") String requestUri) {
        SignedJWT requestObjectJwt = relyingPartyService.getRequestObject(requestUri);
        RequestObject requestObject = authorizationRequestValidator.validate(requestObjectJwt, clientId);
        validateInputDescriptors(requestObject);
        requestObjectRepository.save(requestObject);
        // TODO: User consent
        Credential credential = credentialRepository.findByOrderByIssuedAtDesc().getFirst();
        String presentationCredential = credentialPresentationFactory.create(credential,
            requestObject.getPresentationDefinition(), requestObject.getClientId(), requestObject.getNonce());
        String presentationSubmission = getPresentationSubmission(requestObject.getPresentationDefinition().getId());
        ResponseObjectResponse responseObjectResponse = relyingPartyService.postResponseObject(requestObject.getResponseUri(),
            presentationCredential, presentationSubmission, requestObject.getState());
        return ResponseEntity.status(HttpStatus.FOUND).location(responseObjectResponse.redirectUri()).build();
    }

    private void validateInputDescriptors(RequestObject requestObject) {
        List<PresentationDefinition.InputDescriptor> inputDescriptors = requestObject.getPresentationDefinition().getInputDescriptors();
        if (inputDescriptors == null || inputDescriptors.isEmpty()) {
            throw new WalletException("Invalid presentation definition. No input descriptors found.");
        }
        if (inputDescriptors.size() > 1) {
            throw new NotImplementedException("Multiple input descriptors processing not implemented.");
        }
        PresentationDefinition.InputDescriptor inputDescriptor = inputDescriptors.getFirst();
        if (!inputDescriptor.getFormat().containsKey(CREDENTIAL_FORMAT_MSO_MDOC)) {
            throw new NotImplementedException("Input descriptor format '%s' processing not implemented.".formatted(inputDescriptor.getFormat()));
        }
    }

    private String getPresentationSubmission(String presentationDefinitionId) {
        return URLEncoder.encode("""
            {"definition_id":"%s","id":"%s","descriptor_map":[{"id":"org.iso.18013.5.1.mDL","format":"mso_mdoc","path":"$"}]}
            """.formatted(presentationDefinitionId, UUID.randomUUID()), StandardCharsets.UTF_8);
    }
}
