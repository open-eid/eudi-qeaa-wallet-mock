package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.Credential;
import ee.ria.eudi.qeaa.wallet.model.PresentationDefinition;
import ee.ria.eudi.qeaa.wallet.model.RequestObject;
import ee.ria.eudi.qeaa.wallet.model.VerifierMetadata;
import ee.ria.eudi.qeaa.wallet.repository.CredentialRepository;
import ee.ria.eudi.qeaa.wallet.repository.RequestObjectRepository;
import ee.ria.eudi.qeaa.wallet.service.RelyingPartyService;
import ee.ria.eudi.qeaa.wallet.service.ResponseObjectResponse;
import ee.ria.eudi.qeaa.wallet.util.JwtUtil;
import ee.ria.eudi.qeaa.wallet.util.MDocUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
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
                                                @ModelAttribute PresentationConsent presentationConsent) throws ParseException, JOSEException {
        RequestObject requestObject = requestObjectRepository.findByPresentationDefinitionId(presentationDefinitionId)
            .orElseThrow(() -> new WalletException("Presentation request not found"));
        String credentialDoctype = getRequestedCredentialDoctype(requestObject.getPresentationDefinition());
        List<Credential> credentials = credentialRepository.findByDoctypeOrderByIssuedAtDesc(credentialDoctype);
        if (credentials.isEmpty()) {
            throw new WalletException("Credential with requested doc type not found: %s".formatted(credentialDoctype));
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
        List<PresentationDefinition.InputDescriptor> inputDescriptors = presentationDefinition.getInputDescriptors();
        return inputDescriptors.stream()
            .flatMap(i -> i.getConstraints().getFields().stream())
            .filter(f -> f.getPath().contains("$.type") && f.getFilter() != null)
            .map(f -> f.getFilter().getPattern())
            .findFirst()
            .orElseThrow(() -> new WalletException("Requested credential type not found"));
    }

    private ResponseObjectResponse postResponseObject(RequestObject requestObject, Credential credential, PresentationConsent presentationConsent) throws JOSEException {
        String mdocNonce = MDocUtil.generateMdocNonce();
        String vpToken = vpTokenFactory.create(credential, presentationConsent,
            requestObject.getClientId(), requestObject.getResponseUri(), requestObject.getNonce(), mdocNonce);
        Map<String, Object> presentationSubmission = getPresentationSubmission(requestObject.getPresentationDefinition().getId());
        EncryptedJWT responseObject = getEncryptedResponse(requestObject.getClientMetadata(), requestObject.getNonce(), mdocNonce, vpToken, presentationSubmission);
        return relyingPartyService.postResponseObject(requestObject.getResponseUri(), responseObject, requestObject.getState());
    }

    private EncryptedJWT getEncryptedResponse(VerifierMetadata verifierMetadata, String nonce, String mDocNonce, String vpToken, Map<String, Object> presentationSubmission) throws JOSEException {
        JWKSet jwkSet = JwtUtil.getJwkSet(verifierMetadata);
        JWK encryptionKey = jwkSet.getKeys().getFirst();
        JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(verifierMetadata.getAuthorizationEncryptedResponseAlg());
        EncryptionMethod encryptionMethod = EncryptionMethod.parse(verifierMetadata.getAuthorizationEncryptedResponseEnc());
        JWEHeader header = new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
            .keyID(encryptionKey.getKeyID())
            .agreementPartyUInfo(Base64URL.encode(mDocNonce))
            .agreementPartyVInfo(Base64URL.encode(nonce))
            .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("vp_token", vpToken)
            .claim("presentation_submission", presentationSubmission)
            .build();
        EncryptedJWT jwe = new EncryptedJWT(header, claims);
        JWEEncrypter jweEncrypter = JwtUtil.getJWEEncrypter(encryptionKey);
        jwe.encrypt(jweEncrypter);
        return jwe;
    }

    private Map<String, Object> getPresentationSubmission(String presentationDefinitionId) {
        return Map.of("definition_id", presentationDefinitionId, "id", UUID.randomUUID(), "descriptor_map",
            List.of(Map.of("id", UUID.randomUUID(), "format", CREDENTIAL_FORMAT_MSO_MDOC, "path", "$")));
    }
}
