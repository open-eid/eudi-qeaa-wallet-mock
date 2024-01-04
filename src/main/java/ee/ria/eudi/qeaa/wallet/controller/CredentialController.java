package ee.ria.eudi.qeaa.wallet.controller;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSESign1;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import ee.ria.eudi.qeaa.wallet.configuration.properties.WalletProperties;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.factory.DPoPFactory;
import ee.ria.eudi.qeaa.wallet.factory.AuthorizationRequestObjectFactory;
import ee.ria.eudi.qeaa.wallet.factory.ClientAttestationPoPJwtFactory;
import ee.ria.eudi.qeaa.wallet.factory.CredentialJwtKeyProofFactory;
import ee.ria.eudi.qeaa.wallet.model.Credential;
import ee.ria.eudi.qeaa.wallet.model.CredentialResponse;
import ee.ria.eudi.qeaa.wallet.model.ParResponse;
import ee.ria.eudi.qeaa.wallet.model.Session;
import ee.ria.eudi.qeaa.wallet.repository.CredentialRepository;
import ee.ria.eudi.qeaa.wallet.repository.SessionRepository;
import ee.ria.eudi.qeaa.wallet.service.AuthorizationService;
import ee.ria.eudi.qeaa.wallet.service.CredentialIssuerService;
import ee.ria.eudi.qeaa.wallet.util.AccessTokenUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialController {
    private final DPoPFactory dPoPFactory;
    private final AuthorizationRequestObjectFactory authorizationRequestObjectFactory;
    private final AuthorizationService authorizationService;
    private final ClientAttestationPoPJwtFactory clientAttestationPoPJwtFactory;
    private final CredentialIssuerService credentialIssuerService;
    private final CredentialJwtKeyProofFactory credentialJwtKeyProofFactory;
    private final CredentialRepository credentialRepository;
    private final SessionRepository sessionRepository;
    private final SignedJWT walletInstanceAttestation;
    private final WalletProperties walletProperties;

    @GetMapping("/")
    public ModelAndView credentialsView() {
        List<Credential> credentials = credentialRepository.findByOrderByIssuedAtDesc();
        ModelAndView modelAndView = new ModelAndView("credentials");
        modelAndView.addObject(credentials);
        return modelAndView;
    }

    @GetMapping("/credential/{id}")
    public ModelAndView credentialView(@PathVariable("id") Long id) throws IOException, COSEException {
        Credential credential = credentialRepository.findById(id).orElseThrow(() -> new WalletException("Credential not found"));
        ModelAndView modelAndView = new ModelAndView("credential");
        modelAndView.addObject(credential);
        if (credential.getFormat().equals(CREDENTIAL_FORMAT_MSO_MDOC)) {
            byte[] cbor = HexFormat.of().parseHex(credential.getValue());
            CBORItem mdoc = new CBORDecoder(cbor).next();
            CBORItem issuerSigned = ((CBORPairList) mdoc).findByKey("issuerSigned").getValue();
            CBORPair issuerAuth = ((CBORPairList) issuerSigned).findByKey("issuerAuth");
            COSESign1 coseSign1 = COSESign1.build(issuerAuth.getValue());
            List<X509Certificate> x5Chain = coseSign1.getUnprotectedHeader().getX5Chain();
            String x5ChainFormatted = x5Chain.stream()
                .map(Certificate::toString)
                .collect(Collectors.joining("\n\n"));
            CBORByteArray payload = (CBORByteArray) coseSign1.getPayload();
            CBORItem mobileSecurityObject = new CBORDecoder(payload.getValue()).next();
            modelAndView.addObject("cbor", mdoc.prettify());
            modelAndView.addObject("x5chain", x5ChainFormatted);
            modelAndView.addObject("mso", mobileSecurityObject.prettify());
        }
        return modelAndView;
    }

    @PutMapping("/credential/update/{id}")
    public ModelAndView updateCredential(@PathVariable("id") Long id) throws ParseException, JOSEException {
        Credential credential = credentialRepository.findById(id).orElseThrow();
        SignedJWT accessToken = SignedJWT.parse(credential.getAccessToken());
        String accessTokenHash = AccessTokenUtil.computeSHA256(credential.getAccessToken());
        SignedJWT credentialDPoPProof = dPoPFactory.create(HttpMethod.POST, metadataService.getCredentialIssuerMetadata().credentialEndpoint(), accessTokenHash);
        SignedJWT credentialJwtKeyProof = credentialJwtKeyProofFactory.create(credential.getCNonce());
        CredentialResponse credentialResponse = credentialIssuerService.credentialRequest(accessToken, credentialDPoPProof, credentialJwtKeyProof);
        credential.setValue(credentialResponse.credential());
        credential.setCNonce(credentialResponse.cNonce());
        credential.setCNonceExpiresIn(credentialResponse.cNonceExpiresIn());
        credential.setIssuedAt(LocalDateTime.now());
        credentialRepository.save(credential);
        return new ModelAndView("redirect:/credential/%s".formatted(id));
    }

    @PostMapping(value = "/credential")
    public RedirectView requestCredential() throws JOSEException, ParseException {
        CodeVerifier codeVerifier = new CodeVerifier();
        SignedJWT requestObject = authorizationRequestObjectFactory.create(codeVerifier, getAuthorizationDetails());
        SignedJWT walletInstanceAttestationPoP = clientAttestationPoPJwtFactory.create("http://eudi-as.localhost:12080/as/par"); // TODO: From metadata
        ParResponse parResponse = authorizationService.pushedAuthorizationRequest(requestObject, walletInstanceAttestation, walletInstanceAttestationPoP);
        sessionRepository.save(Session.builder()
            .requestObjectClaims(requestObject.getJWTClaimsSet())
            .codeVerifier(codeVerifier)
            .build());

        String wiaSubject = walletInstanceAttestation.getJWTClaimsSet().getStringClaim(JWTClaimNames.SUBJECT);
        return new RedirectView(UriComponentsBuilder
            .fromUriString("http://eudi-as.localhost:12080/authorize") // TODO: From metadata
            .queryParam("request_uri", parResponse.requestUri())
            .queryParam("client_id", wiaSubject)
            .toUriString());
    }

    private Map<String, Object> getAuthorizationDetails() {
        return Map.of(
            "type", "openid_credential",
            "format", CREDENTIAL_FORMAT_MSO_MDOC,
            "doctype", "org.iso.18013.5.1.mDL",
            "locations", List.of(walletProperties.issuer().baseUrl())
        );
    }
}
