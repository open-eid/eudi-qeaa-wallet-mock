package ee.ria.eudi.qeaa.wallet.controller;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.PresentationDefinition;
import ee.ria.eudi.qeaa.wallet.model.RequestObject;
import ee.ria.eudi.qeaa.wallet.repository.RequestObjectRepository;
import ee.ria.eudi.qeaa.wallet.service.RelyingPartyService;
import ee.ria.eudi.qeaa.wallet.validation.AuthorizationRequestValidator;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

import static ee.ria.eudi.qeaa.wallet.model.Credential.CREDENTIAL_FORMAT_MSO_MDOC;

@Controller
@RequiredArgsConstructor
public class AuthorizationController {
    private final AuthorizationRequestValidator authorizationRequestValidator;
    private final RelyingPartyService relyingPartyService;
    private final RequestObjectRepository requestObjectRepository;

    @GetMapping(path = "/authorize")
    public ModelAndView authorize(@RequestParam(name = "client_id") String clientId,
                                  @RequestParam(name = "request_uri") String requestUri) {
        SignedJWT requestObjectJwt = relyingPartyService.getRequestObject(requestUri);
        RequestObject requestObject = authorizationRequestValidator.validate(requestObjectJwt, clientId);
        validateInputDescriptors(requestObject);
        requestObjectRepository.save(requestObject);
        ModelAndView modelAndView = new ModelAndView("consent");
        modelAndView.addObject("presentation_definition", requestObject.getPresentationDefinition());
        modelAndView.addObject("presentation_consent", PresentationConsent.builder()
            .claims(requestObject.getPresentationDefinition().getRequestedClaims())
            .build());
        return modelAndView;
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
}
