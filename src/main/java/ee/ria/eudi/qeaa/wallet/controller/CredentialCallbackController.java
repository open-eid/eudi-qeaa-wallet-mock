package ee.ria.eudi.qeaa.wallet.controller;

import ee.ria.eudi.qeaa.wallet.error.WalletException;
import ee.ria.eudi.qeaa.wallet.model.Session;
import ee.ria.eudi.qeaa.wallet.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Slf4j
@Controller
@RequiredArgsConstructor
public class CredentialCallbackController {
    public static final String ISSUANCE_CALLBACK_REQUEST_MAPPING = "/issuance_callback";
    private final SessionRepository sessionRepository;

    @GetMapping(ISSUANCE_CALLBACK_REQUEST_MAPPING)
    public ModelAndView issuanceRequestCallback(@RequestParam(name = "state") String state,
                                                @RequestParam(name = "code") String code) {
        Session session = sessionRepository.findByState(state);
        if (session != null) {
            throw new WalletException("Session not found");
        }
        return new ModelAndView("forward:/");
    }
}
