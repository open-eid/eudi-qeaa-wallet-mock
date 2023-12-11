package ee.ria.eudi.qeaa.wallet.repository;

import ee.ria.eudi.qeaa.wallet.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {

    List<Credential> findByOrderByIssuedAtDesc();
}
