package ee.ria.eudi.qeaa.wallet.repository;

import ee.ria.eudi.qeaa.wallet.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {

    Session findByState(String state);
}
