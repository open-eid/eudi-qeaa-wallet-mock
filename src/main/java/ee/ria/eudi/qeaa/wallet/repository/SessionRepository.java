package ee.ria.eudi.qeaa.wallet.repository;

import ee.ria.eudi.qeaa.wallet.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long> {

    Optional<Session> findByState(String state);
}
