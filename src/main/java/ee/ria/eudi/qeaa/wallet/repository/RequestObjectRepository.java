package ee.ria.eudi.qeaa.wallet.repository;

import ee.ria.eudi.qeaa.wallet.model.RequestObject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RequestObjectRepository extends JpaRepository<RequestObject, String> {

}
