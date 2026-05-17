package com.security.repository;

import com.security.model.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findAllByOrderByScanDateDesc();
    List<ScanResult> findByFileType(String fileType);
    List<ScanResult> findByGateStatus(String gateStatus);
}
