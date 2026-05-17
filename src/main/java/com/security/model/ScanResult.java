package com.security.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "scan_results")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String fileName;
    private String fileType;     // CODE or APK
    private String language;     // java, python, javascript, apk
    private Integer totalLines;
    private Integer securityScore;
    private String gateStatus;   // BLOCKED or PASSED
    private LocalDateTime scanDate;

    @Column(length = 5000)
    private String generatedTests;

    @OneToMany(mappedBy = "scanResult", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<Vulnerability> vulnerabilities;

    // Counts
    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;

    @PrePersist
    protected void onCreate() {
        scanDate = LocalDateTime.now();
    }
}
