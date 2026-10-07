package org.insa.pki.ca.profiles;

import java.time.Duration;
import java.util.List;

public record CertificateProfile(String name, String description, List<String> keyAlgorithms,
                                 List<Integer> keySizes, List<String> extendedKeyUsages,
                                 Duration validity, boolean subjectAltNameRequired,
                                 boolean keyEnciphermentAllowed) {}
