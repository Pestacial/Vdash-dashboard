import { useState, useMemo, useRef } from "react";

// ── Base report data parsed from Trivy_2026_.html ──────────────────────────
const BASE_VULNERABILITIES = [
  { id: "CVE-2026-27456", pkg: "bsdutils (1:2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2025-14017", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "MEDIUM", title: "curl: Security bypass due to global TLS option changes in multi-threaded LDAPS transfers", target: "ubuntu:24.04" },
  { id: "CVE-2026-1965", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "MEDIUM", title: "curl: Authentication bypass due to incorrect connection reuse with Negotiate authentication", target: "ubuntu:24.04" },
  { id: "CVE-2026-3783", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "MEDIUM", title: "curl: Information disclosure via OAuth2 bearer token leakage during HTTP(S) redirect", target: "ubuntu:24.04" },
  { id: "CVE-2025-0167", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: credentials disclosure via .netrc and HTTP redirect", target: "ubuntu:24.04" },
  { id: "CVE-2025-10148", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: predictable WebSocket mask", target: "ubuntu:24.04" },
  { id: "CVE-2025-14524", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: Information disclosure via cross-protocol redirect with OAuth2 bearer token", target: "ubuntu:24.04" },
  { id: "CVE-2025-14819", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: Improper certificate validation due to cached TLS settings reuse", target: "ubuntu:24.04" },
  { id: "CVE-2025-15079", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: Host verification bypass during SSH transfers", target: "ubuntu:24.04" },
  { id: "CVE-2025-15224", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: libssh key passphrase bypass without agent set", target: "ubuntu:24.04" },
  { id: "CVE-2026-3784", pkg: "curl (8.5.0-2ubuntu10.6)", severity: "LOW", title: "curl: Unauthorized access due to improper HTTP proxy connection reuse", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "dirmngr (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2026-2219", pkg: "dpkg (1.22.6ubuntu6.1)", severity: "MEDIUM", title: "dpkg: dpkg-deb component vulnerability in Debian package manager", target: "ubuntu:24.04" },
  { id: "CVE-2025-6297", pkg: "dpkg (1.22.6ubuntu6.1)", severity: "LOW", title: "dpkg: dpkg-deb does not properly sanitize directory paths", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gnupg (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gnupg-utils (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gpg (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gpg-agent (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gpgconf (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gpgsm (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "gpgv (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2025-68973", pkg: "keyboxd (2.4.4-2ubuntu17.3)", severity: "HIGH", title: "GnuPG: Information disclosure and potential arbitrary code execution via out-of-bounds write", target: "ubuntu:24.04" },
  { id: "CVE-2026-27456", pkg: "libblkid1 (2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2026-4046", pkg: "libc-bin (2.39-0ubuntu8.7)", severity: "MEDIUM", title: "glibc: Denial of Service via iconv() function with specific character sets", target: "ubuntu:24.04" },
  { id: "CVE-2026-4437", pkg: "libc-bin (2.39-0ubuntu8.7)", severity: "MEDIUM", title: "glibc: Incorrect DNS response parsing via crafted DNS server response", target: "ubuntu:24.04" },
  { id: "CVE-2026-4438", pkg: "libc-bin (2.39-0ubuntu8.7)", severity: "MEDIUM", title: "glibc: Invalid DNS hostname returned via gethostbyaddr functions", target: "ubuntu:24.04" },
  { id: "CVE-2026-4046", pkg: "libc6 (2.39-0ubuntu8.7)", severity: "MEDIUM", title: "glibc: Denial of Service via iconv() function with specific character sets", target: "ubuntu:24.04" },
  { id: "CVE-2026-4437", pkg: "libc6 (2.39-0ubuntu8.7)", severity: "MEDIUM", title: "glibc: Incorrect DNS response parsing via crafted DNS server response", target: "ubuntu:24.04" },
  { id: "CVE-2026-4438", pkg: "libc6 (2.39-0ubuntu8.7)", severity: "MEDIUM", title: "glibc: Invalid DNS hostname returned via gethostbyaddr functions", target: "ubuntu:24.04" },
  { id: "CVE-2026-4878", pkg: "libcap2 (1:2.66-5ubuntu2.2)", severity: "MEDIUM", title: "libcap: Privilege escalation via TOCTOU race condition in cap_set_file()", target: "ubuntu:24.04" },
  { id: "CVE-2025-14017", pkg: "libcurl4t64 (8.5.0-2ubuntu10.6)", severity: "MEDIUM", title: "curl: Security bypass due to global TLS option changes in multi-threaded LDAPS transfers", target: "ubuntu:24.04" },
  { id: "CVE-2026-1965", pkg: "libcurl4t64 (8.5.0-2ubuntu10.6)", severity: "MEDIUM", title: "curl: Authentication bypass due to incorrect connection reuse with Negotiate authentication", target: "ubuntu:24.04" },
  { id: "CVE-2026-3783", pkg: "libcurl4t64 (8.5.0-2ubuntu10.6)", severity: "MEDIUM", title: "curl: Information disclosure via OAuth2 bearer token leakage during HTTP(S) redirect", target: "ubuntu:24.04" },
  { id: "CVE-2025-66382", pkg: "libexpat1 (2.6.1-2ubuntu0.3)", severity: "MEDIUM", title: "libexpat: Denial of service via crafted file processing", target: "ubuntu:24.04" },
  { id: "CVE-2026-24515", pkg: "libexpat1 (2.6.1-2ubuntu0.3)", severity: "MEDIUM", title: "libexpat: null pointer dereference", target: "ubuntu:24.04" },
  { id: "CVE-2026-25210", pkg: "libexpat1 (2.6.1-2ubuntu0.3)", severity: "MEDIUM", title: "libexpat: Information disclosure and data integrity issues via integer overflow in buffer reallocation", target: "ubuntu:24.04" },
  { id: "CVE-2026-23865", pkg: "libfreetype6 (2.13.2+dfsg-1build3)", severity: "MEDIUM", title: "Freetype: Information disclosure or denial of service via specially crafted font files", target: "ubuntu:24.04" },
  { id: "CVE-2024-2236", pkg: "libgcrypt20 (1.10.3-2build1)", severity: "LOW", title: "libgcrypt: vulnerable to Marvin Attack", target: "ubuntu:24.04" },
  { id: "CVE-2025-14831", pkg: "libgnutls30t64 (3.8.3-1.1ubuntu3.4)", severity: "MEDIUM", title: "gnutls: Denial of Service via excessive resource consumption during certificate verification", target: "ubuntu:24.04" },
  { id: "CVE-2025-9820", pkg: "libgnutls30t64 (3.8.3-1.1ubuntu3.4)", severity: "LOW", title: "gnutls: Stack-based Buffer Overflow in gnutls_pkcs11_token_init()", target: "ubuntu:24.04" },
  { id: "CVE-2026-27456", pkg: "libmount1 (2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2024-10963", pkg: "libpam-modules (1.5.3-5ubuntu5.4)", severity: "MEDIUM", title: "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass", target: "ubuntu:24.04" },
  { id: "CVE-2024-10963", pkg: "libpam-modules-bin (1.5.3-5ubuntu5.4)", severity: "MEDIUM", title: "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass", target: "ubuntu:24.04" },
  { id: "CVE-2024-10963", pkg: "libpam-runtime (1.5.3-5ubuntu5.4)", severity: "MEDIUM", title: "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass", target: "ubuntu:24.04" },
  { id: "CVE-2024-10963", pkg: "libpam0g (1.5.3-5ubuntu5.4)", severity: "MEDIUM", title: "pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass", target: "ubuntu:24.04" },
  { id: "CVE-2025-28162", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: Denial of Service via buffer overflow in pngimage utility", target: "ubuntu:24.04" },
  { id: "CVE-2025-28164", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: Denial of Service via buffer overflow in png_create_read_struct()", target: "ubuntu:24.04" },
  { id: "CVE-2025-64505", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: heap buffer overflow via malformed palette index", target: "ubuntu:24.04" },
  { id: "CVE-2025-64506", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: heap buffer over-read", target: "ubuntu:24.04" },
  { id: "CVE-2025-64720", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: buffer overflow", target: "ubuntu:24.04" },
  { id: "CVE-2025-65018", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: heap buffer overflow", target: "ubuntu:24.04" },
  { id: "CVE-2025-66293", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: out-of-bounds read in png_image_read_composite", target: "ubuntu:24.04" },
  { id: "CVE-2026-22695", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: Denial of service and information disclosure via heap buffer over-read", target: "ubuntu:24.04" },
  { id: "CVE-2026-22801", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: Information disclosure and denial of service via integer truncation in simplified write API", target: "ubuntu:24.04" },
  { id: "CVE-2026-25646", pkg: "libpng16-16t64 (1.6.43-5build1)", severity: "MEDIUM", title: "libpng: heap buffer overflow in png_set_quantize", target: "ubuntu:24.04" },
  { id: "CVE-2026-27456", pkg: "libsmartcols1 (2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2025-7709", pkg: "libsqlite3-0 (3.45.1-1ubuntu2.4)", severity: "MEDIUM", title: "SQLite: integer overflow in FTS5 extension", target: "ubuntu:24.04" },
  { id: "CVE-2026-0964", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "MEDIUM", title: "libssh: Improper sanitation of paths received from SCP servers", target: "ubuntu:24.04" },
  { id: "CVE-2026-0967", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "MEDIUM", title: "libssh: Denial of Service via inefficient regular expression processing", target: "ubuntu:24.04" },
  { id: "CVE-2026-0968", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "MEDIUM", title: "libssh: Denial of Service due to malformed SFTP message", target: "ubuntu:24.04" },
  { id: "CVE-2026-3731", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "MEDIUM", title: "libssh: Denial of Service via out-of-bounds read in SFTP extension name handler", target: "ubuntu:24.04" },
  { id: "CVE-2025-8114", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "LOW", title: "libssh: NULL Pointer Dereference in KEX Session ID Calculation", target: "ubuntu:24.04" },
  { id: "CVE-2025-8277", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "LOW", title: "libssh: Memory Exhaustion via Repeated Key Exchange", target: "ubuntu:24.04" },
  { id: "CVE-2026-0965", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "LOW", title: "libssh: Denial of Service via improper configuration file handling", target: "ubuntu:24.04" },
  { id: "CVE-2026-0966", pkg: "libssh-4 (0.10.6-2ubuntu0.1)", severity: "LOW", title: "libssh: Buffer underflow in ssh_get_hexa() on invalid input", target: "ubuntu:24.04" },
  { id: "CVE-2025-15467", pkg: "libssl3t64 (3.0.13-0ubuntu3.5)", severity: "MEDIUM", title: "openssl: Remote code execution or Denial of Service via oversized IV in CMS parsing", target: "ubuntu:24.04" },
  { id: "CVE-2025-9230", pkg: "libssl3t64 (3.0.13-0ubuntu3.5)", severity: "MEDIUM", title: "openssl: Out-of-bounds read & write in RFC 3211 KEK Unwrap", target: "ubuntu:24.04" },
  { id: "CVE-2026-31790", pkg: "libssl3t64 (3.0.13-0ubuntu3.5)", severity: "MEDIUM", title: "openssl: Information Disclosure from Uninitialized Memory via Invalid RSA Public Key", target: "ubuntu:24.04" },
  { id: "CVE-2026-29111", pkg: "libsystemd0 (255.4-1ubuntu8.8)", severity: "MEDIUM", title: "systemd: Arbitrary code execution or Denial of Service via spurious IPC API call data", target: "ubuntu:24.04" },
  { id: "CVE-2025-13151", pkg: "libtasn1-6 (4.19.0-3ubuntu0.24.04.1)", severity: "MEDIUM", title: "libtasn1: Denial of Service via stack-based buffer overflow in asn1_expend_octet_string", target: "ubuntu:24.04" },
  { id: "CVE-2026-27456", pkg: "libuuid1 (2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2024-56433", pkg: "login (1:4.13+dfsg1-4ubuntu3.2)", severity: "LOW", title: "shadow-utils: Default subordinate ID configuration could lead to compromise", target: "ubuntu:24.04" },
  { id: "CVE-2026-27456", pkg: "mount (2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2025-15467", pkg: "openssl (3.0.13-0ubuntu3.5)", severity: "MEDIUM", title: "openssl: Remote code execution or Denial of Service via oversized IV in CMS parsing", target: "ubuntu:24.04" },
  { id: "CVE-2025-9230", pkg: "openssl (3.0.13-0ubuntu3.5)", severity: "MEDIUM", title: "openssl: Out-of-bounds read & write in RFC 3211 KEK Unwrap", target: "ubuntu:24.04" },
  { id: "CVE-2026-31790", pkg: "openssl (3.0.13-0ubuntu3.5)", severity: "MEDIUM", title: "openssl: Information Disclosure from Uninitialized Memory via Invalid RSA Public Key", target: "ubuntu:24.04" },
  { id: "CVE-2024-56433", pkg: "passwd (1:4.13+dfsg1-4ubuntu3.2)", severity: "LOW", title: "shadow-utils: Default subordinate ID configuration could lead to compromise", target: "ubuntu:24.04" },
  { id: "CVE-2025-40909", pkg: "perl-base (5.38.2-3.2ubuntu0.1)", severity: "MEDIUM", title: "perl: Working directory race condition where file operations may target unintended paths", target: "ubuntu:24.04" },
  { id: "CVE-2026-41035", pkg: "rsync (3.2.7-1ubuntu1.2)", severity: "MEDIUM", title: "rsync: Use-after-free vulnerability in extended attribute handling", target: "ubuntu:24.04" },
  { id: "CVE-2025-45582", pkg: "tar (1.35+dfsg-3build1)", severity: "MEDIUM", title: "tar: path traversal", target: "ubuntu:24.04" },
  { id: "CVE-2026-27456", pkg: "util-linux (2.39.3-9ubuntu6.3)", severity: "MEDIUM", title: "util-linux: TOCTOU in the mount program when setting up loop devices", target: "ubuntu:24.04" },
  { id: "CVE-2021-31879", pkg: "wget (1.21.4-1ubuntu4.1)", severity: "MEDIUM", title: "wget: authorization header disclosure on redirect", target: "ubuntu:24.04" },
  { id: "CVE-2024-12798", pkg: "ch.qos.logback:logback-core (1.2.13)", severity: "MEDIUM", title: "logback-core: arbitrary code execution via JaninoEventEvaluator", target: "Java" },
  { id: "CVE-2025-11226", pkg: "ch.qos.logback:logback-core (1.2.13)", severity: "MEDIUM", title: "logback-core: Conditional arbitrary code execution in logback-core", target: "Java" },
  { id: "CVE-2024-12801", pkg: "ch.qos.logback:logback-core (1.2.13)", severity: "LOW", title: "logback-core: SaxEventRecorder vulnerable to Server-Side Request Forgery (SSRF)", target: "Java" },
  { id: "CVE-2026-1225", pkg: "ch.qos.logback:logback-core (1.2.13)", severity: "LOW", title: "logback-core: Malicious logback.xml config allows instantiation of arbitrary classes", target: "Java" },
  { id: "CVE-2025-52999", pkg: "com.fasterxml.jackson.core:jackson-core (2.13.2)", severity: "HIGH", title: "jackson-core: Potential StackoverflowError", target: "Java" },
  { id: "GHSA-72hv-8253-57qq", pkg: "com.fasterxml.jackson.core:jackson-core (2.13.2)", severity: "MEDIUM", title: "jackson-core: Number Length Constraint Bypass in Async Parser Leads to Potential DoS", target: "Java" },
  { id: "CVE-2023-52428", pkg: "com.nimbusds:nimbus-jose-jwt (9.30.2)", severity: "HIGH", title: "nimbus-jose-jwt: large JWE p2c header value causes Denial of Service", target: "Java" },
  { id: "CVE-2025-53864", pkg: "com.nimbusds:nimbus-jose-jwt (9.30.2)", severity: "MEDIUM", title: "nimbus-jose-jwt: Uncontrolled recursion in Connect2id Nimbus JOSE + JWT", target: "Java" },
  { id: "CVE-2025-48734", pkg: "commons-beanutils:commons-beanutils (1.9.4)", severity: "HIGH", title: "commons-beanutils: Apache Commons BeanUtils PropertyUtilsBean enum declaredClass property not suppressed by default", target: "Java" },
  { id: "CVE-2025-48924", pkg: "commons-lang:commons-lang (2.6)", severity: "MEDIUM", title: "commons-lang: Uncontrolled Recursion vulnerability in Apache Commons Lang", target: "Java" },
  { id: "CVE-2025-58057", pkg: "io.netty:netty-codec (4.1.77.Final)", severity: "MEDIUM", title: "netty-codec: BrotliDecoder is vulnerable to DoS via zip bomb style attack", target: "Java" },
  { id: "CVE-2026-33870", pkg: "io.netty:netty-codec-http (4.1.77.Final)", severity: "HIGH", title: "netty-codec-http: Request smuggling via incorrect parsing of HTTP/1.1 chunked transfer encoding", target: "Java" },
  { id: "CVE-2024-29025", pkg: "io.netty:netty-codec-http (4.1.77.Final)", severity: "MEDIUM", title: "netty-codec-http: Allocation of Resources Without Limits or Throttling", target: "Java" },
  { id: "CVE-2025-67735", pkg: "io.netty:netty-codec-http (4.1.77.Final)", severity: "MEDIUM", title: "netty-codec-http: Request Smuggling via CRLF Injection", target: "Java" },
  { id: "CVE-2025-58056", pkg: "io.netty:netty-codec-http (4.1.77.Final)", severity: "LOW", title: "netty-codec-http: Request smuggling due to incorrect parsing of chunk extensions", target: "Java" },
  { id: "CVE-2025-55163", pkg: "io.netty:netty-codec-http2 (4.1.77.Final)", severity: "HIGH", title: "netty-codec-http2: MadeYouReset HTTP/2 DDoS Vulnerability", target: "Java" },
  { id: "CVE-2026-33871", pkg: "io.netty:netty-codec-http2 (4.1.77.Final)", severity: "HIGH", title: "netty: Denial of Service via HTTP/2 CONTINUATION frame flood", target: "Java" },
  { id: "GHSA-xpw8-rcwv-8f8p", pkg: "io.netty:netty-codec-http2 (4.1.77.Final)", severity: "HIGH", title: "netty-codec-http2: HTTP/2 Rapid Reset Attack vulnerability", target: "Java" },
  { id: "CVE-2024-47535", pkg: "io.netty:netty-common (4.1.77.Final)", severity: "MEDIUM", title: "netty: Denial of Service attack on windows app using Netty", target: "Java" },
  { id: "CVE-2025-25193", pkg: "io.netty:netty-common (4.1.77.Final)", severity: "MEDIUM", title: "netty: Denial of Service attack on windows app using Netty", target: "Java" },
  { id: "CVE-2023-34462", pkg: "io.netty:netty-handler (4.1.77.Final)", severity: "MEDIUM", title: "netty: SniHandler 16MB allocation leads to OOM", target: "Java" },
  { id: "CVE-2025-48924", pkg: "org.apache.commons:commons-lang3 (3.8.1)", severity: "MEDIUM", title: "commons-lang3: Uncontrolled Recursion vulnerability in Apache Commons Lang", target: "Java" },
  { id: "CVE-2025-66516", pkg: "org.apache.tika:tika-core (2.9.2)", severity: "CRITICAL", title: "tika-core: Apache Tika core/parsers/PDF parser module: Update to CVE-2025-54988 to expand scope of artifacts affected", target: "Java" },
  { id: "CVE-2026-29145", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "CRITICAL", title: "Apache Tomcat: Authentication bypass due to CLIENT_CERT soft fail misconfiguration", target: "Java" },
  { id: "CVE-2025-55752", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "HIGH", title: "tomcat-catalina: Directory traversal via rewrite with possible RCE", target: "Java" },
  { id: "CVE-2026-34483", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "HIGH", title: "Apache Tomcat: Information disclosure due to improper encoding in JsonAccessLogValve", target: "Java" },
  { id: "CVE-2026-34487", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "HIGH", title: "Apache Tomcat: Information disclosure via sensitive data in log files", target: "Java" },
  { id: "CVE-2025-66614", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "MEDIUM", title: "tomcat: Client certificate verification bypass due to virtual host mapping", target: "Java" },
  { id: "CVE-2026-25854", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "MEDIUM", title: "Apache Tomcat: Open Redirect vulnerability via LoadBalancerDrainingValve", target: "Java" },
  { id: "CVE-2026-34500", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "MEDIUM", title: "Apache Tomcat: Authentication bypass via client certificate misconfiguration", target: "Java" },
  { id: "CVE-2025-55754", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "LOW", title: "tomcat: Apache Tomcat console manipulation", target: "Java" },
  { id: "CVE-2025-61795", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "LOW", title: "tomcat-catalina: Apache Tomcat Denial of service", target: "Java" },
  { id: "CVE-2026-24733", pkg: "org.apache.tomcat:tomcat-catalina (9.0.107)", severity: "LOW", title: "tomcat: security constraint bypass with HTTP/0.9", target: "Java" },
  { id: "CVE-2025-48989", pkg: "org.apache.tomcat:tomcat-coyote (9.0.107)", severity: "HIGH", title: "tomcat: HTTP/2 MadeYouReset DoS attack through control frames", target: "Java" },
  { id: "CVE-2026-24734", pkg: "org.apache.tomcat:tomcat-coyote (9.0.107)", severity: "HIGH", title: "Apache Tomcat: Certificate revocation bypass due to improper OCSP response validation", target: "Java" },
  { id: "CVE-2026-24880", pkg: "org.apache.tomcat:tomcat-tribes (9.0.107)", severity: "HIGH", title: "Apache Tomcat: HTTP Request/Response Smuggling via invalid chunk extension", target: "Java" },
  { id: "CVE-2026-29146", pkg: "org.apache.tomcat:tomcat-tribes (9.0.107)", severity: "HIGH", title: "Apache Tomcat: Information disclosure via Padding Oracle vulnerability in EncryptInterceptor", target: "Java" },
  { id: "CVE-2024-23944", pkg: "org.apache.zookeeper:zookeeper (3.7.2)", severity: "MEDIUM", title: "Apache ZooKeeper: Information disclosure in persistent watcher handling", target: "Java" },
  { id: "CVE-2025-67030", pkg: "org.codehaus.plexus:plexus-utils (3.3.0)", severity: "HIGH", title: "plexus-utils: Directory Traversal in extractFile method", target: "Java" },
  { id: "CVE-2024-22201", pkg: "org.eclipse.jetty.http2:http2-common (9.4.41.v20210516)", severity: "HIGH", title: "jetty: stop accepting new connections from valid clients", target: "Java" },
  { id: "CVE-2025-5115", pkg: "org.eclipse.jetty.http2:http2-common (9.4.41.v20210516)", severity: "HIGH", title: "jetty: HTTP/2 MadeYouReset DoS attack through HTTP/2 control frames", target: "Java" },
  { id: "CVE-2023-44487", pkg: "org.eclipse.jetty.http2:http2-common (9.4.41.v20210516)", severity: "MEDIUM", title: "HTTP/2: Multiple HTTP/2 enabled web servers vulnerable to Rapid Reset Attack DDoS", target: "Java" },
  { id: "CVE-2023-36478", pkg: "org.eclipse.jetty.http2:http2-hpack (9.4.41.v20210516)", severity: "HIGH", title: "jetty: hpack header values cause denial of service in http/2", target: "Java" },
  { id: "CVE-2026-2332", pkg: "org.eclipse.jetty:jetty-http (9.4.41.v20210516)", severity: "HIGH", title: "jetty-http: HTTP request smuggling via chunked extension quoted-string parsing", target: "Java" },
  { id: "CVE-2023-40167", pkg: "org.eclipse.jetty:jetty-http (9.4.41.v20210516)", severity: "MEDIUM", title: "jetty: Improper validation of HTTP/1 content-length", target: "Java" },
  { id: "CVE-2024-6763", pkg: "org.eclipse.jetty:jetty-http (9.4.41.v20210516)", severity: "MEDIUM", title: "jetty-http: Jetty URI parsing of invalid authority", target: "Java" },
  { id: "CVE-2022-2047", pkg: "org.eclipse.jetty:jetty-http (9.4.41.v20210516)", severity: "LOW", title: "jetty-http: improper hostname input handling", target: "Java" },
  { id: "CVE-2025-11143", pkg: "org.eclipse.jetty:jetty-http (9.4.41.v20210516)", severity: "LOW", title: "jetty-http: Security bypass due to differential URI parsing", target: "Java" },
  { id: "CVE-2019-17495", pkg: "org.webjars:swagger-ui (2.2.10-1)", severity: "CRITICAL", title: "Cross-site scripting in Swagger-UI", target: "Java" },
  { id: "CVE-2018-25031", pkg: "org.webjars:swagger-ui (2.2.10-1)", severity: "MEDIUM", title: "swagger-ui: Spoofing attack", target: "Java" },
];

// Helper: derive NIST NVD URL
const nvdUrl = (id) =>
  id.startsWith("GHSA-")
    ? `https://github.com/advisories/${id}`
    : `https://nvd.nist.gov/vuln/detail/${id}`;

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4 };

const SEVERITY_COLORS = {
  CRITICAL: { bg: "#ff2d55", text: "#fff" },
  HIGH: { bg: "#ff6b00", text: "#fff" },
  MEDIUM: { bg: "#f5a623", text: "#fff" },
  LOW: { bg: "#8e9bb5", text: "#fff" },
  NEGLIGIBLE: { bg: "#3d4a63", text: "#fff" },
};

function parseHtmlReport(html) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  const rows = doc.querySelectorAll("table tr");
  const vulns = [];
  rows.forEach((row, i) => {
    if (i === 0) return;
    const cells = row.querySelectorAll("td");
    if (cells.length < 4) return;
    vulns.push({
      severity: cells[0]?.textContent?.trim() || "",
      id: cells[1]?.textContent?.trim() || "",
      pkg: cells[2]?.textContent?.trim() || "",
      title: cells[3]?.textContent?.trim() || "",
      target: "Uploaded",
    });
  });
  return vulns;
}

function SeverityBadge({ level }) {
  const c = SEVERITY_COLORS[level] || { bg: "#555", text: "#fff" };
  return (
    <span style={{
      background: c.bg, color: c.text,
      padding: "2px 10px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, letterSpacing: 1,
      display: "inline-block", fontFamily: "monospace",
    }}>{level}</span>
  );
}

function StatusBadge({ status }) {
  const map = {
    open: { bg: "#1e2a3a", color: "#8e9bb5", label: "Open" },
    patched: { bg: "#0d2e1a", color: "#2ecc71", label: "✓ Patched" },
    ignored: { bg: "#2a1e0d", color: "#f5a623", label: "~ Ignored" },
  };
  const s = map[status] || map.open;
  return (
    <span style={{
      background: s.bg, color: s.color,
      padding: "2px 9px", borderRadius: 4,
      fontSize: 11, fontWeight: 600, cursor: "pointer",
      border: `1px solid ${s.color}33`, display: "inline-block",
    }}>{s.label}</span>
  );
}

export default function App() {
  const [activeView, setActiveView] = useState("base"); // "base" | "uploaded"
  const [uploadedVulns, setUploadedVulns] = useState(null);
  const [uploadedName, setUploadedName] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [patchStatus, setPatchStatus] = useState({}); // key: `${id}|${pkg}` => "open"|"patched"|"ignored"
  const [expandedRow, setExpandedRow] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [darkMode, setDarkMode] = useState(true);
  const fileRef = useRef();

  const vulns = activeView === "base" ? BASE_VULNERABILITIES : (uploadedVulns || []);

  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NEGLIGIBLE: 0 };
    vulns.forEach(v => { if (c[v.severity] !== undefined) c[v.severity]++; });
    return c;
  }, [vulns]);

  const filtered = useMemo(() => {
    let list = [...vulns];
    if (severityFilter !== "ALL") list = list.filter(v => v.severity === severityFilter);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(v =>
        v.id.toLowerCase().includes(q) ||
        v.pkg.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
    return list;
  }, [vulns, severityFilter, searchQuery]);

  const handleUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setUploadedName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const parsed = parseHtmlReport(ev.target.result);
      setUploadedVulns(parsed);
      setActiveView("uploaded");
    };
    reader.readAsText(file);
  };

  const cycleStatus = (key) => {
    const order = ["open", "patched", "ignored"];
    const cur = patchStatus[key] || "open";
    const next = order[(order.indexOf(cur) + 1) % order.length];
    setPatchStatus(prev => ({ ...prev, [key]: next }));
  };

  const bg = darkMode ? "#0b1120" : "#f0f4fa";
  const surface = darkMode ? "#111827" : "#ffffff";
  const surface2 = darkMode ? "#1a2235" : "#f7f9fc";
  const border = darkMode ? "#1e2d45" : "#dde3ef";
  const text = darkMode ? "#c9d8f0" : "#1a2235";
  const subtext = darkMode ? "#5a7099" : "#8896b0";
  const hoverBg = darkMode ? "#162035" : "#eef2fb";

  return (
    <div style={{ minHeight: "100vh", background: bg, color: text, fontFamily: "'IBM Plex Mono', monospace", transition: "background 0.3s" }}>
      <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />

      {/* ── Top Bar ── */}
      <div style={{
        background: surface, borderBottom: `1px solid ${border}`,
        padding: "0 24px", display: "flex", alignItems: "center",
        justifyContent: "space-between", height: 56, position: "sticky", top: 0, zIndex: 100,
        boxShadow: darkMode ? "0 2px 16px #00000066" : "0 2px 8px #0000001a"
      }}>
        {/* Left: title + nav */}
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: "#4a9eff", letterSpacing: 2, textTransform: "uppercase" }}>
            ▸ TrivyDash
          </span>
          <div style={{ width: 1, height: 28, background: border }} />
          <button onClick={() => setActiveView("base")} style={{
            background: activeView === "base" ? "#4a9eff22" : "transparent",
            color: activeView === "base" ? "#4a9eff" : subtext,
            border: activeView === "base" ? "1px solid #4a9eff55" : "1px solid transparent",
            padding: "5px 14px", borderRadius: 5, cursor: "pointer", fontSize: 12, fontWeight: 600,
            fontFamily: "inherit", transition: "all 0.2s"
          }}>
            Base Report
          </button>
          {uploadedVulns && (
            <button onClick={() => setActiveView("uploaded")} style={{
              background: activeView === "uploaded" ? "#2ecc7122" : "transparent",
              color: activeView === "uploaded" ? "#2ecc71" : subtext,
              border: activeView === "uploaded" ? "1px solid #2ecc7155" : "1px solid transparent",
              padding: "5px 14px", borderRadius: 5, cursor: "pointer", fontSize: 12, fontWeight: 600,
              fontFamily: "inherit", transition: "all 0.2s"
            }}>
              ↑ {uploadedName || "Uploaded"}
            </button>
          )}
        </div>

        {/* Right: search, dark mode, upload */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search CVE, package…"
            style={{
              background: surface2, border: `1px solid ${border}`, color: text,
              padding: "5px 12px", borderRadius: 5, fontSize: 12, fontFamily: "inherit",
              outline: "none", width: 200,
            }}
          />
          <button onClick={() => setDarkMode(d => !d)} style={{
            background: surface2, border: `1px solid ${border}`, color: text,
            padding: "5px 10px", borderRadius: 5, cursor: "pointer", fontSize: 13,
            fontFamily: "inherit"
          }}>{darkMode ? "☀" : "☾"}</button>
          <input ref={fileRef} type="file" accept=".html,.xml" style={{ display: "none" }} onChange={handleUpload} />
          <button onClick={() => fileRef.current.click()} style={{
            background: "#4a9eff", color: "#fff", border: "none",
            padding: "6px 16px", borderRadius: 5, cursor: "pointer",
            fontSize: 12, fontWeight: 700, fontFamily: "inherit", letterSpacing: 0.5,
          }}>
            ↑ Upload Report
          </button>
        </div>
      </div>

      {/* ── Main ── */}
      <div style={{ padding: "24px 28px" }}>

        {/* Report header */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: text }}>
              Trivy Report — OpenSILEX
            </h1>
            <span style={{ fontSize: 13, color: subtext }}>
              {activeView === "base" ? "Base · 2026" : `Uploaded · ${uploadedName}`}
            </span>
            <span style={{
              background: "#4a9eff22", color: "#4a9eff", border: "1px solid #4a9eff44",
              borderRadius: 4, padding: "1px 10px", fontSize: 12, fontWeight: 700,
            }}>
              {vulns.length} vulns
            </span>
          </div>
        </div>

        {/* ── Severity filter pills ── */}
        <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"].map(s => {
            const active = severityFilter === s;
            const col = SEVERITY_COLORS[s];
            const count = s === "ALL" ? vulns.length : (counts[s] || 0);
            return (
              <button key={s} onClick={() => setSeverityFilter(s)} style={{
                background: active ? (col?.bg || "#4a9eff") : surface2,
                color: active ? (col?.text || "#fff") : subtext,
                border: `1px solid ${active ? (col?.bg || "#4a9eff") : border}`,
                padding: "5px 14px", borderRadius: 20, cursor: "pointer",
                fontSize: 12, fontWeight: 600, fontFamily: "inherit",
                transition: "all 0.18s",
              }}>
                {s === "ALL" ? `All (${count})` : `${s[0]}${s.slice(1).toLowerCase()} (${count})`}
              </button>
            );
          })}
        </div>

        {/* ── Table ── */}
        <div style={{ background: surface, border: `1px solid ${border}`, borderRadius: 8, overflow: "hidden" }}>
          {/* Table header */}
          <div style={{
            display: "grid",
            gridTemplateColumns: activeView === "base"
              ? "110px 1fr 180px 90px 130px 140px"
              : "110px 1fr 180px 90px 130px",
            background: surface2, borderBottom: `1px solid ${border}`,
            padding: "10px 16px", gap: 12,
          }}>
            {["Severity", "Title / Package", "CVE / ID", "Target", "Status",
              ...(activeView === "base" ? ["Remediation"] : [])
            ].map(h => (
              <span key={h} style={{ fontSize: 10, fontWeight: 700, color: subtext, textTransform: "uppercase", letterSpacing: 1.5 }}>{h}</span>
            ))}
          </div>

          {/* Rows */}
          {filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: subtext, fontSize: 13 }}>No vulnerabilities match the current filter.</div>
          ) : filtered.map((v, i) => {
            const key = `${v.id}|${v.pkg}`;
            const status = patchStatus[key] || "open";
            const isExpanded = expandedRow === key;
            const rowBg = isExpanded ? hoverBg : (i % 2 === 0 ? surface : surface2);

            return (
              <div key={`${key}-${i}`} style={{ borderBottom: `1px solid ${border}` }}>
                <div
                  onClick={() => setExpandedRow(isExpanded ? null : key)}
                  style={{
                    display: "grid",
                    gridTemplateColumns: activeView === "base"
                      ? "110px 1fr 180px 90px 130px 140px"
                      : "110px 1fr 180px 90px 130px",
                    padding: "10px 16px", gap: 12, alignItems: "center",
                    background: rowBg, cursor: "pointer", transition: "background 0.15s",
                    opacity: status === "patched" ? 0.5 : 1,
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = hoverBg}
                  onMouseLeave={e => e.currentTarget.style.background = rowBg}
                >
                  <div><SeverityBadge level={v.severity} /></div>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: text, lineHeight: 1.4, marginBottom: 2 }}>{v.title}</div>
                    <div style={{ fontSize: 11, color: subtext, fontFamily: "'IBM Plex Mono', monospace" }}>{v.pkg}</div>
                  </div>
                  <div>
                    <a
                      href={nvdUrl(v.id)}
                      target="_blank"
                      rel="noreferrer"
                      onClick={e => e.stopPropagation()}
                      style={{ color: "#4a9eff", fontSize: 11, textDecoration: "none", fontFamily: "monospace" }}
                    >{v.id}</a>
                  </div>
                  <div style={{ fontSize: 11, color: subtext }}>{v.target}</div>
                  <div onClick={e => { e.stopPropagation(); cycleStatus(key); }}>
                    <StatusBadge status={status} />
                  </div>
                  {activeView === "base" && (
                    <div>
                      <a
                        href={nvdUrl(v.id)}
                        target="_blank"
                        rel="noreferrer"
                        onClick={e => e.stopPropagation()}
                        style={{
                          color: "#2ecc71", fontSize: 11, textDecoration: "none",
                          border: "1px solid #2ecc7133", padding: "2px 8px",
                          borderRadius: 4, background: "#0d2e1a", display: "inline-block",
                        }}
                      >
                        {v.id.startsWith("GHSA") ? "GitHub ↗" : "NIST ↗"}
                      </a>
                    </div>
                  )}
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div style={{
                    background: darkMode ? "#0d1829" : "#eef4ff",
                    borderTop: `1px solid ${border}`, padding: "14px 20px 14px 36px",
                    fontSize: 12, color: subtext,
                  }}>
                    <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
                      <div><span style={{ color: text, fontWeight: 600 }}>ID:</span> {v.id}</div>
                      <div><span style={{ color: text, fontWeight: 600 }}>Package:</span> {v.pkg}</div>
                      <div><span style={{ color: text, fontWeight: 600 }}>Target:</span> {v.target}</div>
                      <div><span style={{ color: text, fontWeight: 600 }}>Status:</span>{" "}
                        <span style={{ cursor: "pointer" }} onClick={() => cycleStatus(key)}>
                          <StatusBadge status={patchStatus[key] || "open"} />
                        </span>
                        <span style={{ marginLeft: 8, fontSize: 10, color: subtext }}>(click to cycle)</span>
                      </div>
                    </div>
                    <div style={{ marginTop: 10 }}>
                      <span style={{ color: text, fontWeight: 600 }}>Links: </span>
                      <a href={nvdUrl(v.id)} target="_blank" rel="noreferrer"
                        style={{ color: "#4a9eff", marginRight: 14 }}>
                        {v.id.startsWith("GHSA") ? "GitHub Advisory" : "NIST NVD"} ↗
                      </a>
                      <a href={`https://www.google.com/search?q=${encodeURIComponent(v.id + " patch fix")}`}
                        target="_blank" rel="noreferrer" style={{ color: "#2ecc71" }}>
                        Search patches ↗
                      </a>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div style={{ marginTop: 16, fontSize: 11, color: subtext, textAlign: "right" }}>
          Showing {filtered.length} of {vulns.length} vulnerabilities · Click any row to expand · Click status badge to cycle Open → Patched → Ignored
        </div>
      </div>
    </div>
  );
}
