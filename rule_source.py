rule_groups = {
	1: {
		'name': 'Use a Wildcard to Avoid Verification',
		'Message': 'Explicit Disabling of HTTPS Certificate Validation via HTTP Library Parameters. Characteristic: Directly setting validation toggle (e.g., verify=False) in high-level HTTP library calls, affecting only the current request - representing an application-layer convenience-style security bypass.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	2: {
		'name': 'Creating a Custom String to avoid Verification of Certificates',
		'Message': 'SSL secures HTTPS connections; overwriting Certificate Authority (CA) bundles to bypass certificate verification compromises security and enables MiTM attacks.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	3: {
		'name': 'Use an unverified context to avoid HTTPS Verification',
		'Message': 'Global Certificate Validation Bypass via Unverified SSL Context Creation. Characteristic: Constructing certificate-unverified SSL context objects (e.g., ssl._create_unverified_context()), reusable across multiple requests - representing a transport-layer infrastructure-level security flaw.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	4: {
		'name': 'Using HTTP instead of HTTPS',
		'Message': 'Developers should access APIs/web services via HTTPS (not HTTP) for SSL confidentiality; HTTP compromises security as per Wildcard Misuse Pattern',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	5: {
		'name': 'Using Insecure Random Number Generation',
		'Message': 'Insecure keys enable attackers to compromise encryption. Cryptographically strong randomness is essential. In Python, using random module for keys (salts) generation is insecure, the secrets module provides cryptographically secure alternatives.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Randomness",
		"Attack Type": "Predictability",
		"Analysis Method": ""
	},
	6: {
		'name': 'Using a static and insecure Salt',
		'Message': 'Password-Based Encryption (PBE) requires cryptographically secure random salts; predictable salts enable dictionary attacks and compromise encryption.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	7: {
		'name': 'Using an Insecure Mode',
		'Message': 'While developers may choose different algorithms for their encryption, they may choose the Electronic Codebook (ECB) mode. This mode is insecure as it breaks integrity and may leak information. It is recommended to use different modes such as Cipher Block Chaining (CBC)',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	8: {
		'name': 'Using less than 1000 Iterations',
		'Message': 'Password-Based Encryption (PBE) requires iteration counts ≥1000; lower values enable brute-force attacks and violate Python security standards.',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	9: {
		'name': 'Using Insecure Block Ciphers',
		'Message': 'Ciphers such as Data Encryption Standard (DES) are considered insecure. Should use the secure symmetric cipher Advanced Encryption Standard (AES). However, The use of non-randomly generated keys, insecure encryption modes (such as ECB), or fixed/predictable initialization vectors (IVs) in AES are also considered insecure.',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	10: {
		'name': 'Using an Insecure Asymmetric Cipher',
		'Message': 'Asymmetric encryption requires public/private keys for confidentiality and integrity; Example: RSA/DSA must use ≥2048-bit keys to remain cryptographically secure',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "C/A",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	 },
	11: {
		'name': 'Using an insecure Hash',
		'Message': 'Developers use cryptographic hashes (like SHA256 or SHA512) to verify message or file integrity by generating a unique digest. Broken hashes like MD2, MD4, MD5, and SHA1 are insecure because different inputs can produce the same digest, compromising integrity.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Integrity",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	12: {
		'name': 'Not verifying the Json Web Token (JWT)',
		'Message': 'JWT enable compact authentication but must retain default signature verification; disabling verification fundamentally compromises security.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	13: {
		'name': 'Using a deprecated or invalid Transport Layer Security (TLS) Version',
		'Message': 'Must avoid insecure/deprecated TLS/SSL versions; these enable MiTM attacks—use only latest versions.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Confidentiality",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	14: {
		'name': 'Using an Insecure Protocol',
		'Message': 'When connecting to certain systems or computers, developers can use the Lightweight Directory Access Protocol (LDAP) protocol. Developers may connect using LDAP without providing credentials, which allows unauthenticated connections. To ensure a confidential connection, it is recommended to provide credentials.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	15: {
		'__link__': 'https://docs.python.org/3/library/xml.html#xml-vulnerabilities',
		'name': 'Using an insecure XML Deserialization',
		'Message': 'Using an Insecure Extensible Markup Language (XML) Deserialization. Developers who use XML objects should use secure methods to protect against Server-Side Request Forgery (SSRF) attacks. SSRF attacks will allow attackers to read the configuration information about the server. It is recommended for developers to disable network access and resolve remote entities.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Integrity",
		"Attack Type": "Deserialization",
		"Analysis Method": ""
	},
	16: {
		'__link__': 'LINK',
		'name': 'Using an insecure YAML Deserialization',
		'Message': 'YAML modules may be exploited in a similar way to the XML Deserialization Misuse pattern. Unsafe usage of YAML grants attackers access to Remote Code Execution (RCE) by simple deserialization. Each YAML module has a safe deserialization method that is recommended.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Integrity",
		"Attack Type": "Deserialization",
		"Analysis Method": ""
	},
	17: {
		'__link__': 'https://docs.python.org/3/library/pickle.html#restricting-globals',
		'name': 'Using an Insecure Pickle Deserialization',
		'Message': 'The Pickle format is inherently insecure and enables Remote Code Execution; avoid entirely, but if required, sign files for integrity verification.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Integrity",
		"Attack Type": "Deserialization",
		"Analysis Method": ""
	},
	18: {
		'__link__': 'https://rules.sonarsource.com/python/type/Vulnerability/RSPEC-2631',
		'name': 'Not properly escaping regular expressions (regex)',
		'Message': 'Developers who use regex should escape the input they pass in to avoid Denial of Service (DoS). If they do not escape regular expressions, the input passed can cause the computer to calculate the expression continuously. It is recommended to escape the input to better sanitize the input passed in the regular expression engine.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Integrity",
		"Attack Type": "Brute-Force",
		"Analysis Method": ""
	},
	-1: {
		'name': 'UNKNOWN',
		'Message': 'UNKNOWN',
		'CWE': 'UNKNOWN',
		'Severity': "UNKNOWN",
		"Crypto Property": "UNKNOWN",
		"Attack Type": "UNKNOWN",
		"Analysis Method": "UNKNOWN"
	},
}

rule_groups_java = {
	1: {
		'name': 'Cryptographic keys',
		'Message': 'Cryptographic keys must be unpredictable when using SecretKeySpec (byte array input). Hardcoded/constant byte arrays expose keys, enabling adversaries to access sensitive data. Generate unpredictable byte arrays for secure keys instead.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Predictable Secrets",
		"Analysis Method": ""
	},
	2: {
		'name': 'Passwords in Password-based Encryption (PBE)',
		'Message': 'PBE keys generated via PBEKeySpec require three parameters: password, salt, and iteration count. Hardcoded/constant passwords expose keys, enabling attackers to predict keys. Use unpredictable passwords in PBEKeySpec instead.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Predictable Secrets",
		"Analysis Method": ""
	},
	3: {
		'name': 'Passwords in KeyStore',
		'Message': 'KeyStore passwords (via java.security.KeyStore) protect stored keys/certificates. Hardcoded/constant passwords risk exposure of all secured items. Use unpredictable passwords to access the KeyStore instead.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Predictable Secrets",
		"Analysis Method": ""
	},
	4: {
		'name': 'Hostname Verifier',
		'Message': 'Hostname verification via HostnameVerifier.verify() must perform actual checks. Returning true by default enables URL spoofing, facilitating attacks like phishing.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	5: {
		'name': 'Certificate Validation',
		'Message': 'Certificate validation via X509TrustManager must implement proper checks. Empty validation methods trust all certificates, including untrusted ones, enabling Man-in-the-middle (MitM) attacks. ',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	6: {
		'name': 'SSL Sockets',
		'Message': 'SSL socket connections via SSLSocket require hostname verification (using HostnameVerifier). Omitting verification during socket creation enables insecure connections.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	7: {
		'name': 'Hypertext Transfer Protocol',
		'Message': 'When using java.net.URL, never employ HTTP for sensitive data transmission; always use HTTPS to prevent interception of unencrypted information.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "C/I/A",
		"Attack Type": "SSL/TLS MitM",
		"Analysis Method": ""
	},
	8: {
		'name': 'Pseudorandom Number Generator (PRNG)',
		'Message': 'When generating random values for cryptographic operations, never use java.util.Random; always employ java.security. SecureRandom to prevent predictable random values.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Randomness",
		"Attack Type": "Predictability",
		"Analysis Method": ""
	},
	9: {
		'name': 'Seeds in Pseudorandom Number Generator (PRNG)',
		'Message': 'PRNG seeding in SecureRandom must use non-deterministic seeds. Constant/static seeds cause predictable outputs on every run, creating security risks. Use random seeds instead.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Randomness",
		"Attack Type": "Predictability",
		"Analysis Method": ""
	},
	10: {
		'name': 'Salts in Password-based encryption (PBE)',
		'Message': 'PBE salts (via PBEParameterSpec) must be randomly generated. Constant/static salts enable dictionary attacks, producing predictable keys. Use cryptographically random salts instead.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	11: {
		'name': 'Mode of Operation',
		'Message': 'Cipher modes in javax.crypto.Cipher: ECB is insecure due to plaintext pattern leakage. Use CBC or GCM instead. ',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	12: {
		'name': 'Initialization Vector (IV)',
		'Message': 'Initialization Vectors (IVs) enhance cryptographic security when used with secret keys. Static/constant IVs introduce vulnerabilities by reducing randomness. Use unpredictable random IVs via IvParameterSpec instead.',
		'CWE': '',
		'Severity': "M",
		"Crypto Property": "Confidentiality",
		"Attack Type": "CPA",
		"Analysis Method": ""
	},
	13: {
		'name': 'Iteration Count in Password-based Encryption (PBE)',
		'Message': 'When configuring PBEParameterSpec, always set iteration counts above 1000 to ensure sufficient resistance against brute-force attacks.',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Brute-force",
		"Analysis Method": ""
	},
	14: {
		'name': 'Symmetric Ciphers',
		'Message': 'Symmetric ciphers use the same key for encryption and decryption. 64-bit ciphers (DES, Blowfish, RC4, RC2, IDEA) are broken due to feasible brute-force attacks and are insecure. AES (128-bit block size, 128/192/256-bit keys) should be used for security.',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "Confidentiality",
		"Attack Type": "Brute-force",
		"Analysis Method": ""
	},
	15: {
		'name': 'Asymmetric Ciphers',
		'Message': 'Asymmetric ciphers use public/private key pairs. 1024-bit RSA is broken due to feasible brute-force attacks. Always use ≥2048-bit keys for RSA security.',
		'CWE': '',
		'Severity': "L",
		"Crypto Property": "C/A",
		"Attack Type": "Brute-force",
		"Analysis Method": ""
	},
	16: {
		'name': 'Cryptographic Hash Functions',
		'Message': 'Cryptographic hash functions convert arbitrary input to a fixed-length hash. Broken functions (SHA1, MD4, MD5, MD2) are vulnerable to collisions (same hash for different inputs), causing security risks. Developers must use strong alternatives like SHA-256.',
		'CWE': '',
		'Severity': "H",
		"Crypto Property": "Integrity",
		"Attack Type": "Brute-force",
		"Analysis Method": ""
	},
	# 17: {
	# 	'name': 'Cryptographic MAC',
	# 	'Message': 'When implementing MAC algorithms, never use HmacMD5 or HmacSHA1; always employ HmacSHA256+ to prevent collision-based forgery attacks.',
	# 	'CWE': '',
	# 	'Severity': "H",
	# 	"Crypto Property": "Integrity",
	# 	"Attack Type": "Brute-force",
	# 	"Analysis Method": ""
	# },
	# 18: {
	# 	'name': 'Credentials in String',
	# 	'Message': 'When handling sensitive credentials, never store them in String variables; always use mutable char/byte arrays and clear immediately after use to prevent memory exposure.',
	# 	'CWE': '',
	# 	'Severity': "H",
	# 	"Crypto Property": "Integrity",
	# 	"Attack Type": "Brute-force",
	# 	"Analysis Method": ""
	# },
	-1: {
		'name': 'UNKNOWN',
		'Message': 'UNKNOWN',
		'CWE': 'UNKNOWN',
		'Severity': "UNKNOWN",
		"Crypto Property": "UNKNOWN",
		"Attack Type": "UNKNOWN",
		"Analysis Method": "UNKNOWN"
	},
}


