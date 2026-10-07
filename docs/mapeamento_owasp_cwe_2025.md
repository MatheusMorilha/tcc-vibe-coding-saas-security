# Mapeamento OWASP Top 10:2025 → CWE

Documentação de referência do dicionário `MAPEAMENTO_OWASP` usado em `scripts/extrator_sast.py` para classificar cada achado de SAST (Semgrep / Snyk Code) em uma das dez categorias do OWASP Top 10:2025.

**Fonte:** levantamento manual a partir do site oficial do OWASP Top 10:2025, consultando a lista geral e a página de cada categoria:

- <https://top10.owasp.org/2025/>
- <https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/>
- <https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/>
- <https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/>
- <https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/>
- <https://top10.owasp.org/2025/A05_2025-Injection/>
- <https://top10.owasp.org/2025/A06_2025-Insecure_Design/>
- <https://top10.owasp.org/2025/A07_2025-Authentication_Failures/>
- <https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/>
- <https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
- <https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/>

**Validação:** este levantamento foi comparado, CWE a CWE, com o dicionário já implementado em `scripts/extrator_sast.py` — as 249 entradas coincidem integralmente, sem divergências e sem sobreposição de um mesmo CWE em mais de uma categoria.

---

## A01:2025 - Broken Access Control

40 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| CWE-23 | Relative Path Traversal |
| CWE-36 | Absolute Path Traversal |
| CWE-59 | Improper Link Resolution Before File Access ('Link Following') |
| CWE-61 | UNIX Symbolic Link (Symlink) Following |
| CWE-65 | Windows Hard Link |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| CWE-201 | Exposure of Sensitive Information Through Sent Data |
| CWE-219 | Storage of File with Sensitive Data Under Web Root |
| CWE-276 | Incorrect Default Permissions |
| CWE-281 | Improper Preservation of Permissions |
| CWE-282 | Improper Ownership Management |
| CWE-283 | Unverified Ownership |
| CWE-284 | Improper Access Control |
| CWE-285 | Improper Authorization |
| CWE-352 | Cross-Site Request Forgery (CSRF) |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor |
| CWE-377 | Insecure Temporary File |
| CWE-379 | Creation of Temporary File in Directory with Insecure Permissions |
| CWE-402 | Transmission of Private Resources into a New Sphere ('Resource Leak') |
| CWE-424 | Improper Protection of Alternate Path |
| CWE-425 | Direct Request ('Forced Browsing') |
| CWE-441 | Unintended Proxy or Intermediary ('Confused Deputy') |
| CWE-497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory |
| CWE-540 | Inclusion of Sensitive Information in Source Code |
| CWE-548 | Exposure of Information Through Directory Listing |
| CWE-552 | Files or Directories Accessible to External Parties |
| CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key |
| CWE-601 | URL Redirection to Untrusted Site ('Open Redirect') |
| CWE-615 | Inclusion of Sensitive Information in Source Code Comments |
| CWE-639 | Authorization Bypass Through User-Controlled Key |
| CWE-668 | Exposure of Resource to Wrong Sphere |
| CWE-732 | Incorrect Permission Assignment for Critical Resource |
| CWE-749 | Exposed Dangerous Method or Function |
| CWE-862 | Missing Authorization |
| CWE-863 | Incorrect Authorization |
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-922 | Insecure Storage of Sensitive Information |
| CWE-1275 | Sensitive Cookie with Improper SameSite Attribute |


## A02:2025 - Security Misconfiguration

16 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-5 | J2EE Misconfiguration: Data Transmission Without Encryption |
| CWE-11 | ASP.NET Misconfiguration: Creating Debug Binary |
| CWE-13 | ASP.NET Misconfiguration: Password in Configuration File |
| CWE-15 | External Control of System or Configuration Setting |
| CWE-16 | Configuration |
| CWE-260 | Password in Configuration File |
| CWE-315 | Cleartext Storage of Sensitive Information in a Cookie |
| CWE-489 | Active Debug Code |
| CWE-526 | Exposure of Sensitive Information Through Environmental Variables |
| CWE-547 | Use of Hard-coded, Security-relevant Constants |
| CWE-611 | Improper Restriction of XML External Entity Reference |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| CWE-776 | Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |
| CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag |
| CWE-1174 | ASP.NET Misconfiguration: Improper Model Validation |


## A03:2025 - Software Supply Chain Failures

6 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-447 | Use of Obsolete Function |
| CWE-1035 | 2017 Top 10 A9: Using Components with Known Vulnerabilities |
| CWE-1104 | Use of Unmaintained Third Party Components |
| CWE-1329 | Reliance on Component That is Not Updateable |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component |
| CWE-1395 | Dependency on Vulnerable Third-Party Component |


## A04:2025 - Cryptographic Failures

32 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-261 | Weak Encoding for Password |
| CWE-296 | Improper Following of a Certificate's Chain of Trust |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-320 | Key Management Errors (Prohibited) |
| CWE-321 | Use of Hard-coded Cryptographic Key |
| CWE-322 | Key Exchange without Entity Authentication |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption |
| CWE-324 | Use of a Key Past its Expiration Date |
| CWE-325 | Missing Required Cryptographic Step |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-328 | Reversible One-Way Hash |
| CWE-329 | Not Using a Random IV with CBC Mode |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-331 | Insufficient Entropy |
| CWE-332 | Insufficient Entropy in PRNG |
| CWE-334 | Small Space of Random Values |
| CWE-335 | Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG) |
| CWE-336 | Same Seed in Pseudo-Random Number Generator (PRNG) |
| CWE-337 | Predictable Seed in Pseudo-Random Number Generator (PRNG) |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG) |
| CWE-340 | Generation of Predictable Numbers or Identifiers |
| CWE-342 | Predictable Exact Value from Previous Values |
| CWE-347 | Improper Verification of Cryptographic Signature |
| CWE-523 | Unprotected Transport of Credentials |
| CWE-757 | Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade') |
| CWE-759 | Use of a One-Way Hash without a Salt |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt |
| CWE-780 | Use of RSA Algorithm without OAEP |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort |
| CWE-1240 | Use of a Cryptographic Primitive with a Risky Implementation |
| CWE-1241 | Use of Predictable Algorithm in Random Number Generator |


## A05:2025 - Injection

37 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-20 | Improper Input Validation |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') |
| CWE-76 | Improper Neutralization of Equivalent Special Elements |
| CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') |
| CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |
| CWE-80 | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) |
| CWE-83 | Improper Neutralization of Script in Attributes in a Web Page |
| CWE-86 | Improper Neutralization of Invalid Characters in Identifiers in Web Pages |
| CWE-88 | Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') |
| CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') |
| CWE-91 | XML Injection (aka Blind XPath Injection) |
| CWE-93 | Improper Neutralization of CRLF Sequences ('CRLF Injection') |
| CWE-94 | Improper Control of Generation of Code ('Code Injection') |
| CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') |
| CWE-96 | Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection') |
| CWE-97 | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page |
| CWE-98 | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') |
| CWE-99 | Improper Control of Resource Identifiers ('Resource Injection') |
| CWE-103 | Struts: Incomplete validate() Method Definition |
| CWE-104 | Struts: Form Bean Does Not Extend Validation Class |
| CWE-112 | Missing XML Validation |
| CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting') |
| CWE-114 | Process Control |
| CWE-115 | Misinterpretation of Output |
| CWE-116 | Improper Encoding or Escaping of Output |
| CWE-129 | Improper Validation of Array Index |
| CWE-159 | Improper Handling of Invalid Use of Special Elements |
| CWE-470 | Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') |
| CWE-493 | Critical Public Variable Without Final Modifier |
| CWE-500 | Public Static Field Not Marked Final |
| CWE-564 | SQL Injection: Hibernate |
| CWE-610 | Externally Controlled Reference to a Resource in Another Sphere |
| CWE-643 | Improper Neutralization of Data within XPath Expressions ('XPath Injection') |
| CWE-644 | Improper Neutralization of HTTP Headers for Scripting Syntax |
| CWE-917 | Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection') |


## A06:2025 - Insecure Design

39 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-73 | External Control of File Name or Path |
| CWE-183 | Permissive List of Allowed Inputs |
| CWE-256 | Unprotected Storage of Credentials |
| CWE-266 | Incorrect Privilege Assignment |
| CWE-269 | Improper Privilege Management |
| CWE-286 | Incorrect User Management |
| CWE-311 | Missing Encryption of Sensitive Data |
| CWE-312 | Cleartext Storage of Sensitive Information |
| CWE-313 | Cleartext Storage in a File or on Disk |
| CWE-316 | Cleartext Storage of Sensitive Information in Memory |
| CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') |
| CWE-382 | J2EE Bad Practices: Use of System.exit() |
| CWE-419 | Unprotected Primary Channel |
| CWE-434 | Unrestricted Upload of File with Dangerous Type |
| CWE-436 | Interpretation Conflict |
| CWE-444 | Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') |
| CWE-451 | User Interface (UI) Misrepresentation of Critical Information |
| CWE-454 | External Initialization of Trusted Variables or Data Stores |
| CWE-472 | External Control of Assumed-Immutable Web Parameter |
| CWE-501 | Trust Boundary Violation |
| CWE-522 | Insufficiently Protected Credentials |
| CWE-525 | Use of Web Browser Cache Containing Sensitive Information |
| CWE-539 | Use of Persistent Cookies Containing Sensitive Information |
| CWE-598 | Use of GET Request Method With Sensitive Query Strings |
| CWE-602 | Client-Side Enforcement of Server-Side Security |
| CWE-628 | Function Call with Incorrectly Specified Arguments |
| CWE-642 | External Control of Critical State Data |
| CWE-646 | Reliance on File Name or Extension of Externally-Supplied File |
| CWE-653 | Insufficient Compartmentalization |
| CWE-656 | Reliance on Security Through Obscurity |
| CWE-657 | Violation of Secure Design Principles |
| CWE-676 | Use of Potentially Dangerous Function |
| CWE-693 | Protection Mechanism Failure |
| CWE-799 | Improper Control of Interaction Frequency |
| CWE-807 | Reliance on Untrusted Inputs in a Security Decision |
| CWE-841 | Improper Enforcement of Behavioral Workflow |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames |
| CWE-1022 | Use of Web Link to Untrusted Target with window.opener Access |
| CWE-1125 | Excessive Attack Surface |


## A07:2025 - Authentication Failures

36 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-258 | Empty Password in Configuration File |
| CWE-259 | Use of Hard-coded Password |
| CWE-287 | Improper Authentication |
| CWE-288 | Authentication Bypass Using an Alternate Path or Channel |
| CWE-289 | Authentication Bypass by Alternate Name |
| CWE-290 | Authentication Bypass by Spoofing |
| CWE-291 | Reliance on IP Address for Authentication |
| CWE-293 | Using Referer Field for Authentication |
| CWE-294 | Authentication Bypass by Capture-replay |
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
| CWE-298 | Improper Validation of Certificate with Host Mismatch |
| CWE-299 | Improper Validation of Certificate with Host Mismatch |
| CWE-300 | Channel Accessible by Non-Endpoint |
| CWE-302 | Authentication Bypass by Assumed-Immutable Data |
| CWE-303 | Incorrect Implementation of Authentication Algorithm |
| CWE-304 | Missing Critical Step in Authentication |
| CWE-305 | Authentication Bypass by Primary Weakness |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts |
| CWE-308 | Use of Single-factor Authentication |
| CWE-309 | Use of Password System for Primary Authentication |
| CWE-346 | Origin Validation Error |
| CWE-350 | Reliance on Reverse DNS Resolution for a Security-Critical Action |
| CWE-384 | Session Fixation |
| CWE-521 | Weak Password Requirements |
| CWE-613 | Insufficient Session Expiration |
| CWE-620 | Unverified Password Change |
| CWE-640 | Weak Password Recovery Mechanism for Forgotten Password |
| CWE-798 | Use of Hard-coded Credentials |
| CWE-940 | Improper Verification of Source of a Communication Channel |
| CWE-941 | Incorrectly Specified Destination in a Communication Channel |
| CWE-1390 | Weak Authentication |
| CWE-1391 | Use of Weak Credentials |
| CWE-1392 | Use of Default Credentials |
| CWE-1393 | Use of Default Password |


## A08:2025 - Software or Data Integrity Failures

14 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-345 | Insufficient Verification of Data Authenticity |
| CWE-353 | Missing Support for Integrity Check |
| CWE-426 | Untrusted Search Path |
| CWE-427 | Uncontrolled Search Path Element |
| CWE-494 | Download of Code Without Integrity Check |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-506 | Embedded Malicious Code |
| CWE-509 | Replicating Malicious Code (Virus or Worm) |
| CWE-565 | Reliance on Cookies without Validation and Integrity Checking |
| CWE-784 | Reliance on Cookies without Validation and Integrity Checking in a Security Decision |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |
| CWE-830 | Inclusion of Web Functionality from an Untrusted Source |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| CWE-926 | Improper Export of Android Application Components |


## A09:2025 - Security Logging and Alerting Failures

5 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-117 | Improper Output Neutralization for Logs |
| CWE-221 | Information Loss of Omission |
| CWE-223 | Omission of Security-relevant Information |
| CWE-532 | Insertion of Sensitive Information into Log File |
| CWE-778 | Insufficient Logging |


## A10:2025 - Mishandling of Exceptional Conditions

24 CWEs mapeados.

| CWE | Descrição |
|---|---|
| CWE-209 | Generation of Error Message Containing Sensitive Information |
| CWE-215 | Insertion of Sensitive Information Into Debugging Code |
| CWE-234 | Failure to Handle Missing Parameter |
| CWE-235 | Improper Handling of Extra Parameters |
| CWE-248 | Uncaught Exception |
| CWE-252 | Unchecked Return Value |
| CWE-274 | Improper Handling of Insufficient Privileges |
| CWE-280 | Improper Handling of Insufficient Permissions or Privileges |
| CWE-369 | Divide By Zero |
| CWE-390 | Detection of Error Condition Without Action |
| CWE-391 | Unchecked Error Condition |
| CWE-394 | Unexpected Status Code or Return Value |
| CWE-396 | Declaration of Catch for Generic Exception |
| CWE-397 | Declaration of Throws for Generic Exception |
| CWE-460 | Improper Cleanup on Thrown Exception |
| CWE-476 | NULL Pointer Dereference |
| CWE-478 | Missing Default Case in Multiple Condition Expression |
| CWE-484 | Omitted Break Statement in Switch |
| CWE-550 | Server-generated Error Message Containing Sensitive Information |
| CWE-636 | Not Failing Securely ('Failing Open') |
| CWE-703 | Improper Check or Handling of Exceptional Conditions |
| CWE-754 | Improper Check for Unusual or Exceptional Conditions |
| CWE-755 | Improper Handling of Exceptional Conditions |
| CWE-756 | Missing Custom Error Page |
