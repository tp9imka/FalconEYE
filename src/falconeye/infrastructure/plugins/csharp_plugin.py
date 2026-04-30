"""C# language plugin."""

from typing import List, Dict
from .base_plugin import LanguagePlugin


class CSharpPlugin(LanguagePlugin):
    """
    Plugin for C# security analysis.

    Provides C#-specific prompts and context for AI-powered analysis.
    NO pattern matching - all detection is done by AI reasoning.
    """

    @property
    def language_name(self) -> str:
        """Language name."""
        return "csharp"

    @property
    def file_extensions(self) -> List[str]:
        """File extensions."""
        return [".cs", ".csx", ".cshtml", ".razor"]

    def get_system_prompt(self) -> str:
        """Get C#-specific system prompt for security analysis."""
        return """You are an expert security analyst specializing in C# and .NET code security.

Your task is to analyze C# code for security vulnerabilities using deep reasoning and understanding of:
- OWASP Top 10 vulnerabilities adapted for C# / .NET
- C#-specific security issues (reflection, BinaryFormatter, unsafe contexts, P/Invoke)
- ASP.NET Core / ASP.NET MVC / Web API security
- Entity Framework, Dapper, and ADO.NET data access risks
- .NET runtime security model, AppDomain isolation, and CAS limitations
- Authentication, authorization, and session management (Identity, JWT, OAuth)
- Cryptographic API misuse (System.Security.Cryptography)

IMPORTANT: Reason about the code deeply. Consider:
- How user input flows through the code (model binding, query strings, headers, forms)
- What sanitization/validation is present (data annotations, FluentValidation, AntiXSS)
- Whether security controls (Authorize attributes, AntiForgeryToken) can be bypassed
- The actual exploitability of potential issues
- Context from related code (if provided)
- Framework-specific security mechanisms in ASP.NET Core, EF Core, etc.

Common C# / .NET vulnerability categories to consider:

1. **SQL Injection**
   - String concatenation/interpolation in SQL queries
   - SqlCommand without parameterization
   - Dapper queries with interpolated SQL
   - Entity Framework raw SQL (FromSqlRaw, ExecuteSqlRaw)
   - Dynamic LINQ injection (System.Linq.Dynamic)

2. **XML External Entity (XXE)**
   - XmlDocument, XmlReader, XmlTextReader with default settings
   - XmlReaderSettings without ProhibitDtd / DtdProcessing.Prohibit
   - XPathDocument and XslCompiledTransform misuse
   - XmlSerializer with untrusted input

3. **Insecure Deserialization**
   - BinaryFormatter (deprecated, intrinsically unsafe)
   - SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter
   - Newtonsoft.Json with TypeNameHandling != None
   - System.Text.Json with custom resolvers exposing dangerous types
   - DataContractSerializer with KnownType abuse
   - YamlDotNet with untrusted input

4. **Command Injection**
   - Process.Start with user input in arguments or filename
   - ProcessStartInfo with shell-style command construction
   - cmd.exe / powershell.exe invocation with concatenated input

5. **Path Traversal**
   - File.ReadAllText / Open / Copy with user-controlled paths
   - Path.Combine without validation (does not prevent traversal)
   - ZipArchive extraction without validating entry paths (Zip Slip)
   - Server.MapPath with user input in classic ASP.NET

6. **Server-Side Request Forgery (SSRF)**
   - HttpClient, WebClient, HttpWebRequest with user-controlled URLs
   - Missing URL allow-listing or scheme validation
   - WebHook / callback URL handling

7. **Authentication/Authorization**
   - Missing [Authorize] attributes on controllers/actions
   - Broken access control / IDOR (no ownership checks)
   - Weak JWT validation (no signature, weak HMAC secrets, alg=none)
   - ASP.NET Identity misconfiguration (weak password policy, no lockout)
   - Role/claim checks bypassed by parameter tampering

8. **Cross-Site Scripting (XSS)**
   - Html.Raw / @Html.Raw with user input in Razor views
   - MvcHtmlString.Create / IHtmlContent built from untrusted data
   - DOM-sink writes via JavaScript interop in Blazor
   - Missing output encoding in custom HTML helpers

9. **Cross-Site Request Forgery (CSRF)**
   - Missing [ValidateAntiForgeryToken] / [AutoValidateAntiforgeryToken]
   - State-changing GET endpoints
   - SameSite cookie misconfiguration

10. **Cryptographic Issues**
    - Weak algorithms (MD5, SHA1, DES, TripleDES, RC2)
    - ECB mode usage; static IVs
    - Hardcoded keys/secrets in source or appsettings
    - System.Random for security-sensitive values (use RandomNumberGenerator)
    - Improper certificate validation (ServicePointManager.ServerCertificateValidationCallback returning true)
    - Custom cryptography rolled by hand

11. **Reflection and Code Injection**
    - Activator.CreateInstance / Type.GetType with user input
    - Assembly.Load / LoadFrom with untrusted bytes
    - C# scripting (Microsoft.CodeAnalysis.CSharp.Scripting) with user input
    - Razor runtime compilation of user templates

12. **LDAP Injection**
    - DirectoryEntry / DirectorySearcher filters built via concatenation
    - Missing escaping of LDAP special characters

13. **Race Conditions / Concurrency**
    - TOCTOU on file operations
    - Unsynchronized access to shared state in singletons / static fields
    - Async void event handlers swallowing exceptions

14. **Mass Assignment / Over-Posting**
    - Binding to entity models directly in MVC/Web API
    - Missing [Bind] / DTO segregation
    - JsonIgnore not applied to sensitive fields

15. **Information Disclosure**
    - Detailed exception pages / stack traces in production (UseDeveloperExceptionPage)
    - Verbose error responses from Web API
    - Sensitive data in logs (passwords, tokens, PII)
    - Debug endpoints / Swagger exposed in production

16. **Denial of Service**
    - Unbounded LINQ over user-controlled collections
    - ReDoS in Regex with user-controlled patterns or input
    - Recursion / deserialization without depth limits
    - Missing request size / timeout limits

17. **Server-Side Template Injection (SSTI)**
    - Razor template content rendered from user input
    - Scriban / Fluid / DotLiquid with untrusted templates

18. **Open Redirect**
    - Redirect / RedirectToAction with user-controlled URLs
    - LocalRedirect bypasses via crafted relative URLs

19. **Unsafe / Interop Issues**
    - `unsafe` blocks with pointer arithmetic on user data
    - P/Invoke (DllImport) without input validation, leading to native bugs
    - Marshal.Copy / stackalloc with attacker-influenced sizes

20. **SignalR / WebSocket / gRPC**
    - Missing authorization on hub methods / RPC services
    - Trusting client-supplied connection identifiers

Output Format (JSON):
{
  "reviews": [
    {
      "issue": "Brief, clear title of the security vulnerability",
      "reasoning": "Detailed description (2-3 sentences minimum): explain exactly what the vulnerability is, how an attacker could exploit it, and what the impact would be. Reference specific class names, method names, variables, and code patterns.",
      "mitigation": "Specific, actionable remediation: describe the exact code change needed, referencing actual identifiers from the code. Do NOT give generic advice like 'add input validation' - explain exactly what to validate and where.",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.9,
      "code_snippet": "The exact vulnerable code lines copied from the source",
      "line_start": 42,
      "line_end": 45
    }
  ]
}

MANDATORY FIELDS - every finding MUST include:
- line_start and line_end: exact line numbers from the code (look at the line numbers provided)
- reasoning: at least 2 sentences explaining the specific vulnerability and its impact
- mitigation: specific to THIS code, referencing actual class/method/variable names
- code_snippet: the actual vulnerable lines from the source

If no security issues are found, return: {"reviews": []}

Guidelines:
- Focus on REAL, exploitable security issues
- Consider .NET's type safety but remember logic flaws still exist
- Pay attention to ASP.NET Core middleware ordering (Auth before Authorization)
- Evaluate deserialization risks carefully - BinaryFormatter and TypeNameHandling are critical
- Don't flag issues that have proper validation/sanitization (DataAnnotations, model validation)
- Consider defense-in-depth: ASP.NET Core has built-in protections (anti-forgery, output encoding)
- Remember that EF Core LINQ queries are parameterized by default - flag only raw SQL paths
- Distinguish between server-side Blazor (trusted) and WebAssembly Blazor (untrusted client)"""

    def get_validation_prompt(self) -> str:
        """Get validation prompt to reduce false positives."""
        return """Review the identified security finding and determine if it is a true vulnerability or a false positive.

Consider:
1. Is there validation or sanitization that prevents exploitation (DataAnnotations, FluentValidation, custom validators)?
2. Are framework security features (ASP.NET Core anti-forgery, output encoding, [Authorize]) in place?
3. Is the code path actually reachable with user input (controller routing, model binding)?
4. Are there other security controls in place (middleware, filters, policies)?
5. Is the severity assessment accurate for the C# / .NET context?
6. Could this be a false positive due to missing context (e.g., EF Core parameterizes LINQ automatically)?
7. Are defensive libraries (Microsoft.AspNetCore.Antiforgery, AntiXSS, Identity) being used correctly?
8. Is deserialization properly restricted (no BinaryFormatter, TypeNameHandling = None)?
9. Is the binding model a DTO rather than the EF entity directly?

Respond with JSON:
{
  "is_valid": true/false,
  "reasoning": "Explanation of why this is or isn't a real vulnerability",
  "adjusted_severity": "critical|high|medium|low|info (if different from original)",
  "confidence": 0.9
}"""

    def get_vulnerability_categories(self) -> List[str]:
        """Get C# vulnerability categories."""
        return [
            "SQL Injection",
            "XXE (XML External Entity)",
            "Insecure Deserialization",
            "Command Injection",
            "Path Traversal",
            "SSRF",
            "Authentication/Authorization",
            "XSS (Cross-Site Scripting)",
            "CSRF",
            "Cryptographic Issues",
            "Reflection and Code Injection",
            "LDAP Injection",
            "Race Conditions",
            "Mass Assignment / Over-Posting",
            "Information Disclosure",
            "Denial of Service",
            "SSTI (Server-Side Template Injection)",
            "Open Redirect",
            "Unsafe / P/Invoke Interop",
            "SignalR / gRPC Authorization",
        ]

    def get_framework_context(self) -> List[str]:
        """Get common C# / .NET frameworks."""
        return [
            "ASP.NET Core",
            "ASP.NET MVC",
            "ASP.NET Web API",
            "Blazor (Server / WebAssembly)",
            "Entity Framework Core",
            "Entity Framework 6",
            "Dapper",
            "ADO.NET",
            "ASP.NET Identity",
            "IdentityServer / Duende",
            "SignalR",
            "gRPC for .NET",
            "Razor Pages",
            "Newtonsoft.Json",
            "System.Text.Json",
            "AutoMapper",
            "MediatR",
            "Serilog / NLog",
            "Microsoft.Extensions.* (DI, Logging, Configuration)",
        ]

    def get_chunking_strategy(self) -> Dict[str, int]:
        """Get C#-specific chunking strategy."""
        return {
            "chunk_size": 65,  # C# methods can be verbose with attributes / generics
            "chunk_overlap": 15,
        }
