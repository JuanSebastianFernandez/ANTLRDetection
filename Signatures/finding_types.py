"""
Module: finding_types.py

This module defines standardized finding types, global regular expressions, and security signature
structures used by the static analysis system (SAST). Each programming language has a dedicated
signature class (e.g., Java, Python, C) that inherits from a common BaseSignatures class.

Components:
- Constants for common finding types.
- A global regular expression for detecting sensitive system paths.
- A base class with default dictionaries for imports, method calls, and other pattern types.
- Language-specific subclasses for defining customized detection patterns per language.

These definitions are used by listeners during AST traversal to flag suspicious code structures,
potential vulnerabilities, and obfuscation techniques.
"""

import re

# --- 1. STANDARDIZED FINDING TYPES (GLOBAL) ---
# These are 'finding_type' identifiers to be used across all SAST reports.

FINDING_TYPE_CODE_EXECUTION: str = "CODE_EXECUTION"
FINDING_TYPE_FILE_SYSTEM_ACCESS: str = "FILE_SYSTEM_ACCESS"
FINDING_TYPE_NETWORK_COMMUNICATION: str = "NETWORK_COMMUNICATION"
FINDING_TYPE_CRYPTOGRAPHIC_USE: str = "CRYPTOGRAPHIC_USE"
FINDING_TYPE_HARDCODED_CREDENTIALS: str = "HARDCODED_CREDENTIALS"
FINDING_TYPE_OBFUSCATION_TECHNIQUE: str = "OBFUSCATION_TECHNIQUE"
FINDING_TYPE_IMPROPER_ERROR_HANDLING: str = "IMPROPER_ERROR_HANDLING"
FINDING_TYPE_SELF_AWARE_BEHAVIOR: str = "SELF_AWARE_BEHAVIOR"
FINDING_TYPE_SENSITIVE_DATA_ACCESS: str = "SENSITIVE_DATA_ACCESS"
FINDING_TYPE_SYSTEM_INFO_ACCESS: str = "SYSTEM_INFO_ACCESS"

# --- 2. GLOBAL REGEX FOR SENSITIVE PATH DETECTION ---
# Shared regex for all language listeners to detect sensitive file system paths.
SENSITIVE_PATH_REGEX_GLOBAL: re.Pattern = re.compile(
    r"(C:\\\\|C:/|/)(Windows|Users|System32|Program Files|etc|root|home|var/log|bin|passwd|s?bin|usr|opt|srv|mnt|media|dev|proc|tmp|var|run|lib|usr/local|usr/share|var/tmp|var/run|sys|boot|init|lost\\+found|sbin|var/spool|var/mail|var/cache|var/lib|var/backups|etc/ssh|etc/passwd|etc/shadow|~/\\.ssh)",  # noqa
    re.IGNORECASE
)

# --- 3. BASE SIGNATURE CLASS ---
class BaseSignatures:
    """
    Abstract base class that defines the default structure for all security signature sets.
    Subclasses should override dictionaries for IMPORTS, METHOD_CALLS, STRUCTURAL_PATTERNS, etc.,
    to match language-specific behavior.

    Attributes:
        IMPORTS (dict): Dictionary of suspicious imports/modules or header inclusions.
        METHOD_CALLS (dict): Dictionary of dangerous or sensitive function or method calls.
        STRING_KEYWORDS (dict): Dictionary of high-risk substrings (e.g., credentials) in literals.
        NAMING_CONVENTIONS (dict): Dictionary of naming patterns used in obfuscation.
        STRUCTURAL_PATTERNS (dict): Dictionary of code structure issues (e.g., empty catch blocks).
    """
    IMPORTS: dict[str, dict[str, str]] = {}
    METHOD_CALLS: dict[str, dict[str, str]] = {}
    STRING_KEYWORDS: dict[str, dict[str, str]] = {
        "password": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Possible hardcoded credential."},
        "secret": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Possible hardcoded credential."},
        "apikey": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Possible hardcoded credential."},
        "privatekey": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Possible hardcoded credential."},
        "token": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "desc": "Possible hardcoded credential."}
    }
    NAMING_CONVENTIONS: dict[str, dict[str, str]] = {
        "OBFUSCATED_CLASS_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Suspicious or dynamically generated short class name."},
        "OBFUSCATED_METHOD_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "desc": "Suspiciously short method name."},
    }
    STRUCTURAL_PATTERNS: dict[str, dict[str, str]] = {}

    def __init__(self) -> None:
        """
        Initializes the BaseSignatures class.
        The global regex can be accessed from this base class or its subclasses.
        """
        pass

# --- 4. LANGUAGE-SPECIFIC SIGNATURE CLASSES ---
# Each class defines dictionaries adapted to each language's syntax and standard libraries.
# These are used during AST traversal by language-specific listeners.

class JavaSignatures(BaseSignatures):
    """
    Security Signatures for Java language.
    """
    IMPORTS: dict[str, dict[str, str]] = {
        "java.io.File": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "File manipulation capability."},
        "java.io.FileOutputStream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "File write capability, potential for encryption/overwrite."},
        "java.nio.file.Files": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "Advanced file manipulation capabilities (write, delete)."},
        "javax.crypto": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Use of Java Cryptography API (potential for file encryption)."},
        "java.net": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Network communication capability (potential for exfiltration or C2)."}
    }

    METHOD_CALLS: dict[str, dict[str, str]] = {
        "Runtime.getRuntime().exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Execution of native operating system commands."},
        "System.exit": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "desc": "Call to terminate program execution (flow control)."},
        ".delete": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "File deletion call."},
        "getClass().getProtectionDomain().getCodeSource().getLocation": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "Code attempting to locate its own execution path."}
    }
    STRING_KEYWORDS: dict[str, dict[str, str]] = BaseSignatures.STRING_KEYWORDS # Reusing base class definitions
    NAMING_CONVENTIONS: dict[str, dict[str, str]] = BaseSignatures.NAMING_CONVENTIONS # Reusing base class definitions

    STRUCTURAL_PATTERNS: dict[str, dict[str, str]] = { # These patterns are detected by logic in the listener, not by a direct dictionary lookup.
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Empty catch block that can hide critical errors."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Overridden method with an empty or very simple body, possible evasion technique."},
        "SELF_AWARE_CODE_FILE_DOT": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "desc": "Code accessing the current directory ('new File(\".\")'), possible prelude to self-modification."},
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "desc": "Access to sensitive system paths (e.g., /etc/passwd, C:\\Windows)."}
    }
    

class PythonSignatures(BaseSignatures):
    """
    Security Signatures for Python language.
    """
    IMPORTS: dict[str, dict[str, str]] = {
        "os": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Capability to interact with the file system/OS."},
        "subprocess": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Capability to create and manage subprocesses, potential for command execution."},
        "socket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Low-level network communication capability."},
        "urllib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Capability to make network requests."},
        "requests": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Capability to make HTTP/S requests."},
        "cryptography": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Use of a popular cryptography library."},
        "shutil": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "Capability to perform destructive file operations (e.g., rmtree)."},
        "sys": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "desc": "Access to system and interpreter parameters."},
        "io": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Capability to manipulate I/O streams."}
    }

    METHOD_CALLS: dict[str, dict[str, str]] = { # Includes patterns like 'eval(', 'exec(', 'os.system('
        "eval(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Dynamic code execution from a string."},
        "exec(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Dynamic code execution."},
        "os.system(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Execution of a command in the system shell."},
        "subprocess.run": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Execution of an external command (risky if used with shell=True)."},
        "pickle.load": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Deserialization of data with pickle, can lead to arbitrary code execution."},
        "open(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Generic file access."}
    }
    STRING_KEYWORDS: dict[str, dict[str, str]] = BaseSignatures.STRING_KEYWORDS # Reusing base class definitions
    NAMING_CONVENTIONS: dict[str, dict[str, str]] = BaseSignatures.NAMING_CONVENTIONS # Reusing base class definitions

    STRUCTURAL_PATTERNS: dict[str, dict[str, str]] = {
        "EMPTY_EXCEPT_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Empty 'except' block that can hide critical errors."},
        "SUSPICIOUS_PASS_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Function with 'pass' body, possible evasion or obfuscation technique."},
        "SELF_AWARE_CODE_PATH": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "Code attempting to access its own execution path."},
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "desc": "Access to sensitive system paths (e.g., /etc/passwd, C:\\Windows)."},
    }

class CSignatures(BaseSignatures):
    """
    Security Signatures for C language.
    """
    IMPORTS: dict[str, dict[str, str]] = { # In C, "imports" are header inclusions.
        "stdio.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Inclusion of stdio.h header (input/output operations)."},
        "stdlib.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "INFO", "desc": "Inclusion of stdlib.h header (potential for command execution via system())."},
        "windows.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "desc": "Inclusion of windows.h header (access to Windows APIs)."},
        "sys/socket.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Inclusion of header for network sockets."},
        "netinet/in.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Inclusion of header for internet addresses."},
        "arpa/inet.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Inclusion of header for internet address conversion functions."},
        "unistd.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Inclusion of unistd.h header (system calls like fork(), exec())."},
        "fcntl.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Inclusion of fcntl.h header (file control)."},
        "sys/mman.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Inclusion of header for memory management (mmap, potential for code injection)."},
        "crypt.h": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Inclusion of header for cryptography functions."}
    }

    METHOD_CALLS: dict[str, dict[str, str]] = {
        "strcpy": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of strcpy (potential buffer overflow, no boundary check)."}, # Classic vulnerability
        "strcat": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of strcat (potential buffer overflow, no boundary check)."},
        "gets": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of gets (buffer overflow, intrinsically insecure function)."},
        "sprintf": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of sprintf (potential buffer overflow if buffer is too small)."},
        "system": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Execution of operating system commands via system()."},
        "fork": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Creation of a new process (potential for malware spawn)."},
        "exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Exec family of functions (replacement of the current process, potential for payload)."}, # covers execve, execl, etc.
        "mmap": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "File/memory mapping (potential for code injection/modification)."},
        "VirtualAlloc": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Virtual memory allocation (Windows), common in exploits."},
        "CreateFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "File access (Windows API)."},
        "WriteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "File writing (Windows API)."},
        "DeleteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "File deletion (Windows API)."}
    }
    
    STRING_KEYWORDS: dict[str, dict[str, str]] = BaseSignatures.STRING_KEYWORDS # Reusing base class definitions

    NAMING_CONVENTIONS: dict[str, dict[str, str]] = BaseSignatures.NAMING_CONVENTIONS # Reusing base class definitions

    STRUCTURAL_PATTERNS: dict[str, dict[str, str]] = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "desc": "Access to sensitive system paths (e.g., /etc/passwd, C:\\Windows)."},
        "SELF_AWARE_CODE_ARGV0": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "Code attempting to access its own execution name (argv[0])."},
        "SIMPLE_FUNCTION_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Function with a very simple or empty body, possible evasion technique or placeholder."}
        # C does not have try-catch/except like Java/Python.
    }

class CppSignatures(BaseSignatures):
    """
    Security Signatures for C++ language.
    """
    IMPORTS: dict[str, dict[str, str]] = { # In C++, "imports" are #include directives.
        "iostream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Inclusion of iostream header (input/output operations)."},
        "fstream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "Inclusion of fstream header (file manipulation)."},
        "windows.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "desc": "Inclusion of windows.h header (access to Windows APIs)."},
        "sys/socket.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Inclusion of header for network sockets (Unix/Linux)."},
        "netinet/in.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Inclusion of header for internet addresses (Unix/Linux)."},
        "arpa/inet.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Inclusion of header for internet address conversion functions (Unix/Linux)."},
        "unistd.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Inclusion of unistd.h header (system calls like fork(), exec() in Unix/Linux)."},
        "fcntl.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Inclusion of fcntl.h header (file control in Unix/Linux)."},
        "sys/mman.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Inclusion of header for memory management (mmap, potential for code injection in Unix/Linux)."},
        "cryptopp": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Use of Crypto++ library (cryptography)."},
        "openssl": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Use of OpenSSL library (cryptography)."}
    }

    METHOD_CALLS: dict[str, dict[str, str]] = { # Includes C-style functions and C++ methods
        "strcpy": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of strcpy (potential buffer overflow, no boundary check)."},
        "strcat": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of strcat (potential buffer overflow, no boundary check)."},
        "gets": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of gets (buffer overflow, intrinsically insecure function)."},
        "sprintf": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "desc": "Use of sprintf (potential buffer overflow if buffer is too small)."},
        "system": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Execution of operating system commands via system()."},
        "fork": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Creation of a new process (potential for malware spawn)."},
        "exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Exec family of functions (replacement of the current process, potential for payload)."},
        "mmap": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "File/memory mapping (potential for code injection/modification)."},
        "VirtualAlloc": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "desc": "Virtual memory allocation (Windows), common in exploits."},
        "CreateFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "File access (Windows API)."},
        "WriteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "File writing (Windows API)."},
        "DeleteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "File deletion (Windows API)."},
        "ShellExecute": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Execution of external programs (Windows API)."},
        "URLDownloadToFile": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "desc": "File download from URL (Windows API)."}
    }
    
    STRING_KEYWORDS: dict[str, dict[str, str]] = BaseSignatures.STRING_KEYWORDS # Reusing base class definitions

    NAMING_CONVENTIONS: dict[str, dict[str, str]] = BaseSignatures.NAMING_CONVENTIONS # Reusing base class definitions

    STRUCTURAL_PATTERNS: dict[str, dict[str, str]] = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "MEDIUM", "desc": "Access to sensitive system paths (e.g., /etc/passwd, C:\\Windows)."},
        "SELF_AWARE_CODE_ARGV0": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "Code attempting to access its own execution name (argv[0])."},
        "EMPTY_FUNCTION_BODY": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Empty function body, possible evasion or placeholder."},
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Empty catch block that can hide critical errors."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Overridden method with an empty or very simple body, possible evasion technique."},
        "SIMPLE_FUNCTION_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Function with a very simple or empty body, possible evasion technique or placeholder."}
    }

class JavaScriptSignatures(BaseSignatures):
    """
    Security Signatures for JavaScript language.
    """
    IMPORTS: dict[str, dict[str, str]] = { # In JS, "imports" are modules.
        "fs": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Import of 'fs' module (file manipulation)."},
        "child_process": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Import of 'child_process' module (command execution)."},
        "net": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Import of 'net' module (low-level networking)."},
        "http": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Import of 'http' module (HTTP requests)."},
        "https": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "desc": "Import of 'https' module (HTTPS requests)."},
        "crypto": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "desc": "Import of 'crypto' module (cryptography)."},
        "path": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "desc": "Import of 'path' module (file path manipulation)."},
        "url": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "desc": "Import of 'url' module (URL parsing)."}
    }

    METHOD_CALLS: dict[str, dict[str, str]] = {
        "eval(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Dynamic code execution from a string."},
        "setTimeout": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "desc": "Use of setTimeout with string (code evaluation)."},
        "setInterval": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "desc": "Use of setInterval with string (code evaluation)."},
        "new Function(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Creation of dynamic functions from a string."},
        "document.write": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Direct writing to HTML document (XSS risk)."},
        "element.innerHTML": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Assignment to innerHTML (XSS risk)."},
        "fs.readFileSync": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "desc": "Synchronous file reading."},
        "fs.writeFileSync": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "desc": "Synchronous file writing."},
        "child_process.exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "desc": "Execution of system commands."},
        "require(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "desc": "Dynamic module import (potential for malware loading)."}, # For Node.js
        "atob(": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "desc": "Use of atob (Base64 decoding, common in obfuscation)."},
        "btoa(": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "desc": "Use of btoa (Base64 encoding, common in obfuscation)."}
    }

    STRING_KEYWORDS: dict[str, dict[str, str]] = BaseSignatures.STRING_KEYWORDS # Reusing base class definitions

    NAMING_CONVENTIONS: dict[str, dict[str, str]] = BaseSignatures.NAMING_CONVENTIONS # Reusing base class definitions

    STRUCTURAL_PATTERNS: dict[str, dict[str, str]] = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "MEDIUM", "desc": "Access to sensitive system paths (e.g., /etc/passwd, C:\\Windows)."},
        "SELF_AWARE_CODE_PATH": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "desc": "Code attempting to access its own execution path (e.g., __dirname, process.argv[0])."},
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "desc": "Empty catch block that can hide critical errors."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "desc": "Overridden method with an empty or very simple body, possible evasion technique."}
    }