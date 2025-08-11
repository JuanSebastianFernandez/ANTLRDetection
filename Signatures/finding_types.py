# vesta_backend/signatures/finding_types.py

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
from typing import Any, Optional

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
# New ransomware-specific types
FINDING_TYPE_RANSOM_NOTE_CREATION: str = "RANSOM_NOTE_CREATION"
FINDING_TYPE_BACKUP_DESTRUCTION: str = "BACKUP_DESTRUCTION"
FINDING_TYPE_MASS_FILE_ENCRYPTION: str = "MASS_FILE_ENCRYPTION"
FINDING_TYPE_PAYMENT_COMMUNICATION: str = "PAYMENT_COMMUNICATION"
FINDING_TYPE_SERVICE_DISRUPTION: str = "SERVICE_DISRUPTION"
FINDING_TYPE_LATERAL_MOVEMENT: str = "LATERAL_MOVEMENT"
FINDING_TYPE_ANTI_FORENSICS: str = "ANTI_FORENSICS"

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
        BEHAVIORAL_PATTERNS (dict): Dictionary of combined patterns indicating specific behaviors.
    """
    # Default structure for signature entries, including optional behavioral_trigger
    _DEFAULT_SIGNATURE_ENTRY: dict[str, Any] = {
        "type": "",
        "severity": "",
        "weight": 0.0,
        "desc": "",
        "behavioral_trigger": None # Explicitly optional
    }

    IMPORTS: dict[str, dict[str, Any]] = {}
    METHOD_CALLS: dict[str, dict[str, Any]] = {}
    STRING_KEYWORDS: dict[str, dict[str, Any]] = {
        # Hardcoded credentials - HIGH priority
        "password": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "weight": 0.7, "desc": "Possible hardcoded credential."},
        "secret": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "weight": 0.7, "desc": "Possible hardcoded credential."},
        "apikey": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "weight": 0.8, "desc": "Possible hardcoded credential."},
        "privatekey": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "weight": 0.8, "desc": "Possible hardcoded credential."},
        "token": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "MEDIUM", "weight": 0.4, "desc": "Possible hardcoded credential (common in legitimate apps)."},
        
        # Ransomware-specific keywords - CRITICAL priority with high weights
        "ransom": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware-related keyword: 'ransom'.", "behavioral_trigger": "ransom_keyword"},
        "decrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Ransomware-related keyword: 'decrypt'.", "behavioral_trigger": "decrypt_keyword"},
        "bitcoin": {"type": FINDING_TYPE_PAYMENT_COMMUNICATION, "severity": "HIGH", "weight": 0.9, "desc": "Ransomware-related keyword: 'bitcoin' (payment).", "behavioral_trigger": "bitcoin_ref"},
        "payment": {"type": FINDING_TYPE_PAYMENT_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Payment-related keyword.", "behavioral_trigger": "payment_keyword"},
        "encrypted": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.5, "desc": "Encryption-related keyword.", "behavioral_trigger": "encrypted_keyword"},
        "victim": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "HIGH", "weight": 0.9, "desc": "Ransomware-related keyword: 'victim'.", "behavioral_trigger": "victim_keyword"},
        "restore": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Recovery-related keyword.", "behavioral_trigger": "restore_keyword"},
        "recovery": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Recovery-related keyword.", "behavioral_trigger": "recovery_keyword"},
        "keyfile": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Ransomware-related keyword: 'keyfile'.", "behavioral_trigger": "keyfile_keyword"},
        "wallet": {"type": FINDING_TYPE_PAYMENT_COMMUNICATION, "severity": "MEDIUM", "weight": 0.7, "desc": "Cryptocurrency wallet reference.", "behavioral_trigger": "wallet_ref"},
        
        # Ransom note filenames - CRITICAL priority
        "note.txt": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware ransom note filename.", "behavioral_trigger": "ransom_note_filename"},
        "read_me": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware ransom note filename.", "behavioral_trigger": "ransom_note_filename"},
        "HOW_TO_DECRYPT": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.98, "desc": "Common ransom note filename.", "behavioral_trigger": "ransom_note_filename"},
        "DECRYPT_INSTRUCTION": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.98, "desc": "Ransom instruction file.", "behavioral_trigger": "ransom_note_filename"},
        "FILES_ENCRYPTED": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.98, "desc": "Ransomware notification.", "behavioral_trigger": "ransom_note_filename"},
        "YOUR_FILES_ARE_ENCRYPTED": {"type": FINDING_TYPE_RANSOM_NOTE_CREATION, "severity": "CRITICAL", "weight": 0.98, "desc": "Typical ransomware message.", "behavioral_trigger": "ransom_note_filename"},
        
        # Ransomware file extensions - CRITICAL priority
        ".locked": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware file extension.", "behavioral_trigger": "extension_change"},
        ".encrypted": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware file extension.", "behavioral_trigger": "extension_change"},
        ".crypto": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware file extension.", "behavioral_trigger": "extension_change"},
        ".vault": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Ransomware file extension.", "behavioral_trigger": "extension_change"},
        ".cerber": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Cerber ransomware extension.", "behavioral_trigger": "extension_change"},
        ".locky": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Locky ransomware extension.", "behavioral_trigger": "extension_change"},
        ".wannacry": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "WannaCry ransomware extension.", "behavioral_trigger": "extension_change"},
        ".ryuk": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Ryuk ransomware extension.", "behavioral_trigger": "extension_change"},
        ".sodinokibi": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Sodinokibi/REvil ransomware extension.", "behavioral_trigger": "extension_change"},
        ".maze": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Maze ransomware extension.", "behavioral_trigger": "extension_change"},
        ".conti": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Conti ransomware extension.", "behavioral_trigger": "extension_change"},
        ".darkside": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.98, "desc": "DarkSide ransomware extension.", "behavioral_trigger": "extension_change"},
        
        # Cryptography keywords - balanced weights
        "cipher": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.7, "desc": "Cryptographic cipher reference.", "behavioral_trigger": "crypto_keyword"},
        "aes": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.7, "desc": "AES encryption algorithm.", "behavioral_trigger": "crypto_keyword"},
        "rsa": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.7, "desc": "RSA encryption algorithm.", "behavioral_trigger": "crypto_keyword"},
        "fernet": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Fernet encryption (common in Python ransomware).", "behavioral_trigger": "crypto_keyword"},
        "crypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.4, "desc": "Generic cryptography reference.", "behavioral_trigger": "crypto_keyword"},
        "key": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "LOW", "weight": 0.2, "desc": "Cryptographic key reference (common word).", "behavioral_trigger": "crypto_keyword"},
        "decryptor": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Decryptor tool reference.", "behavioral_trigger": "decrypt_tool_keyword"},
        "pbkdf2": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Key derivation function used in ransomware.", "behavioral_trigger": "crypto_keyword"},
        "scrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Key derivation function used in ransomware.", "behavioral_trigger": "crypto_keyword"},
        "chacha20": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Stream cipher used in ransomware.", "behavioral_trigger": "crypto_keyword"},
        "salsa20": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Stream cipher used in ransomware.", "behavioral_trigger": "crypto_keyword"},
        
        # Network/anonymity - adjusted weights
        "tor": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.8, "desc": "Tor network reference (anonymous communication).", "behavioral_trigger": "tor_network"},
        "onion": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.8, "desc": "Onion routing reference (anonymous communication).", "behavioral_trigger": "onion_network"},
        ".onion": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.9, "desc": "Tor hidden service URL.", "behavioral_trigger": "onion_network"},
        "hiddenservice": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.8, "desc": "Hidden service reference (anonymous communication).", "behavioral_trigger": "hidden_service"},
        "http://": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "HTTP URL reference.", "behavioral_trigger": "http_url"},
        "https://": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "HTTPS URL reference.", "behavioral_trigger": "https_url"},
        
        # Obfuscation indicators - balanced
        "base64": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.3, "desc": "Base64 encoding indicator.", "behavioral_trigger": "base64_obfuscation"},
        "xor": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "HIGH", "weight": 0.7, "desc": "XOR operation (common in malware obfuscation).", "behavioral_trigger": "xor_obfuscation"},
        
        # System disruption keywords
        "taskkill": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.8, "desc": "Process termination command.", "behavioral_trigger": "process_kill"},
        "sc stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.8, "desc": "Service stop command.", "behavioral_trigger": "service_stop"},
        "net stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.8, "desc": "Network service stop command.", "behavioral_trigger": "service_stop"},
        "reg add": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Registry modification command.", "behavioral_trigger": "registry_modification"},
        "schtasks": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Task scheduler command.", "behavioral_trigger": "scheduled_task"},
        
        # Anti-forensics keywords
        "wevtutil": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "HIGH", "weight": 0.8, "desc": "Event log manipulation utility.", "behavioral_trigger": "log_clear"},
        "fsutil": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "MEDIUM", "weight": 0.6, "desc": "File system utility (can modify timestamps).", "behavioral_trigger": "timestamp_modify"},
    }
    
    NAMING_CONVENTIONS: dict[str, dict[str, Any]] = {
        "OBFUSCATED_CLASS_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.5, "desc": "Suspiciously short or dynamically generated class name."},
        "OBFUSCATED_METHOD_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.3, "desc": "Suspiciously short method name."},
        "OBFUSCATED_FUNCTION_SHORT_NAME": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.3, "desc": "Suspiciously short function name."}
    }
    
    STRUCTURAL_PATTERNS: dict[str, dict[str, Any]] = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Sensitive system path access.", "behavioral_trigger": "sensitive_path_ref"},
    }
    
    # --- BEHAVIORAL_PATTERNS con referencia a los triggers atómicos ---
    BEHAVIORAL_PATTERNS: dict[str, dict] = {
        "MASS_FILE_ENCRYPTION": {
            "triggers": ["crypto_import", "file_traversal", "file_write", "extension_change", "crypto_keyword", "encrypted_keyword", "file_delete", "file_rename"],
            "weight": 0.9,
            "type": FINDING_TYPE_MASS_FILE_ENCRYPTION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating mass file encryption behavior."
        },
        "BACKUP_DESTRUCTION": {
            "triggers": ["backup_api_call", "shadow_copy_delete", "backup_delete", "restore_keyword", "recovery_keyword", "bcdedit_manipulation", "service_stop"],
            "weight": 0.95,
            "type": FINDING_TYPE_BACKUP_DESTRUCTION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating backup/recovery prevention."
        },
        "RANSOM_NOTE_DEPLOYMENT": {
            "triggers": ["file_create", "ransom_keyword", "bitcoin_ref", "payment_keyword", "victim_keyword", "ransom_note_filename", "decrypt_tool_keyword", "file_write"],
            "weight": 0.9,
            "type": FINDING_TYPE_RANSOM_NOTE_CREATION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating ransom note creation and deployment."
        },
        "C2_COMMUNICATION": {
            "triggers": ["network_request", "network_connection", "tor_network", "onion_network", "hidden_service", "bitcoin_ref", "wallet_ref", "http_url", "https_url"],
            "weight": 0.85,
            "type": FINDING_TYPE_NETWORK_COMMUNICATION,
            "severity": "HIGH",
            "desc": "Pattern indicating Command and Control communication."
        },
        "PERSISTENCE_MECHANISM": {
            "triggers": ["registry_modification", "startup_entry", "service_creation", "scheduled_task", "self_location_path", "self_location_name"],
            "weight": 0.8,
            "type": FINDING_TYPE_CODE_EXECUTION,
            "severity": "HIGH",
            "desc": "Pattern indicating a persistence mechanism."
        },
        "CODE_INJECTION_MEMORY_MANIPULATION": {
            "triggers": ["memory_mapping", "memory_allocation", "memory_manipulation_import", "process_creation"],
            "weight": 0.9,
            "type": FINDING_TYPE_CODE_EXECUTION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating code injection or memory manipulation."
        },
        "DYNAMIC_CODE_EXECUTION": {
            "triggers": ["dynamic_code_exec", "dynamic_module_load", "reflection_obfuscation"],
            "weight": 0.9,
            "type": FINDING_TYPE_CODE_EXECUTION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating dynamic code execution from strings or loaded modules."
        },
        "OS_COMMAND_EXECUTION": {
            "triggers": ["os_command_exec", "external_command_exec", "process_creation", "process_replacement"],
            "weight": 0.9,
            "type": FINDING_TYPE_CODE_EXECUTION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating execution of operating system commands."
        },
        "FILE_SYSTEM_TRAVERSAL_AND_MODIFICATION": {
            "triggers": ["file_traversal", "file_read", "file_write", "file_delete", "file_rename", "file_permission_change"],
            "weight": 0.7,
            "type": FINDING_TYPE_FILE_SYSTEM_ACCESS,
            "severity": "HIGH",
            "desc": "Pattern indicating extensive file system traversal combined with modification."
        },
        "SERVICE_DISRUPTION": {
            "triggers": ["service_stop", "process_kill", "registry_modification", "backup_delete", "antivirus_disable"],
            "weight": 0.85,
            "type": FINDING_TYPE_SERVICE_DISRUPTION,
            "severity": "CRITICAL",
            "desc": "Pattern indicating system service disruption."
        },
        "LATERAL_MOVEMENT": {
            "triggers": ["network_scan", "credential_access", "remote_execution", "share_enumeration", "network_connection"],
            "weight": 0.8,
            "type": FINDING_TYPE_LATERAL_MOVEMENT,
            "severity": "HIGH",
            "desc": "Pattern indicating lateral movement attempt."
        },
        "ANTI_FORENSICS": {
            "triggers": ["log_clear", "event_log_clear", "artifact_deletion", "timestamp_modify", "file_delete"],
            "weight": 0.85,
            "type": FINDING_TYPE_ANTI_FORENSICS,
            "severity": "HIGH",
            "desc": "Pattern indicating anti-forensics behavior."
        }
    }

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
    Security Signatures for Java language - Improved for ransomware detection.
    """
    # IMPORTS: Suspicious imports/modules or header inclusions.
    IMPORTS: dict[str, dict[str, Any]] = {
        # === CRYPTOGRAPHY - HIGH DISCRIMINATIVE POWER ===
        "javax.crypto.Cipher": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.9, "desc": "Direct cipher operations - file encryption capability.", "behavioral_trigger": "crypto_import"},
        "javax.crypto.spec.SecretKeySpec": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "Secret key specification for symmetric encryption.", "behavioral_trigger": "crypto_import"},
        "javax.crypto.spec.IvParameterSpec": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "IV parameter spec for block ciphers.", "behavioral_trigger": "crypto_import"},
        "javax.crypto.KeyGenerator": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Cryptographic key generation.", "behavioral_trigger": "crypto_import"},
        "javax.crypto.spec": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Cryptographic specifications package.", "behavioral_trigger": "crypto_import"},
        "java.security.SecureRandom": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.4, "desc": "Secure random generation - common in crypto.", "behavioral_trigger": "crypto_import"},
        "java.security.MessageDigest": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "LOW", "weight": 0.2, "desc": "Hashing - legitimate uses common.", "behavioral_trigger": "crypto_import"},
        
        # === FILE SYSTEM - BALANCED FOR ML TRAINING ===
        "java.io.File": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "Basic file operations - very common.", "behavioral_trigger": "file_access_import"},
        "java.io.FileInputStream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File input stream.", "behavioral_trigger": "file_read_import"},
        "java.io.FileOutputStream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.3, "desc": "File output capability.", "behavioral_trigger": "file_write_import"},
        "java.nio.file.Files": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "Advanced file operations - bulk operations possible.", "behavioral_trigger": "file_write_import"},
        "java.nio.file.Paths": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "Path utilities - very common.", "behavioral_trigger": "file_access_import"},
        "java.nio.file.Path": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "Modern path API - very common.", "behavioral_trigger": "file_access_import"},
        "java.io.RandomAccessFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Direct file access - potential for in-place encryption.", "behavioral_trigger": "file_write_import"},
        
        # === CODE EXECUTION - CRITICAL FOR SECURITY ===
        "java.lang.Runtime": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Runtime execution capability.", "behavioral_trigger": "code_exec_import"},
        "java.lang.ProcessBuilder": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.85, "desc": "Process creation - command execution.", "behavioral_trigger": "code_exec_import"},
        "java.lang.Process": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Process management.", "behavioral_trigger": "code_exec_import"},
        
        # === NETWORK - MODERATE WEIGHTS ===
        "java.net.Socket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "Network socket capability.", "behavioral_trigger": "network_import"},
        "java.net.URL": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.1, "desc": "URL handling - very common.", "behavioral_trigger": "network_import"},
        "java.net.HttpURLConnection": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.3, "desc": "HTTP connections.", "behavioral_trigger": "network_import"},
        "java.net.URLConnection": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.3, "desc": "URL connections.", "behavioral_trigger": "network_import"},
        "java.net.ServerSocket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Server socket creation.", "behavioral_trigger": "network_import"},
        
        # === REFLECTION & OBFUSCATION ===
        "java.lang.reflect": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.5, "desc": "Reflection capabilities - potential obfuscation.", "behavioral_trigger": "reflection_obfuscation"},
        "java.lang.Class": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.4, "desc": "Class introspection.", "behavioral_trigger": "reflection_self_aware"},
        "java.lang.ClassLoader": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Dynamic class loading - potential code injection.", "behavioral_trigger": "dynamic_class_loading"},
        
        # === ENCODING/OBFUSCATION - REDUCED WEIGHTS ===
        "java.util.Base64": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.15, "desc": "Base64 encoding - common in legitimate apps.", "behavioral_trigger": "base64_obfuscation"},
        "java.util.zip": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "INFO", "weight": 0.05, "desc": "Compression - very common.", "behavioral_trigger": "compression_obfuscation"},
        
        # === SYSTEM INFO - REDUCED PRIORITY ===
        "java.lang.System": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "System properties - very common."},
        "java.lang.management": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.1, "desc": "JVM management."},
        
        # === THREADING - VERY LOW PRIORITY ===
        "java.util.concurrent": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.05, "desc": "Concurrency utilities - very common."},
        "java.lang.Thread": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.05, "desc": "Threading - very common."},
        
        # === DESKTOP INTEGRATION - MEDIUM PRIORITY ===
        "java.awt.Desktop": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Desktop integration - can launch programs.", "behavioral_trigger": "desktop_exec"},
        
        # === NUEVAS FIRMAS ESPECÍFICAS PARA RANSOMWARE ===
        # Windows Registry Access (via JNI or libraries)
        "com.sun.jna": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "JNA - native code access potential.", "behavioral_trigger": "native_code_access"},
        "sun.misc.Unsafe": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Unsafe operations - direct memory access.", "behavioral_trigger": "unsafe_operations"},
        
        # Scheduling and Persistence
        "java.util.Timer": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.4, "desc": "Timer for scheduled tasks.", "behavioral_trigger": "scheduled_task"},
        "java.util.concurrent.ScheduledExecutorService": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.4, "desc": "Scheduled execution service.", "behavioral_trigger": "scheduled_task"},
        
        # Email/Communication for ransom notes
        "javax.mail": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Email capabilities.", "behavioral_trigger": "email_capability"},
        
        # File Attributes and Permissions
        "java.nio.file.attribute": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File attribute manipulation.", "behavioral_trigger": "file_permission_change"},
        
        # Serialization (potential for obfuscation)
        "java.io.ObjectInputStream": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Object deserialization - code execution risk.", "behavioral_trigger": "deserialization_risk"},
        "java.io.ObjectOutputStream": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.3, "desc": "Object serialization.", "behavioral_trigger": "serialization_obfuscation"},
        
        # XML Processing (can be used for obfuscation)
        "javax.xml.transform": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.3, "desc": "XML transformation.", "behavioral_trigger": "xml_obfuscation"},
    }

    # METHOD_CALLS: Dangerous or sensitive function or method calls.
    METHOD_CALLS: dict[str, dict[str, Any]] = {
        # === CRITICAL SYSTEM COMMANDS ===
        "Runtime.getRuntime().exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Direct OS command execution.", "behavioral_trigger": "os_command_exec"},
        "ProcessBuilder.start": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Process execution via ProcessBuilder.", "behavioral_trigger": "process_creation"},
        
        # === HIGH-IMPACT FILE OPERATIONS ===
        ".delete()": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "File deletion operation.", "behavioral_trigger": "file_delete"},
        "Files.delete": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "NIO file deletion.", "behavioral_trigger": "file_delete"},
        "Files.deleteIfExists": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Conditional file deletion.", "behavioral_trigger": "file_delete"},
        "File.delete": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Legacy file deletion.", "behavioral_trigger": "file_delete"},
        
        # === BULK FILE OPERATIONS - VERY IMPORTANT FOR RANSOMWARE ===
        "Files.walk": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.85, "desc": "Recursive directory traversal - key ransomware behavior.", "behavioral_trigger": "file_traversal"},
        "Files.list": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "Directory listing.", "behavioral_trigger": "file_traversal"},
        "File.listFiles": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "Legacy directory listing.", "behavioral_trigger": "file_traversal"},
        "Files.find": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "File search with predicates - targeted file finding.", "behavioral_trigger": "file_traversal"},
        
        # === FILE MODIFICATION OPERATIONS ===
        "Files.write": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File write operation.", "behavioral_trigger": "file_write"},
        "Files.copy": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.3, "desc": "File copy operation.", "behavioral_trigger": "file_copy"},
        "Files.move": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "File move/rename - extension changes.", "behavioral_trigger": "file_rename"},
        "Files.createFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.3, "desc": "File creation.", "behavioral_trigger": "file_create"},
        "Files.createDirectory": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Directory creation.", "behavioral_trigger": "directory_create"},
        "Files.createDirectories": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.3, "desc": "Recursive directory creation.", "behavioral_trigger": "directory_create"},
        
        # === FILE READING - LOW PRIORITY ===
        "Files.readAllBytes": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Reading file contents.", "behavioral_trigger": "file_read"},
        "Files.readAllLines": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Reading text file lines.", "behavioral_trigger": "file_read"},
        "Files.newBufferedReader": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "Buffered file reading.", "behavioral_trigger": "file_read"},
        
        # === FILE PERMISSIONS - MODERATE PRIORITY ===
        "Files.setPosixFilePermissions": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "POSIX file permissions change.", "behavioral_trigger": "file_permission_change"},
        "Files.setOwner": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "File ownership change.", "behavioral_trigger": "file_permission_change"},
        "File.setReadable": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "File readability change.", "behavioral_trigger": "file_permission_change"},
        "File.setWritable": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File writability change.", "behavioral_trigger": "file_permission_change"},
        
        # === CRYPTOGRAPHIC OPERATIONS - CRITICAL ===
        "Cipher.doFinal": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "CRITICAL", "weight": 0.9, "desc": "Final crypto operation - actual encryption/decryption.", "behavioral_trigger": "crypto_op"},
        "Cipher.update": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Streaming crypto operation.", "behavioral_trigger": "crypto_op"},
        "Cipher.init": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.75, "desc": "Cipher initialization.", "behavioral_trigger": "crypto_init"},
        "KeyGenerator.generateKey": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Cryptographic key generation.", "behavioral_trigger": "key_generation"},
        "SecretKeySpec.<init>": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.75, "desc": "Secret key specification creation.", "behavioral_trigger": "key_creation"},
        
        # === NETWORK OPERATIONS ===
        "Socket.connect": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "Direct socket connection.", "behavioral_trigger": "network_connection"},
        "URLConnection.connect": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.3, "desc": "URL connection.", "behavioral_trigger": "network_connection"},
        "HttpURLConnection.getInputStream": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.3, "desc": "HTTP response reading.", "behavioral_trigger": "network_request"},
        "HttpURLConnection.getOutputStream": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "HTTP request sending.", "behavioral_trigger": "network_request"},
        
        # === SELF-AWARENESS - MODERATE PRIORITY ===
        "getClass().getProtectionDomain().getCodeSource().getLocation": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "weight": 0.8, "desc": "Code location detection - self-awareness.", "behavioral_trigger": "self_location"},
        "System.getProperty(\"java.class.path\")": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.5, "desc": "Classpath detection.", "behavioral_trigger": "self_location"},
        "System.getProperty(\"user.dir\")": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "LOW", "weight": 0.2, "desc": "Working directory - common.", "behavioral_trigger": "self_location"},
        
        # === REFLECTION & DYNAMIC LOADING - HIGH RISK ===
        "Class.forName": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Dynamic class loading.", "behavioral_trigger": "dynamic_class_loading"},
        "Method.invoke": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Dynamic method invocation.", "behavioral_trigger": "dynamic_method_invoke"},
        "Constructor.newInstance": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Dynamic object instantiation.", "behavioral_trigger": "dynamic_instantiation"},
        "URLClassLoader.newInstance": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Dynamic class loader creation.", "behavioral_trigger": "dynamic_class_loading"},
        
        # === UNSAFE OPERATIONS - CRITICAL ===
        "Unsafe.allocateMemory": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Direct memory allocation - unsafe operations.", "behavioral_trigger": "unsafe_memory"},
        "Unsafe.putAddress": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Direct memory manipulation.", "behavioral_trigger": "unsafe_memory"},
        
        # === DESERIALIZATION - HIGH RISK ===
        "ObjectInputStream.readObject": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.85, "desc": "Object deserialization - code execution risk.", "behavioral_trigger": "deserialization_exec"},
        
        # === SCHEDULING - MODERATE PRIORITY ===
        "Timer.schedule": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.4, "desc": "Task scheduling.", "behavioral_trigger": "scheduled_task"},
        "ScheduledExecutorService.schedule": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.4, "desc": "Scheduled execution.", "behavioral_trigger": "scheduled_task"},
        
        # === COMMON OPERATIONS - VERY LOW PRIORITY ===
        "System.exit": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "weight": 0.1, "desc": "Program termination - very common."},
        "Thread.sleep": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.05, "desc": "Thread sleep - very common."},
        "System.currentTimeMillis": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.01, "desc": "Current time - extremely common."},
        "System.out.println": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.01, "desc": "Console output - extremely common."},
        
        # === NUEVAS FIRMAS ESPECÍFICAS ===
        # File extension manipulation patterns
        "String.replaceAll.*\\.(.*?)$": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "HIGH", "weight": 0.8, "desc": "File extension manipulation pattern.", "behavioral_trigger": "extension_change"},
        "Paths.get.*\\.encrypted": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Encrypted file extension reference.", "behavioral_trigger": "encrypted_extension"},
        "Paths.get.*\\.locked": {"type": FINDING_TYPE_MASS_FILE_ENCRYPTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Locked file extension reference.", "behavioral_trigger": "encrypted_extension"},
        
        # Registry access patterns (Windows via JNI)
        "Advapi32.RegOpenKeyEx": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Windows registry access via JNI.", "behavioral_trigger": "registry_modification"},
        "Advapi32.RegSetValueEx": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Windows registry modification via JNI.", "behavioral_trigger": "registry_modification"},
        
        # Email sending for ransom notes
        "Transport.send": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Email sending capability.", "behavioral_trigger": "email_send"},
        "Session.getInstance": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.2, "desc": "Mail session creation.", "behavioral_trigger": "email_setup"},
    }
    
    STRING_KEYWORDS: dict[str, dict[str, Any]] = BaseSignatures.STRING_KEYWORDS
    NAMING_CONVENTIONS: dict[str, dict[str, Any]] = BaseSignatures.NAMING_CONVENTIONS

    STRUCTURAL_PATTERNS: dict[str, dict[str, Any]] = {
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "weight": 0.5, "desc": "Empty catch block hiding errors."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.5, "desc": "Suspicious method override."},
        "SELF_AWARE_CODE_FILE_DOT": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.6, "desc": "Current directory access.", "behavioral_trigger": "current_dir_access"},
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Sensitive system path access.", "behavioral_trigger": "sensitive_path_ref"}
    }

class PythonSignatures(BaseSignatures):
    """
    Security Signatures for Python language - Improved for ransomware detection.
    """
    # IMPORTS: Suspicious imports/modules or header inclusions.
    IMPORTS: dict[str, dict[str, Any]] = {
        # === CRYPTOGRAPHY - ALTA PRIORIDAD PARA RANSOMWARE ===
        "cryptography": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "Cryptography library - strong encryption capability.", "behavioral_trigger": "crypto_import"},
        "cryptodome": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "PyCryptodome library - advanced crypto.", "behavioral_trigger": "crypto_import"},
        "pycrypto": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.80, "desc": "PyCrypto library (deprecated but still used).", "behavioral_trigger": "crypto_import"},
        "nacl": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.80, "desc": "PyNaCl modern cryptography.", "behavioral_trigger": "crypto_import"},
        "cryptography.fernet": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "CRITICAL", "weight": 0.90, "desc": "Fernet encryption - commonly used in Python ransomware.", "behavioral_trigger": "crypto_import"},
        "cryptography.hazmat": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "Low-level cryptographic primitives.", "behavioral_trigger": "crypto_import"},
        "Crypto.Cipher": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "Direct cipher access from PyCrypto/PyCryptodome.", "behavioral_trigger": "crypto_import"},
        "hashlib": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.40, "desc": "Hashing capabilities - legitimate uses common.", "behavioral_trigger": "crypto_import"},
        
        # === FILE SYSTEM - PRIORIDADES AJUSTADAS ===
        "os": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "Basic OS interaction - extremely common.", "behavioral_trigger": "os_import"},
        "shutil": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "High-level file operations (rmtree, move, copy).", "behavioral_trigger": "file_ops_import"},
        "pathlib": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.10, "desc": "Modern path manipulation - very common.", "behavioral_trigger": "file_access_import"},
        "glob": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.70, "desc": "File pattern matching - key for ransomware file discovery.", "behavioral_trigger": "file_search_import"},
        "fnmatch": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.50, "desc": "Filename pattern matching.", "behavioral_trigger": "file_search_import"},
        "tempfile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.30, "desc": "Temporary file creation.", "behavioral_trigger": "temp_file_import"},
        "io": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "I/O operations - very common.", "behavioral_trigger": "file_access_import"},
        "fileinput": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.60, "desc": "Bulk file processing capability.", "behavioral_trigger": "bulk_file_import"},
        
        # === CODE EXECUTION - CRÍTICO ===
        "subprocess": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "Subprocess execution capability.", "behavioral_trigger": "code_exec_import"},
        "subprocess32": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "Subprocess backport.", "behavioral_trigger": "code_exec_import"},
        "ctypes": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.85, "desc": "Direct system API calls - high risk.", "behavioral_trigger": "system_api_import"},
        "ctypes.wintypes": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.90, "desc": "Windows API types - Windows-specific operations.", "behavioral_trigger": "windows_api_import"},
        "pickle": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Serialization with code execution risk.", "behavioral_trigger": "serialization_import"},
        "dill": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Extended pickle - higher execution risk.", "behavioral_trigger": "serialization_import"},
        "marshal": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Python object serialization.", "behavioral_trigger": "serialization_import"},
        "importlib": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Dynamic module loading.", "behavioral_trigger": "dynamic_import"},
        "__import__": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Dynamic import function.", "behavioral_trigger": "dynamic_import"},
        
        # === NETWORK - BALANCEADO ===
        "socket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.45, "desc": "Low-level networking capability.", "behavioral_trigger": "network_import"},
        "urllib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.20, "desc": "URL handling - very common.", "behavioral_trigger": "url_import"},
        "urllib3": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.25, "desc": "HTTP library.", "behavioral_trigger": "http_import"},
        "requests": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.35, "desc": "Popular HTTP library.", "behavioral_trigger": "http_import"},
        "httpx": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.35, "desc": "Modern HTTP client.", "behavioral_trigger": "http_import"},
        "aiohttp": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.40, "desc": "Async HTTP client/server.", "behavioral_trigger": "async_http_import"},
        "ftplib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.50, "desc": "FTP client capability.", "behavioral_trigger": "ftp_import"},
        "smtplib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.45, "desc": "SMTP/email capability.", "behavioral_trigger": "email_import"},
        "imaplib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.45, "desc": "IMAP email access.", "behavioral_trigger": "email_import"},
        "poplib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.45, "desc": "POP3 email access.", "behavioral_trigger": "email_import"},
        "telnetlib": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.70, "desc": "Telnet protocol - often used maliciously.", "behavioral_trigger": "telnet_import"},
        "paramiko": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.65, "desc": "SSH client/server - remote access capability.", "behavioral_trigger": "ssh_import"},
        "pexpect": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "Process interaction automation.", "behavioral_trigger": "process_automation_import"},
        
        # === WINDOWS ESPECÍFICO - MUY IMPORTANTE PARA RANSOMWARE ===
        "winreg": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Windows registry access.", "behavioral_trigger": "registry_import"},
        "win32api": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Windows API access.", "behavioral_trigger": "windows_api_import"},
        "win32con": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Windows constants.", "behavioral_trigger": "windows_api_import"},
        "win32file": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.70, "desc": "Windows file operations.", "behavioral_trigger": "windows_file_import"},
        "win32service": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Windows service management.", "behavioral_trigger": "service_import"},
        "win32security": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Windows security functions.", "behavioral_trigger": "security_import"},
        "wmi": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Windows Management Instrumentation.", "behavioral_trigger": "wmi_import"},
        "comtypes": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.55, "desc": "COM interface access.", "behavioral_trigger": "com_import"},
        
        # === OBFUSCATION - PESOS REDUCIDOS ===
        "base64": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.25, "desc": "Base64 encoding - common in legitimate code.", "behavioral_trigger": "base64_import"},
        "zlib": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.20, "desc": "Compression library.", "behavioral_trigger": "compression_import"},
        "gzip": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.15, "desc": "GZIP compression.", "behavioral_trigger": "compression_import"},
        "bz2": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.15, "desc": "BZ2 compression.", "behavioral_trigger": "compression_import"},
        "lzma": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.20, "desc": "LZMA compression.", "behavioral_trigger": "compression_import"},
        "codecs": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.40, "desc": "Text encoding/decoding.", "behavioral_trigger": "encoding_import"},
        "binascii": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.35, "desc": "Binary-ASCII conversion.", "behavioral_trigger": "encoding_import"},
        
        # === AUTOMATION & SCHEDULING ===
        "schedule": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Task scheduling library.", "behavioral_trigger": "scheduling_import"},
        "crontab": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.55, "desc": "Cron job management.", "behavioral_trigger": "scheduling_import"},
        "apscheduler": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Advanced Python scheduler.", "behavioral_trigger": "scheduling_import"},
        
        # === GUI & DESKTOP INTEGRATION ===
        "tkinter": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.40, "desc": "GUI framework - ransom note display.", "behavioral_trigger": "gui_import"},
        "wx": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.45, "desc": "wxPython GUI framework.", "behavioral_trigger": "gui_import"},
        "PyQt5": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.45, "desc": "Qt5 GUI framework.", "behavioral_trigger": "gui_import"},
        "PyQt6": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.45, "desc": "Qt6 GUI framework.", "behavioral_trigger": "gui_import"},
        "pystray": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.60, "desc": "System tray integration - stealth capability.", "behavioral_trigger": "stealth_import"},
        "plyer": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Cross-platform native APIs.", "behavioral_trigger": "native_api_import"},
        
        # === STEGANOGRAPHY & ADVANCED OBFUSCATION ===
        "stegano": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "HIGH", "weight": 0.80, "desc": "Steganography library.", "behavioral_trigger": "steganography_import"},
        "PIL": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.15, "desc": "Image processing - legitimate uses common.", "behavioral_trigger": "image_import"},
        "Pillow": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.15, "desc": "Image processing library.", "behavioral_trigger": "image_import"},
        
        # === NUEVAS FIRMAS ESPECÍFICAS ===
        "psutil": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.55, "desc": "Process and system monitoring.", "behavioral_trigger": "process_monitor_import"},
        "keyring": {"type": FINDING_TYPE_HARDCODED_CREDENTIALS, "severity": "HIGH", "weight": 0.70, "desc": "Credential storage access.", "behavioral_trigger": "credential_import"},
        "cryptg": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.80, "desc": "Fast cryptographic library.", "behavioral_trigger": "crypto_import"},
        "pyotp": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.50, "desc": "One-time password generation.", "behavioral_trigger": "otp_import"},
    }

    # METHOD_CALLS: Ajustados con mejor granularidad y pesos más precisos
    METHOD_CALLS: dict[str, dict[str, Any]] = {
        # === CODE EXECUTION - CRÍTICO ===
        "eval(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Dynamic code execution from string.", "behavioral_trigger": "dynamic_code_exec"},
        "exec(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Dynamic code execution.", "behavioral_trigger": "dynamic_code_exec"},
        "compile(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Code compilation for execution.", "behavioral_trigger": "code_compile"},
        "os.system(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.85, "desc": "Shell command execution.", "behavioral_trigger": "os_command_exec"},
        "subprocess.run": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "External command execution.", "behavioral_trigger": "external_command_exec"},
        "subprocess.call": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "External command execution.", "behavioral_trigger": "external_command_exec"},
        "subprocess.check_call": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "External command with error checking.", "behavioral_trigger": "external_command_exec"},
        "subprocess.check_output": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.65, "desc": "Command execution with output capture.", "behavioral_trigger": "command_output_exec"},
        "subprocess.Popen": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Advanced process creation.", "behavioral_trigger": "process_creation"},
        "os.spawn": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Process spawning.", "behavioral_trigger": "process_creation"},
        "os.execv": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Process replacement.", "behavioral_trigger": "process_replacement"},
        "os.popen": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "Pipe to command.", "behavioral_trigger": "command_pipe"},
        
        # === PICKLE/SERIALIZATION - ALTO RIESGO ===
        "pickle.load": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.85, "desc": "Pickle deserialization - code execution risk.", "behavioral_trigger": "unsafe_deserialization"},
        "pickle.loads": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.85, "desc": "Pickle from bytes - code execution risk.", "behavioral_trigger": "unsafe_deserialization"},
        "dill.load": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.90, "desc": "Dill deserialization - higher risk than pickle.", "behavioral_trigger": "unsafe_deserialization"},
        "marshal.loads": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Marshal deserialization risk.", "behavioral_trigger": "unsafe_deserialization"},
        
        # === BULK FILE OPERATIONS - CLAVE PARA RANSOMWARE ===
        "os.walk": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.80, "desc": "Recursive directory traversal - key ransomware behavior.", "behavioral_trigger": "bulk_file_traversal"},
        "glob.glob": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Pattern-based file discovery.", "behavioral_trigger": "pattern_file_search"},
        "glob.iglob": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Iterator-based file discovery.", "behavioral_trigger": "pattern_file_search"},
        "pathlib.Path.glob": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Modern pattern-based file search.", "behavioral_trigger": "pattern_file_search"},
        "pathlib.Path.rglob": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.80, "desc": "Recursive file pattern search.", "behavioral_trigger": "recursive_file_search"},
        "os.scandir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.50, "desc": "Efficient directory scanning.", "behavioral_trigger": "directory_scan"},
        "os.listdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.20, "desc": "Simple directory listing - very common.", "behavioral_trigger": "simple_directory_list"},
        
        # === FILE OPERATIONS - AJUSTADOS ===
        "open(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.05, "desc": "Generic file access - extremely common.", "behavioral_trigger": "basic_file_access"},
        "shutil.rmtree": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "CRITICAL", "weight": 0.90, "desc": "Recursive directory deletion - destructive.", "behavioral_trigger": "mass_directory_delete"},
        "shutil.move": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.70, "desc": "File/directory moving - can change extensions.", "behavioral_trigger": "bulk_file_move"},
        "shutil.copy": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.30, "desc": "File copying.", "behavioral_trigger": "file_copy"},
        "shutil.copy2": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.35, "desc": "File copying with metadata.", "behavioral_trigger": "file_copy"},
        "shutil.copytree": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.50, "desc": "Directory tree copying.", "behavioral_trigger": "directory_copy"},
        "os.remove": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.45, "desc": "Single file deletion.", "behavioral_trigger": "file_delete"},
        "os.unlink": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.45, "desc": "File deletion (unlink).", "behavioral_trigger": "file_delete"},
        "os.rmdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.50, "desc": "Directory removal.", "behavioral_trigger": "directory_delete"},
        "os.removedirs": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.75, "desc": "Recursive directory removal.", "behavioral_trigger": "recursive_directory_delete"},
        "os.rename": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.65, "desc": "File/directory renaming - extension changes.", "behavioral_trigger": "file_rename"},
        "os.renames": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.70, "desc": "Recursive renaming.", "behavioral_trigger": "recursive_rename"},
        "pathlib.Path.unlink": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.45, "desc": "Modern file deletion.", "behavioral_trigger": "file_delete"},
        "pathlib.Path.rmdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.50, "desc": "Modern directory removal.", "behavioral_trigger": "directory_delete"},
        "pathlib.Path.rename": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.65, "desc": "Modern file renaming.", "behavioral_trigger": "file_rename"},
        "os.path.abspath(__file__)": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.60, "desc": "Self-aware code accessing its own file path.", "behavioral_trigger": "self_aware_code"},
        
        # === FILE PERMISSIONS - IMPORTANTE ===
        "os.chmod": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.55, "desc": "File permission modification.", "behavioral_trigger": "permission_change"},
        "os.chown": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.60, "desc": "File ownership change.", "behavioral_trigger": "ownership_change"},
        "pathlib.Path.chmod": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.55, "desc": "Modern permission change.", "behavioral_trigger": "permission_change"},
        
        # === BACKUP/SHADOW COPY DESTRUCTION - CRÍTICO PARA RANSOMWARE ===
        "subprocess.run.*vssadmin": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Shadow copy manipulation via vssadmin.", "behavioral_trigger": "shadow_copy_attack"},
        "subprocess.run.*wbadmin": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Windows backup manipulation.", "behavioral_trigger": "backup_destruction"},
        "subprocess.run.*bcdedit": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Boot configuration manipulation.", "behavioral_trigger": "boot_config_attack"},
        "os.system.*vssadmin": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Shadow copy attack via os.system.", "behavioral_trigger": "shadow_copy_attack"},
        "os.system.*wbadmin": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Backup destruction via os.system.", "behavioral_trigger": "backup_destruction"},
        "os.system.*bcdedit": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Boot manipulation via os.system.", "behavioral_trigger": "boot_config_attack"},
        
        # === SERVICE MANIPULATION - ALTA PRIORIDAD ===
        "subprocess.run.*sc stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.85, "desc": "Windows service stopping.", "behavioral_trigger": "service_disruption"},
        "subprocess.run.*net stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.85, "desc": "Network service stopping.", "behavioral_trigger": "service_disruption"},
        "subprocess.run.*taskkill": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.80, "desc": "Process termination.", "behavioral_trigger": "process_kill"},
        "os.system.*sc stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.85, "desc": "Service stopping via os.system.", "behavioral_trigger": "service_disruption"},
        "os.system.*taskkill": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.80, "desc": "Process killing via os.system.", "behavioral_trigger": "process_kill"},
        
        # === REGISTRY OPERATIONS - WINDOWS SPECIFIC ===
        "winreg.OpenKey": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Windows registry access.", "behavioral_trigger": "registry_access"},
        "winreg.SetValueEx": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Windows registry modification.", "behavioral_trigger": "registry_modification"},
        "winreg.CreateKey": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.80, "desc": "Windows registry key creation.", "behavioral_trigger": "registry_creation"},
        "winreg.DeleteKey": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Windows registry key deletion.", "behavioral_trigger": "registry_deletion"},
        
        # === NETWORK COMMUNICATION - BALANCEADO ===
        "requests.post": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.40, "desc": "HTTP POST request.", "behavioral_trigger": "http_post"},
        "requests.get": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.15, "desc": "HTTP GET request - very common.", "behavioral_trigger": "http_get"},
        "urllib.request.urlopen": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.35, "desc": "URL opening.", "behavioral_trigger": "url_access"},
        "socket.connect": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.65, "desc": "Direct socket connection.", "behavioral_trigger": "socket_connection"},
        "socket.bind": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.60, "desc": "Socket server binding.", "behavioral_trigger": "socket_server"},
        "socket.listen": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.65, "desc": "Socket listening.", "behavioral_trigger": "socket_server"},
        
        # === CRYPTOGRAPHIC OPERATIONS - CRÍTICO PARA RANSOMWARE ===
        "Fernet.encrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "CRITICAL", "weight": 0.90, "desc": "Fernet encryption - common in Python ransomware.", "behavioral_trigger": "symmetric_encryption"},
        "Fernet.decrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.75, "desc": "Fernet decryption operation.", "behavioral_trigger": "symmetric_decryption"},
        "AES.new": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "AES cipher initialization.", "behavioral_trigger": "aes_cipher_init"},
        "DES.new": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.80, "desc": "DES cipher initialization (weak but used).", "behavioral_trigger": "des_cipher_init"},
        "ChaCha20.new": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "ChaCha20 stream cipher.", "behavioral_trigger": "stream_cipher_init"},
        "Salsa20.new": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "Salsa20 stream cipher.", "behavioral_trigger": "stream_cipher_init"},
        "RSA.generate": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.80, "desc": "RSA key generation.", "behavioral_trigger": "rsa_key_gen"},
        "RSA.encrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.85, "desc": "RSA encryption operation.", "behavioral_trigger": "asymmetric_encryption"},
        "RSA.decrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.75, "desc": "RSA decryption operation.", "behavioral_trigger": "asymmetric_decryption"},
        "cipher.encrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.80, "desc": "Generic cipher encryption.", "behavioral_trigger": "cipher_encrypt"},
        "cipher.decrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.60, "desc": "Generic cipher decryption.", "behavioral_trigger": "cipher_decrypt"},
        "os.urandom": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.40, "desc": "Cryptographically secure random generation.", "behavioral_trigger": "secure_random"},
        "secrets.token_bytes": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.45, "desc": "Secure random token generation.", "behavioral_trigger": "secure_token_gen"},
        "PBKDF2.new": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.75, "desc": "Key derivation function - often in ransomware.", "behavioral_trigger": "key_derivation"},
        "scrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.75, "desc": "Scrypt key derivation function.", "behavioral_trigger": "key_derivation"},
        "bcrypt.hashpw": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.35, "desc": "Bcrypt hashing - legitimate password hashing.", "behavioral_trigger": "password_hash"},
        
        # === SELF-AWARENESS - MODERADO ===
        "os.path.realpath(__file__)": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.55, "desc": "Self-location detection.", "behavioral_trigger": "self_location_detection"},
        "sys.argv[0]": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.50, "desc": "Script name access.", "behavioral_trigger": "script_name_access"},
        "__file__": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "LOW", "weight": 0.25, "desc": "Current file reference - very common.", "behavioral_trigger": "file_reference"},
        "inspect.getfile": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.50, "desc": "Get file of object.", "behavioral_trigger": "introspection"},
        "inspect.currentframe": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.55, "desc": "Current frame access.", "behavioral_trigger": "frame_introspection"},
        "sys.executable": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.45, "desc": "Python interpreter path.", "behavioral_trigger": "interpreter_path"},
        
        # === ANTI-DEBUGGING/ANALYSIS - ALTA PRIORIDAD ===
        "sys.settrace": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "HIGH", "weight": 0.80, "desc": "Trace function setting - anti-debugging.", "behavioral_trigger": "anti_debug"},
        "sys.gettrace": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "HIGH", "weight": 0.75, "desc": "Trace function detection - anti-debugging.", "behavioral_trigger": "debug_detection"},
        "threading.settrace": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "HIGH", "weight": 0.80, "desc": "Thread trace setting - anti-debugging.", "behavioral_trigger": "thread_anti_debug"},
        "ctypes.windll.kernel32.IsDebuggerPresent": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "CRITICAL", "weight": 0.95, "desc": "Windows debugger detection.", "behavioral_trigger": "debugger_detection"},
        "ctypes.windll.kernel32.CheckRemoteDebuggerPresent": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "CRITICAL", "weight": 0.95, "desc": "Remote debugger detection.", "behavioral_trigger": "remote_debug_detection"},
        "psutil.process_iter": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "MEDIUM", "weight": 0.60, "desc": "Process enumeration - potential analysis detection.", "behavioral_trigger": "process_enumeration"},
        
        # === TIMING/DELAYS - EVASIÓN ===
        "time.sleep": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "LOW", "weight": 0.10, "desc": "Sleep delay - very common, but can indicate evasion.", "behavioral_trigger": "delay_execution"},
        "threading.Timer": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.45, "desc": "Delayed execution timer.", "behavioral_trigger": "delayed_execution"},
        
        # === MEMORY OPERATIONS - AVANZADO ===
        "ctypes.memmove": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.75, "desc": "Memory manipulation via ctypes.", "behavioral_trigger": "memory_manipulation"},
        "ctypes.memset": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.70, "desc": "Memory setting via ctypes.", "behavioral_trigger": "memory_manipulation"},
        "ctypes.pointer": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.55, "desc": "Pointer creation - low-level access.", "behavioral_trigger": "pointer_manipulation"},
        "ctypes.cast": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.55, "desc": "Type casting - low-level manipulation.", "behavioral_trigger": "type_casting"},
        
        # === ENVIRONMENT MANIPULATION ===
        "os.environ": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.15, "desc": "Environment variable access - common.", "behavioral_trigger": "env_access"},
        "os.putenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.40, "desc": "Environment variable setting.", "behavioral_trigger": "env_modification"},
        "os.unsetenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.40, "desc": "Environment variable removal.", "behavioral_trigger": "env_modification"},
        
        # === DYNAMIC LOADING/IMPORT - RIESGO MODERADO ===
        "importlib.import_module": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.50, "desc": "Dynamic module import.", "behavioral_trigger": "dynamic_import"},
        "importlib.util.spec_from_file_location": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.65, "desc": "Module from file location.", "behavioral_trigger": "module_from_file"},
        "importlib.util.module_from_spec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.65, "desc": "Module from specification.", "behavioral_trigger": "module_from_spec"},
        "__import__": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.55, "desc": "Built-in import function.", "behavioral_trigger": "builtin_import"},
        
        # === FILE METADATA MANIPULATION ===
        "os.utime": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "HIGH", "weight": 0.70, "desc": "File timestamp modification - anti-forensics.", "behavioral_trigger": "timestamp_manipulation"},
        "pathlib.Path.touch": {"type": FINDING_TYPE_ANTI_FORENSICS, "severity": "MEDIUM", "weight": 0.45, "desc": "File timestamp update.", "behavioral_trigger": "timestamp_update"},
        "os.stat": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.10, "desc": "File status information - very common.", "behavioral_trigger": "file_stat"},
        "pathlib.Path.stat": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.10, "desc": "Modern file status.", "behavioral_trigger": "file_stat"},
        
        # === EMAIL OPERATIONS - RANSOM NOTE DELIVERY ===
        "smtplib.SMTP": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.50, "desc": "SMTP connection for email.", "behavioral_trigger": "email_connection"},
        "smtplib.SMTP_SSL": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.55, "desc": "Secure SMTP connection.", "behavioral_trigger": "secure_email"},
        "email.mime": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.25, "desc": "Email composition - common.", "behavioral_trigger": "email_composition"},
        
        # === COMPRESSION/ARCHIVING - POTENCIAL OBFUSCACIÓN ===
        "zipfile.ZipFile": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.20, "desc": "ZIP file operations.", "behavioral_trigger": "zip_operations"},
        "tarfile.TarFile": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.20, "desc": "TAR file operations.", "behavioral_trigger": "tar_operations"},
        "gzip.open": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.15, "desc": "GZIP compression.", "behavioral_trigger": "gzip_operations"},
        
        # === THREAD/PROCESS OPERATIONS ===
        "threading.Thread": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "weight": 0.20, "desc": "Thread creation - common in legitimate code.", "behavioral_trigger": "thread_creation"},
        "multiprocessing.Process": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.35, "desc": "Process creation.", "behavioral_trigger": "process_creation"},
        "concurrent.futures": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "weight": 0.25, "desc": "Concurrent execution.", "behavioral_trigger": "concurrent_execution"},
    }
    
    STRING_KEYWORDS: dict[str, dict[str, Any]] = BaseSignatures.STRING_KEYWORDS
    NAMING_CONVENTIONS: dict[str, dict[str, Any]] = BaseSignatures.NAMING_CONVENTIONS

    STRUCTURAL_PATTERNS: dict[str, dict[str, Any]] = {
        "EMPTY_EXCEPT_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "weight": 0.5, "desc": "Empty except block hiding errors."},
        "SUSPICIOUS_PASS_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.4, "desc": "Function with pass body - possible evasion."},
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Sensitive system path access.", "behavioral_trigger": "sensitive_path_ref"},
    }

class CSignatures(BaseSignatures):
    """
    Security Signatures for C language - Improved for ransomware detection.
    """
    # IMPORTS: Suspicious imports/modules or header inclusions.
    IMPORTS: dict[str, dict[str, Any]] = {
        # Basic I/O - low priority
        "stdio.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Standard I/O operations.", "behavioral_trigger": "file_access_import"},
        "stdlib.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "INFO", "weight": 0.2, "desc": "Standard library (system() available).", "behavioral_trigger": "code_exec_import"},
        
        # File operations
        "fcntl.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.3, "desc": "File control operations.", "behavioral_trigger": "file_access_import"},
        "sys/stat.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "File status information."},
        "sys/types.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "System data types."},
        "libgen.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "File name manipulation."},
        
        # System access - higher priority for ransomware
        "windows.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "Windows API access."},
        "unistd.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "Unix system calls (fork, exec).", "behavioral_trigger": "code_exec_import"},
        "sys/resource.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "System resource limits."},
        
        # Network communication
        "sys/socket.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Network sockets.", "behavioral_trigger": "network_import"},
        "netinet/in.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Internet addresses.", "behavioral_trigger": "network_import"},
        "arpa/inet.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Internet address conversion.", "behavioral_trigger": "network_import"},
        "sys/un.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "Unix domain sockets.", "behavioral_trigger": "network_import"},
        
        # Memory management - HIGH priority (code injection potential)
        "sys/mman.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Memory mapping (mmap) - code injection potential.", "behavioral_trigger": "memory_manipulation_import"},
        "sys/shm.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Shared memory - code injection potential.", "behavioral_trigger": "memory_manipulation_import"},
        
        # Cryptography - HIGH priority
        "crypt.h": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Cryptography functions.", "behavioral_trigger": "crypto_import"},
        "openssl.h": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "OpenSSL cryptographic operations.", "behavioral_trigger": "crypto_import"},
        
        # Obfuscation
        "zlib.h": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.3, "desc": "Compression library.", "behavioral_trigger": "compression_obfuscation"},
        
        # Error handling/threading - low priority
        "string.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "String manipulation."},
        "signal.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "LOW", "weight": 0.2, "desc": "Signal handling."},
        "pthread.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Thread management."},
        "time.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Time functions."},
        "sys/time.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "System time access."},
        "syslog.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "System logging."},
        "errno.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Error handling."},
        "assert.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Assertions."},
        
        # IPC - medium priority
        "sys/ipc.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "Inter-process communication."},
        "sys/msg.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "Message queues."},
        "sys/sem.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "LOW", "weight": 0.2, "desc": "Semaphore operations."},
        
        # Character/locale handling - very low priority
        "ctype.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Character classification."},
        "locale.h": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Locale settings."},
    }

    # METHOD_CALLS: Dangerous or sensitive function or method calls.
    METHOD_CALLS: dict[str, dict[str, Any]] = {
        # Buffer overflow vulnerabilities - CRITICAL
        "strcpy": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.9, "desc": "strcpy - buffer overflow risk."},
        "strcat": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.9, "desc": "strcat - buffer overflow risk."},
        "gets": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.95, "desc": "gets - inherently unsafe function."},
        "sprintf": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.9, "desc": "sprintf - buffer overflow risk."},
        
        # Code execution - CRITICAL
        "system": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "OS command execution via system().", "behavioral_trigger": "os_command_exec"},
        "fork": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Process creation.", "behavioral_trigger": "process_creation"},
        "exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Process replacement.", "behavioral_trigger": "process_replacement"},
        "execve": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Execute program.", "behavioral_trigger": "process_replacement"},
        "execl": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Execute program with arguments.", "behavioral_trigger": "process_replacement"},
        
        # Memory management - HIGH (code injection potential)
        "mmap": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Memory mapping - code injection potential.", "behavioral_trigger": "memory_mapping"},
        "VirtualAlloc": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Windows virtual memory allocation.", "behavioral_trigger": "memory_allocation"},
        "ShellExecute": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Windows program execution.", "behavioral_trigger": "os_command_exec"},
        
        # File operations - adjusted priorities
        "fopen": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File opening.", "behavioral_trigger": "file_access"},
        "fclose": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File closing."},
        "fread": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File reading.", "behavioral_trigger": "file_read"},
        "fwrite": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "File writing.", "behavioral_trigger": "file_write"},
        "remove": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "File deletion.", "behavioral_trigger": "file_delete"},
        "rename": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "File renaming.", "behavioral_trigger": "file_rename"},
        "chmod": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File permission change.", "behavioral_trigger": "file_permission_change"},
        "chown": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File ownership change.", "behavioral_trigger": "file_permission_change"},
        "mkdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.3, "desc": "Directory creation."},
        "rmdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.6, "desc": "Directory removal.", "behavioral_trigger": "file_delete"},
        "stat": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "File status retrieval."},
        "lstat": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "Symbolic link status."},
        
        "CreateFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Windows file access.", "behavioral_trigger": "file_access"},
        "WriteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.6, "desc": "Windows file writing.", "behavioral_trigger": "file_write"},
        "DeleteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Windows file deletion.", "behavioral_trigger": "file_delete"},
        "URLDownloadToFile": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.7, "desc": "File download from URL.", "behavioral_trigger": "file_download"},
        
        "getenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Environment variable access."},
        "setenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Environment variable setting."},
        "putenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Environment variable modification."},
        
        "signal": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "LOW", "weight": 0.2, "desc": "Signal handling."},
        "sigaction": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "LOW", "weight": 0.2, "desc": "Advanced signal handling."},
        "pthread_create": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Thread creation."},
        "pthread_join": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Thread joining."},
        "pthread_mutex_lock": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Mutex locking."},
    }
    
    STRING_KEYWORDS: dict[str, dict[str, Any]] = BaseSignatures.STRING_KEYWORDS
    NAMING_CONVENTIONS: dict[str, dict[str, Any]] = BaseSignatures.NAMING_CONVENTIONS

    STRUCTURAL_PATTERNS: dict[str, dict[str, Any]] = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Sensitive system path access.", "behavioral_trigger": "sensitive_path_ref"},
        "SELF_AWARE_CODE_ARGV0": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "weight": 0.7, "desc": "Self execution name access (argv[0]).", "behavioral_trigger": "self_location_name"},
        "EMPTY_FUNCTION_BODY": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "weight": 0.4, "desc": "Empty function body."},
        "SIMPLE_FUNCTION_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.4, "desc": "Simple function body - possible evasion."}
    }

class CppSignatures(BaseSignatures):
    """
    Security Signatures for C++ language - Improved for ransomware detection.
    """
    # IMPORTS: Suspicious imports/modules or header inclusions.
    IMPORTS: dict[str, dict[str, Any]] = {
        # Basic I/O
        "iostream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Standard I/O streams.", "behavioral_trigger": "file_access_import"},
        "fstream": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File stream manipulation.", "behavioral_trigger": "file_access_import"},
        
        # System access
        "windows.h": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "Windows API access."},
        "unistd.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "Unix system calls.", "behavioral_trigger": "code_exec_import"},
        "fcntl.h": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.3, "desc": "File control.", "behavioral_trigger": "file_access_import"},
        
        # Network
        "sys/socket.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Network sockets (Unix/Linux).", "behavioral_trigger": "network_import"},
        "netinet/in.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Internet addresses (Unix/Linux).", "behavioral_trigger": "network_import"},
        "arpa/inet.h": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Internet address conversion (Unix/Linux).", "behavioral_trigger": "network_import"},
        
        # Memory management
        "sys/mman.h": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Memory mapping - code injection potential.", "behavioral_trigger": "memory_manipulation_import"},
        
        # Cryptography
        "cryptopp": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Crypto++ library.", "behavioral_trigger": "crypto_import"},
        "openssl": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "OpenSSL library.", "behavioral_trigger": "crypto_import"},
    }

    # METHOD_CALLS: Dangerous or sensitive function or method calls.
    METHOD_CALLS: dict[str, dict[str, Any]] = {
        # C-style vulnerabilities (inherited from C)
        "strcpy": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.9, "desc": "strcpy - buffer overflow risk."},
        "strcat": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.9, "desc": "strcat - buffer overflow risk."},
        "gets": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.95, "desc": "gets - inherently unsafe."},
        "sprintf": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "CRITICAL", "weight": 0.9, "desc": "sprintf - buffer overflow risk."},

        # Code execution        
        "system": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "OS command execution via system().", "behavioral_trigger": "os_command_exec"},
        "fork": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Process creation.", "behavioral_trigger": "process_creation"},
        "exec": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Process replacement.", "behavioral_trigger": "process_replacement"},
        "execve": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Execute program.", "behavioral_trigger": "process_replacement"},
        "execl": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Execute program with arguments.", "behavioral_trigger": "process_replacement"},
        
        # Memory management
        "mmap": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Memory mapping - code injection potential.", "behavioral_trigger": "memory_mapping"},
        "VirtualAlloc": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Windows virtual memory allocation.", "behavioral_trigger": "memory_allocation"},
        "ShellExecute": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Windows program execution.", "behavioral_trigger": "os_command_exec"},
        
        "fopen": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File opening.", "behavioral_trigger": "file_access"},
        "fclose": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File closing."},
        "fread": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File reading.", "behavioral_trigger": "file_read"},
        "fwrite": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "File writing.", "behavioral_trigger": "file_write"},
        "remove": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "File deletion.", "behavioral_trigger": "file_delete"},
        "rename": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "File renaming.", "behavioral_trigger": "file_rename"},
        "chmod": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File permission change.", "behavioral_trigger": "file_permission_change"},
        "chown": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File ownership change.", "behavioral_trigger": "file_permission_change"},
        "mkdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.3, "desc": "Directory creation."},
        "rmdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.6, "desc": "Directory removal.", "behavioral_trigger": "file_delete"},
        "stat": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "File status retrieval."},
        "lstat": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.2, "desc": "Symbolic link status."},
        
        "CreateFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Windows file access.", "behavioral_trigger": "file_access"},
        "WriteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.6, "desc": "Windows file writing.", "behavioral_trigger": "file_write"},
        "DeleteFile": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Windows file deletion.", "behavioral_trigger": "file_delete"},
        "URLDownloadToFile": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.7, "desc": "File download from URL.", "behavioral_trigger": "file_download"},
        
        "getenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Environment variable access."},
        "setenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Environment variable setting."},
        "putenv": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Environment variable modification."},
        
        "signal": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "LOW", "weight": 0.2, "desc": "Signal handling."},
        "sigaction": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "LOW", "weight": 0.2, "desc": "Advanced signal handling."},
        "pthread_create": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Thread creation."},
        "pthread_join": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Thread joining."},
        "pthread_mutex_lock": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "INFO", "weight": 0.1, "desc": "Mutex locking."},
    }
    
    STRING_KEYWORDS: dict[str, dict[str, Any]] = BaseSignatures.STRING_KEYWORDS
    NAMING_CONVENTIONS: dict[str, dict[str, Any]] = BaseSignatures.NAMING_CONVENTIONS

    STRUCTURAL_PATTERNS: dict[str, dict[str, Any]] = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Sensitive system path access.", "behavioral_trigger": "sensitive_path_ref"},
        "SELF_AWARE_CODE": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "HIGH", "weight": 0.7, "desc": "Self execution name access.", "behavioral_trigger": "self_location_name"},
        "EMPTY_FUNCTION_BODY": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "weight": 0.4, "desc": "Empty function body."},
        "SIMPLE_FUNCTION_BODY": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.4, "desc": "Simple function body - possible evasion."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "HIGH", "weight": 0.6, "desc": "Suspicious method override - potential evasion."},
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "weight": 0.5, "desc": "Empty catch block hiding errors."}
    }

class JavaScriptSignatures(BaseSignatures):
    """
    Security Signatures for JavaScript language - Improved for ransomware detection.
    """
    # IMPORTS: Suspicious imports/modules or header inclusions.
    IMPORTS: dict[str, dict[str, Any]] = {
        # File System - Balanced for legitimate vs malicious use
        "fs": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "File system access capability.", "behavioral_trigger": "file_access_import"},
        "fs/promises": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Promise-based file operations.", "behavioral_trigger": "file_access_import"},
        "path": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Path manipulation utilities.", "behavioral_trigger": "file_access_import"},
        "glob": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "File pattern matching - common in ransomware.", "behavioral_trigger": "file_traversal_import"},
        "graceful-fs": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "Enhanced file system operations.", "behavioral_trigger": "file_access_import"},
        "recursive-readdir": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Recursive directory traversal - ransomware indicator.", "behavioral_trigger": "file_traversal_import"},
        "rimraf": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Recursive file deletion utility.", "behavioral_trigger": "file_delete_import"},
        
        # Code Execution - High priority for security
        "child_process": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "System command execution capability.", "behavioral_trigger": "code_exec_import"},
        "vm": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "JavaScript VM - dynamic code execution.", "behavioral_trigger": "code_exec_import"},
        "vm2": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Sandboxed VM - still code execution risk.", "behavioral_trigger": "code_exec_import"},
        "worker_threads": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "weight": 0.2, "desc": "Worker threads - legitimate parallelism."},
        "shelljs": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Shell command abstraction library.", "behavioral_trigger": "code_exec_import"},
        
        # Network Communication - Reduced weights for common libraries
        "net": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.4, "desc": "Low-level networking.", "behavioral_trigger": "network_import"},
        "http": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "Standard HTTP module.", "behavioral_trigger": "network_import"},
        "https": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "Standard HTTPS module.", "behavioral_trigger": "network_import"},
        "axios": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "Popular HTTP client.", "behavioral_trigger": "network_import"},
        "request": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "HTTP request library (deprecated).", "behavioral_trigger": "network_import"},
        "node-fetch": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "Fetch API for Node.js.", "behavioral_trigger": "network_import"},
        "ws": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.2, "desc": "WebSocket library.", "behavioral_trigger": "network_import"},
        "socket.io": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.2, "desc": "Real-time communication library.", "behavioral_trigger": "network_import"},
        
        # Tor/Anonymity Networks - High priority for ransomware
        "tor-request": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.9, "desc": "Tor network requests - anonymity tool.", "behavioral_trigger": "tor_network"},
        "socks-proxy-agent": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.7, "desc": "SOCKS proxy support - potential anonymity.", "behavioral_trigger": "proxy_network"},
        
        # Cryptography - High priority, but balanced
        "crypto": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.4, "desc": "Node.js cryptography module.", "behavioral_trigger": "crypto_import"},
        "crypto-js": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "JavaScript crypto library - common in ransomware.", "behavioral_trigger": "crypto_import"},
        "node-forge": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Pure JS cryptography - no native deps.", "behavioral_trigger": "crypto_import"},
        "tweetnacl": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Compact crypto library.", "behavioral_trigger": "crypto_import"},
        "bcrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "LOW", "weight": 0.2, "desc": "Password hashing - legitimate use."},
        "argon2": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "LOW", "weight": 0.2, "desc": "Password hashing - legitimate use."},
        
        # System Information - Reduced priority
        "os": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "OS utilities - very common."},
        "process": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Process information - very common."},
        "systeminformation": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "Detailed system information gathering."},
        "node-machine-id": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "Machine fingerprinting.", "behavioral_trigger": "machine_id_access"},
        
        # Obfuscation - Balanced weights
        "javascript-obfuscator": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "HIGH", "weight": 0.8, "desc": "Code obfuscation tool.", "behavioral_trigger": "code_obfuscation"},
        "uglify-js": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.2, "desc": "Code minification - legitimate use."},
        "terser": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.2, "desc": "Code minification - legitimate use."},
        "base64": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.2, "desc": "Base64 encoding.", "behavioral_trigger": "base64_obfuscation"},
        "atob": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.4, "desc": "Base64 decoding utility.", "behavioral_trigger": "base64_obfuscation"},
        "btoa": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.4, "desc": "Base64 encoding utility.", "behavioral_trigger": "base64_obfuscation"},
        
        # Compression - Low priority
        "zlib": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "INFO", "weight": 0.1, "desc": "Compression - very common.", "behavioral_trigger": "compression_obfuscation"},
        "archiver": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.2, "desc": "Archive creation."},
        "yauzl": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.2, "desc": "ZIP extraction."},
        "node-7z": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "LOW", "weight": 0.3, "desc": "7-Zip archive handling."},
        
        # Windows-specific APIs - Higher priority for ransomware
        "ffi-napi": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Foreign function interface - native code calls.", "behavioral_trigger": "native_code_access"},
        "node-gyp": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "Native addon compilation."},
        "ref-napi": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Native type system - memory manipulation.", "behavioral_trigger": "native_code_access"},
        
        # Persistence mechanisms
        "node-schedule": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "Task scheduling.", "behavioral_trigger": "scheduled_task"},
        "node-cron": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "Cron-like scheduling.", "behavioral_trigger": "scheduled_task"},
        "auto-launch": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Auto-start application.", "behavioral_trigger": "startup_entry"},
        
        # Registry manipulation (Windows)
        "winreg": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Windows registry access.", "behavioral_trigger": "registry_access"},
        "node-windows": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Windows service creation.", "behavioral_trigger": "service_creation"},
    }

    METHOD_CALLS: dict[str, dict[str, Any]] = {
        # Dynamic Code Execution - CRITICAL priority
        "eval(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.95, "desc": "Dynamic code execution from string.", "behavioral_trigger": "dynamic_code_exec"},
        "new Function(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Dynamic function creation.", "behavioral_trigger": "dynamic_code_exec"},
        "Function(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Function constructor.", "behavioral_trigger": "dynamic_code_exec"},
        "vm.runInThisContext": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Code execution in current context.", "behavioral_trigger": "dynamic_code_exec"},
        "vm.runInNewContext": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "Code execution in new context.", "behavioral_trigger": "dynamic_code_exec"},
        "vm2.NodeVM": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Sandboxed VM execution.", "behavioral_trigger": "dynamic_code_exec"},
        
        # String-based timers (less common, higher suspicion)
        "setTimeout.*eval": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "setTimeout with eval - code injection.", "behavioral_trigger": "dynamic_code_exec"},
        "setInterval.*eval": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "CRITICAL", "weight": 0.9, "desc": "setInterval with eval - code injection.", "behavioral_trigger": "dynamic_code_exec"},
        
        # System Command Execution
        "child_process.exec(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "System command execution.", "behavioral_trigger": "os_command_exec"},
        "child_process.execSync(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Synchronous command execution.", "behavioral_trigger": "os_command_exec"},
        "child_process.spawn(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Process spawning - more controlled.", "behavioral_trigger": "process_creation"},
        "child_process.spawnSync(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.6, "desc": "Synchronous process spawning.", "behavioral_trigger": "process_creation"},
        "child_process.fork(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.5, "desc": "Process forking - Node.js specific.", "behavioral_trigger": "process_creation"},
        "child_process.execFile(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Direct file execution.", "behavioral_trigger": "external_command_exec"},
        
        # Shell.js commands - specific patterns
        "shell.exec(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.8, "desc": "Shell command via shelljs.", "behavioral_trigger": "os_command_exec"},
        "shell.rm(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "File deletion via shelljs.", "behavioral_trigger": "file_delete"},
        
        # Dynamic Module Loading - Medium priority
        "require(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "weight": 0.2, "desc": "Dynamic module loading - common in Node.js.", "behavioral_trigger": "dynamic_module_load"},
        "import(": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "LOW", "weight": 0.2, "desc": "Dynamic ES6 import.", "behavioral_trigger": "dynamic_module_load"},
        
        # File System Operations - Balanced weights
        "fs.readFile(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "File reading.", "behavioral_trigger": "file_read"},
        "fs.readFileSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Synchronous file reading.", "behavioral_trigger": "file_read"},
        "fs.writeFile(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File writing.", "behavioral_trigger": "file_write"},
        "fs.writeFileSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Synchronous file writing.", "behavioral_trigger": "file_write"},
        "fs.appendFile(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "File appending.", "behavioral_trigger": "file_write"},
        "fs.appendFileSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "Synchronous file appending.", "behavioral_trigger": "file_write"},
        
        # File Deletion - High priority for ransomware
        "fs.unlink(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "File deletion.", "behavioral_trigger": "file_delete"},
        "fs.unlinkSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Synchronous file deletion.", "behavioral_trigger": "file_delete"},
        "fs.rmdir(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "Directory removal.", "behavioral_trigger": "file_delete"},
        "fs.rmdirSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "Synchronous directory removal.", "behavioral_trigger": "file_delete"},
        "fs.rm(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Modern file/directory removal.", "behavioral_trigger": "file_delete"},
        "fs.rmSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Synchronous file/directory removal.", "behavioral_trigger": "file_delete"},
        
        # File Renaming/Moving
        "fs.rename(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "File/directory renaming.", "behavioral_trigger": "file_rename"},
        "fs.renameSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "Synchronous renaming.", "behavioral_trigger": "file_rename"},
        "fs.copyFile(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "File copying.", "behavioral_trigger": "file_copy"},
        
        # Directory Traversal - Important for ransomware detection
        "fs.readdir(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "Directory listing.", "behavioral_trigger": "file_traversal"},
        "fs.readdirSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "LOW", "weight": 0.3, "desc": "Synchronous directory listing.", "behavioral_trigger": "file_traversal"},
        "glob.sync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "Synchronous pattern matching.", "behavioral_trigger": "file_traversal"},
        "glob(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.6, "desc": "File pattern matching.", "behavioral_trigger": "file_traversal"},
        "glob.**": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Recursive glob pattern - ransomware indicator.", "behavioral_trigger": "file_traversal"},
        
        # File Permissions
        "fs.chmod(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File permission change.", "behavioral_trigger": "file_permission_change"},
        "fs.chmodSync(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Synchronous permission change.", "behavioral_trigger": "file_permission_change"},
        "fs.chown(": {"type": FINDING_TYPE_FILE_SYSTEM_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "File ownership change.", "behavioral_trigger": "file_permission_change"},
        
        # Critical Ransomware Commands - CRITICAL priority
        "vssadmin delete shadows": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Shadow copy deletion command.", "behavioral_trigger": "shadow_copy_delete"},
        "wbadmin delete catalog": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Backup catalog deletion.", "behavioral_trigger": "backup_delete"},
        "bcdedit /set {default} recoveryenabled No": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Windows recovery disabling.", "behavioral_trigger": "recovery_disable"},
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures": {"type": FINDING_TYPE_BACKUP_DESTRUCTION, "severity": "CRITICAL", "weight": 0.98, "desc": "Boot failure handling disable.", "behavioral_trigger": "recovery_disable"},
        
        # Service Manipulation
        "net stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.8, "desc": "Service stopping command.", "behavioral_trigger": "service_stop"},
        "sc stop": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.8, "desc": "Service control stop.", "behavioral_trigger": "service_stop"},
        "taskkill /f": {"type": FINDING_TYPE_SERVICE_DISRUPTION, "severity": "HIGH", "weight": 0.8, "desc": "Force process termination.", "behavioral_trigger": "process_kill"},
        
        # Registry Manipulation
        "reg add": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Registry modification.", "behavioral_trigger": "registry_modification"},
        "reg delete": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Registry deletion.", "behavioral_trigger": "registry_modification"},
        "winreg.createKey": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Registry key creation.", "behavioral_trigger": "registry_modification"},
        "winreg.setValueEx": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Registry value setting.", "behavioral_trigger": "registry_modification"},
        
        # Network Communication - Reduced weights for common operations
        "http.request(": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.2, "desc": "HTTP request.", "behavioral_trigger": "network_request"},
        "https.request(": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.2, "desc": "HTTPS request.", "behavioral_trigger": "network_request"},
        "axios.post(": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.2, "desc": "HTTP POST via axios.", "behavioral_trigger": "network_request"},
        "fetch(": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "INFO", "weight": 0.1, "desc": "Modern HTTP request.", "behavioral_trigger": "network_request"},
        
        # Direct socket connections - Higher suspicion
        "net.createConnection(": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Direct network connection.", "behavioral_trigger": "network_connection"},
        "new net.Socket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "MEDIUM", "weight": 0.5, "desc": "Raw socket creation.", "behavioral_trigger": "network_connection"},
        
        # WebSocket - Medium priority
        "new WebSocket": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "LOW", "weight": 0.3, "desc": "WebSocket connection.", "behavioral_trigger": "network_connection"},
        
        # Tor/Proxy requests - High priority
        "tor-request(": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.9, "desc": "Tor network request.", "behavioral_trigger": "tor_network"},
        "socksConnection": {"type": FINDING_TYPE_NETWORK_COMMUNICATION, "severity": "HIGH", "weight": 0.8, "desc": "SOCKS proxy connection.", "behavioral_trigger": "proxy_network"},
        
        # Cryptographic Operations
        "crypto.createCipher(": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Cipher creation.", "behavioral_trigger": "crypto_op"},
        "crypto.createDecipher(": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Decipher creation.", "behavioral_trigger": "crypto_op"},
        "crypto.createCipheriv(": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Cipher with IV creation.", "behavioral_trigger": "crypto_op"},
        "crypto.createDecipheriv(": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Decipher with IV creation.", "behavioral_trigger": "crypto_op"},
        "CryptoJS.AES.encrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "AES encryption.", "behavioral_trigger": "crypto_op"},
        "CryptoJS.AES.decrypt": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "AES decryption.", "behavioral_trigger": "crypto_op"},
        "forge.cipher.createCipher": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "HIGH", "weight": 0.8, "desc": "Forge cipher creation.", "behavioral_trigger": "crypto_op"},
        
        # Hash functions - Lower priority
        "crypto.createHash(": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "LOW", "weight": 0.2, "desc": "Hash creation - common use."},
        "crypto.randomBytes(": {"type": FINDING_TYPE_CRYPTOGRAPHIC_USE, "severity": "MEDIUM", "weight": 0.4, "desc": "Random byte generation.", "behavioral_trigger": "crypto_op"},
        
        # Self-awareness - Reduced weights for common Node.js patterns
        "__filename": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "INFO", "weight": 0.1, "desc": "Current filename - very common in Node.js.", "behavioral_trigger": "self_location_ref"},
        "__dirname": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "INFO", "weight": 0.1, "desc": "Current directory - very common in Node.js.", "behavioral_trigger": "self_location_ref"},
        "process.argv[0]": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "LOW", "weight": 0.3, "desc": "Node.js executable path.", "behavioral_trigger": "self_location_name"},
        "process.execPath": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "LOW", "weight": 0.3, "desc": "Node.js executable path.", "behavioral_trigger": "self_location_path"},
        "process.cwd()": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "INFO", "weight": 0.1, "desc": "Current working directory - very common.", "behavioral_trigger": "self_location_path"},
        
        # Browser-specific self-awareness - Higher suspicion in non-browser contexts
        "window.location": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.6, "desc": "Browser location access.", "behavioral_trigger": "self_location_browser"},
        "document.currentScript": {"type": FINDING_TYPE_SELF_AWARE_BEHAVIOR, "severity": "MEDIUM", "weight": 0.6, "desc": "Current script reference.", "behavioral_trigger": "self_location_browser"},
        
        # System Information Gathering
        "os.platform()": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Platform detection - very common."},
        "os.hostname()": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "LOW", "weight": 0.2, "desc": "Hostname access."},
        "os.userInfo()": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "User information access."},
        "process.env": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "INFO", "weight": 0.1, "desc": "Environment variables - very common."},
        
        # Machine ID / Fingerprinting - Higher suspicion
        "machineId.machineIdSync": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "HIGH", "weight": 0.7, "desc": "Machine ID generation.", "behavioral_trigger": "machine_id_access"},
        "getMAC()": {"type": FINDING_TYPE_SYSTEM_INFO_ACCESS, "severity": "MEDIUM", "weight": 0.5, "desc": "MAC address access.", "behavioral_trigger": "machine_id_access"},
        "localStorage": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Browser local storage access."},
        "sessionStorage": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Browser session storage access."},
        "indexedDB": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "MEDIUM", "weight": 0.4, "desc": "Browser IndexedDB access."},
        
        "process.exit": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "MEDIUM", "weight": 0.4, "desc": "Process termination."},
        "process.kill": {"type": FINDING_TYPE_CODE_EXECUTION, "severity": "HIGH", "weight": 0.7, "desc": "Process killing."},
    }
    
    STRING_KEYWORDS: dict[str, dict[str, Any]] = BaseSignatures.STRING_KEYWORDS
    NAMING_CONVENTIONS: dict[str, dict[str, Any]] = BaseSignatures.NAMING_CONVENTIONS
    STRUCTURAL_PATTERNS = {
        "SENSITIVE_PATH_ACCESS": {"type": FINDING_TYPE_SENSITIVE_DATA_ACCESS, "severity": "HIGH", "weight": 0.8, "desc": "Sensitive system path access.", "behavioral_trigger": "sensitive_path_ref"},
        "EMPTY_CATCH_BLOCK": {"type": FINDING_TYPE_IMPROPER_ERROR_HANDLING, "severity": "MEDIUM", "weight": 0.5, "desc": "Empty catch block, may hide critical errors."},
        "SUSPICIOUS_OVERRIDE": {"type": FINDING_TYPE_OBFUSCATION_TECHNIQUE, "severity": "MEDIUM", "weight": 0.5, "desc": "Overridden method with empty or very simple body, possible evasion technique."}
    }