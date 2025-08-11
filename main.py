import os
import json
from handleListeners.HandleListeners import AntlrListenerHandler
from typing import List, Dict, Any

# Define the root directory for code samples relative to this script's location.
ROOT_DIR_FOR_TESTS: str = os.path.abspath(os.path.join(os.path.dirname(__file__), 'codeSamples')) 

# Define paths to various sample files for testing.
JAVA_SAMPLE_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'Java', 'SuspiciousSample.java')
JAVA_SAMPLE_FILE_2: str = os.path.join(ROOT_DIR_FOR_TESTS, 'Java', 'vulnerable_sample.java')
PYTHON_SAMPLE_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'Python', 'vulnerable_sample.py')
UNSUPPORTED_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'unsupported.xyz') 
MALFORMED_PYTHON_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'Python', 'malformed_sample.py')
C_SAMPLE_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'C', 'vulnerable_sample.c') # C test file
CPP_SAMPLE_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'Cpp', 'vulnerable_sample.cpp') # C++ test file
JS_SAMPLE_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'JavaScript', 'vulnerable_sample.js') # JavaScript test file
JS_RANSOMWARE_FILE: str = os.path.join(ROOT_DIR_FOR_TESTS, 'JavaScript', 'ransomware_detected.js') # JavaScript ransomware sample



def run_analysis_tests() -> None:
    """
    Executes a series of static analysis tests on various code samples
    using the AntlrListenerHandler. It prints the analysis report for each file.
    """
    handler: AntlrListenerHandler = AntlrListenerHandler()

    reports_to_run: List[str] = [
        JAVA_SAMPLE_FILE,
        JAVA_SAMPLE_FILE_2,  # Added another Java file for testing
        PYTHON_SAMPLE_FILE,
        UNSUPPORTED_FILE,
        MALFORMED_PYTHON_FILE,
        C_SAMPLE_FILE,
        CPP_SAMPLE_FILE,
        JS_SAMPLE_FILE,
        JS_RANSOMWARE_FILE
    ]

    for file_path in reports_to_run:
        print(f"\n\n===== Analyzing file: {file_path} =====")
        try:
            report: Dict[str, Any] = handler.analyze_file(file_path)
            print(json.dumps(report, indent=4, ensure_ascii=False))
        except Exception as e:
            print(f"FATAL ERROR processing {file_path}: {e}")

    # --- Optional: Run analysis on an entire directory ---
    # print(f"\n\n===== Analyzing directory: {ROOT_DIR_FOR_TESTS} =====")
    # all_reports = handler.analyze_directory(ROOT_DIR_FOR_TESTS)
    # for report in all_reports:
    #     print(json.dumps(report, indent=4, ensure_ascii=False))
    #     print("\n-------------------------------------------------\n")

    print("\nANTLR4 test analysis finished.")


if __name__ == "__main__":
    run_analysis_tests()