# ANTLRDetection Module - Static Source Code Analysis

## 🚀 Introduction

This repository hosts the **ANTLRDetection module**, a core component of the **VESTA** project. VESTA aims to develop a European cybersecurity system to proactively protect infrastructures from ransomware attacks, especially those based on phishing, with a special focus on **Smart Grids**.

The ANTLRDetection module specializes in **Static Application Security Testing (SAST)**. It leverages the powerful ANTLR4 tool to parse source code from various programming languages. Its two main objectives are:

* **Feature Extraction**: Generates a vector of 12 numerical features ("proxies") from the source code. This feature vector feeds VESTA's AI models for ransomware risk prediction.
* **Security Findings Detection**: Identifies suspicious code patterns, known vulnerabilities, and bad security practices, compiling them into a structured and enriched report.

The module is designed to be **modular and extensible**, allowing the easy integration of new languages and detection patterns, while maintaining consistent reporting through a standardized taxonomy of findings.

## 📁 Project Structure

```
.
├── codeSamples/
│   ├── C/
│   ├── Cpp/
│   ├── Java/
│   ├── JavaScript/
│   └── Python/
├── grammars/
│   ├── C/
│   ├── CPP/
│   ├── Java/
│   ├── JavaScript/
│   └── Python/
├── handleListeners/
│   └── AntlrListenerHandler.py
├── listeners/
│   ├── VestaCListener.py
│   ├── VestaCppListener.py
│   ├── VestaJavaListener.py
│   ├── VestaJavaScriptListener.py
│   └── VestaPythonListener.py
├── signatures/
│   └── finding_types.py
├── main.py
├── .gitignore
└── requirements.txt
```

### Description of Key Folders and Files:

* **codeSamples/**: Contains language-specific subfolders with sample source code files. These samples include both benign and suspicious patterns for testing the listeners.
* **grammars/**: Holds ANTLR4 grammars (.g4 files) and the generated Python code (Lexer.py, Parser.py, Listener.py). Each language has its own subdirectory.
* **handleListeners/**: Contains `AntlrListenerHandler.py`, the main orchestrator that detects the file language, loads the correct lexer/parser/listener, runs the analysis, and returns the report.
* **listeners/**: Contains custom ANTLR listeners (`VestaXListener.py`) for each supported language, responsible for extracting the 12 proxy features and detecting language-specific security findings.
* **signatures/**: Includes `finding_types.py`, which defines standardized finding types and language-specific detection signatures.
* **main.py**: The entry point script to test ANTLRDetection on example files.
* **.gitignore**: Specifies files and directories Git should ignore (e.g., virtual environments, generated files).
* **requirements.txt**: Lists the Python dependencies required to run the project.

## ⚙️ Prerequisites

To run this project locally, you need the following:

* **Java Runtime Environment (JRE)**: Required by ANTLR4.

  * [Download JRE](https://www.oracle.com/java/technologies/javase-jre8-downloads.html) (version 8 or higher).

* **Python 3.x** (recommended: Python 3.8+)

  * [Download Python](https://www.python.org/downloads/)

* **pip**: Python's package manager (comes with Python 3).

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repository.git
cd your-repository/
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install & Configure ANTLR4

#### Download ANTLR4 JAR:

* Download `antlr-4.13.2-complete.jar` from:
  [https://www.antlr.org/download.html](https://www.antlr.org/download.html)
* Save it to a directory like `C:\antlr\bin\` (Windows) or `/usr/local/lib/antlr/` (Linux/macOS)

#### Set up `antlr4` command:

**Windows:**

* Create a file `antlr4.bat` in the same folder as the `.jar`:

```bat
@echo off
java -jar "C:\antlr\bin\antlr-4.13.2-complete.jar" %*
```

* Add the folder to your system's `Path` environment variable.

**macOS/Linux:**

* Add this alias to your shell config (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
alias antlr4='java -jar /usr/local/lib/antlr/antlr-4.13.2-complete.jar'
```

* Apply changes with:

```bash
source ~/.bashrc  # or ~/.zshrc
```

### 5. Generate Language Parsers

```bash
cd grammars/
```

#### Java:

```bash
cd Java/
antlr4 -Dlanguage=Python3 JavaLexer.g4 JavaParser.g4 -listener -visitor
cd ..
```

#### Python:

```bash
cd Python/
python transformGrammar.py
antlr4 -Dlanguage=Python3 Python3Lexer.g4 Python3Parser.g4 -listener -visitor
cd ..
```

#### C:

```bash
cd C/
antlr4 -Dlanguage=Python3 C.g4 -listener -visitor
cd ..
```

#### C++:

```bash
cd CPP/
antlr4 -Dlanguage=Python3 CPP14ParserBase.g4 -listener -visitor
antlr4 -Dlanguage=Python3 CPP14Lexer.g4 CPP14Parser.g4 -listener -visitor
cd ..
```

#### JavaScript:

```bash
cd JavaScript/
python transformGrammar.py
antlr4 -Dlanguage=Python3 JavaScriptLexer.g4 JavaScriptParser.g4 -listener -visitor
cd ..
```

Return to project root:

```bash
cd ..
```

## 🚀 Using the ANTLRDetection Module

Once all dependencies and parsers are set up, run the main script to analyze code samples:

```bash
python -m handleListeners.main
```

This will execute `main.py`, which uses `AntlrListenerHandler` to analyze files in `codeSamples/` and print enriched reports to the console.

## 📄 License

This project is licensed under the MIT License. See the LICENSE file for more details.

---

Developed by:
**Engineer Juan Sebastian Fernandez Buitrago**
