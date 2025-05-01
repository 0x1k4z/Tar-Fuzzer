# Project-Fuzzing

**Generation-Based Fuzzer for a Tar Extractor**

## 🛠 Overview

This project implements a **generation-based fuzzer** in C, designed to test the robustness of a simple tar extractor by generating syntactically valid but malicious `.tar` archives. The goal is to identify inputs that cause the extractor to crash, simulating a real-world vulnerability discovery process.

## 🎯 Project Objective

Develop a fuzzer that:
- Generates `.tar` files conforming to the [POSIX 1003.1-1990 tar format](https://www.gnu.org/software/tar/manual/html_node/Standard.html)
- Varies header fields and structures intelligently to discover edge cases and vulnerabilities
- Detects crashes by analyzing the extractor's output
- Saves crashing inputs as files prefixed with `success_` for later analysis

---

## 📦 Prerequisites

- GCC (or Clang) installed on a Linux x86-64 system
- Access to a **tar extractor** binary (e.g., `./extractor`)

---

## ⚙️ Building the Fuzzer

To compile the fuzzer:

```bash
make
```

This command will produce an executable named `fuzzer`.

---

## 🚀 Running the Fuzzer

To start the fuzzing process:

```bash
./fuzzer /path/to/extractor
```

Replace `/path/to/extractor` with the actual path to your tar extractor (e.g., `./extractor`). The fuzzer will:

1. Generate `.tar` files with various header configurations.
2. Run the extractor on each archive.
3. Monitor its output for the crash message:

```
*** The program has crashed ***
```

4. Save crashing inputs as `success_*.tar` for further inspection.

> ℹ️ You may need to grant execute permission to the extractor:
```bash
chmod +x extractor
```

---

## 🧹 Cleaning Up

To remove compiled binaries and intermediate files:

```bash
make clean
```

---

## 👨‍💻 Authors

- **[hfoudia](https://github.com/0x1k4z)**
- **[amirshehrzad](https://github.com/amirshehrzad)**