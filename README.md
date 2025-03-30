# AnvilELF ⚒️🔥

![CI](https://github.com/Dasuos/AnvilELF/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dasuos/AnvilELF/graph/badge.svg?token=VGJ51NS4HK)](https://codecov.io/gh/dasuos/AnvilELF)

**From raw bytes to forged ELF—crafted with purist OOP.**

AnvilELF is a purist object-oriented tool for ELF binary parsing, modification, tracing, and code injection. It is built with **SOLID principles**, **full test coverage**, and a strong focus on **maintainability**.

## 🚀 Roadmap 

|  **Binary Format**               |  **Process Tracing & Code Injection**   |
|----------------------------------|-----------------------------------------|
| ✅ Executable Header              | 🔄 Process Tracing (`ptrace` & `/proc`) |
| ✅ Section Headers                | 🔄 Infection Detection                  |
| ✅ Sections                      | 🔄 Code Injection                       |
| 🔄 String & Symbol Tables        |                                         |
| 🔄 Program Headers               |                                         |
| 🔄 Segments                      |                                         |
| 🔄 Dynamic Linking & Relocations |                                         |


## 🐍 Installation 
```sh
git clone https://github.com/dasuos/AnvilELF.git
cd AnvilELF
make install
```

## ⚡ Usage 

### ✅ Code quality & testing 
To verify code formatting, linting, type safety, and run all tests, use:
```sh
make check
```

### 🛠️ Auto-fixing code 
To automatically format and fix code style issues, run:
```sh
make fix
```

### 🧹 Clean up 
To remove the container and Docker image:
```sh
make clean
```
