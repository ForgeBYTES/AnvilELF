# AnvilELF ⚒️🔥

![CI](https://github.com/Dasuos/AnvilELF/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dasuos/AnvilELF/graph/badge.svg?token=VGJ51NS4HK)](https://codecov.io/gh/dasuos/AnvilELF)

**From raw bytes to forged ELF—crafted with purist OOP.**

AnvilELF is a purist object-oriented tool for ELF binary parsing, inspection, and modification.  
It is built with **SOLID principles**, **full test coverage**, and a strong focus on **maintainability**.

![AnvilELF CLI in action](media/cli_preview.gif)

---

## 🚀 Roadmap

| **Structure**                  | **Manipulation**             |
|--------------------------------|------------------------------|
| ✅ Executable Header            | 🔄 Process Tracing           |
| ✅ Section Headers              | 🔄 Patching & Code Injection |
| ✅ Sections                     | 🔄 Infection Detection       |
| ✅ String & Symbol Tables       | 🔄 Obfuscation               |
| 🔄 Program Headers             |                              |
| 🔄 Segments                    |                              |
| 🔄 Relocations & Linking       |                              |
| 🧠 Obfuscated / Headerless ELF |                              |

## 🧠 Obfuscated / Headerless Binaries (planned)
**The forge won’t cool down just because structure is missing.** 😎

AnvilELF will evolve to handle binaries that lie or hide — stripped headers, renamed sections, corrupted tables. The goal is to analyze and mutate based on **real layout and memory flags**, not names or conventions.

> No `.text`? Corrupt headers? Misleading offsets? Let’s dance. 🔥

---

## ⚡ Usage

```sh
# Show executable header
anvil> header

# List all sections
anvil> sections
anvil> sections --full

# Show a specific section by name
anvil> section --name .shstrtab
anvil> section --name .shstrtab --full

# Disassemble .text section
anvil> text
anvil> text --offset 0 --size 10
# Disassemble .plt section
anvil> plt
# Disassemble .init section
anvil> init
# Disassemble .fini section
anvil> fini

# Show .symtab symbol table
anvil> symtab
# Show .dynsym symbol table
anvil> dynsym

# Exit the shell
anvil> exit
```

---

## 🏗 Development

### 🐍 Installation 
```sh
git clone https://github.com/dasuos/AnvilELF.git
cd AnvilELF
make install
```

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
