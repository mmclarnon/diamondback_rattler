# Compiler settings - Can be customized.
DEBUG ?= 0
PYTHON_VERSION = 3.12
PLATFORM = $(shell uname -p)
CODE_NAME = $(shell . /etc/os-release && echo $VERSION_CODENAME)
ARCHITECTURE = $(shell dpkg --print-architecture)
LOCAL_IP = $(shell hostname -I | awk '{print $$1}')
PYINSTALLER = pyinstaller
ifeq ($(PLATFORM),x86_64)
  ARCHITECTURE = elf64-x86-64   
endif
PYTHON = /usr/bin/python3
ifeq ($(PLATFORM),aarch64)
  ARCHITECTURE = elf64-littleaarch64
endif
VIRTUAL_ENV = virtualenv
PYTHON := ./$(VIRTUAL_ENV)/bin/python3
PIP := ./$(VIRTUAL_ENV)/bin/pip3
VENV := python$(PYTHON_VERSION) -m venv
UPX = /bin/upx
# Use bash as a shell command (bash or dash is required,
# ﻿we need arithmetic in the shell)
SHELL = /bin/bash

# Makefile settings - Can be customized.c
APPNAME = diamondback
CONFIGURATION_FILE = configuration.json
CONFIGURATION_SAMPLE = $(CONFIGURATION_FILE).sample
SRCDIR = src

# UNIX-based OS variables & settings
RM = /bin/rm

all: 
	@echo "built"

develop: 
	DEBIAN_FRONTEND=noninteractive sudo apt-get update
	DEBIAN_FRONTEND=noninteractive sudo apt-get install -y $(REQUIRED_PACKAGES)
	$(VENV) $(VIRTUAL_ENV)
	@$(PIP) install -r requirements.txt

# Builds the app
$(APPNAME): $(OBJ) 
	@$(CP) $(CONFIGURATION_SAMPLE) $(CONFIGURATION_FILE)
	@echo "building final..."
    # https://stackoverflow.com/questions/32059611/adding-text-files-to-binaries-with-objcopy-but-objcopy-complains-about-architec
	@objcopy --input binary --output $(ARCHITECTURE) ./configuration.json.sample ./obj/configuration.json.o
	@$(call buildver)
	@$(PYTHON) ./increment_version.py
	@$(CC) $(CXXFLAGS) -o $@ $^ ./obj/configuration.json.o $(LIBPCAP) $(LIBNET) $(LIBSSH) $(LIB_JANSSON) $(LDFLAGS)
	@-$(RM) $(BINARY) 2> /dev/null
	@-$(UPX) -9 -o$(BINARY) $(APPNAME)
	@-$(RM) *.d

################### Cleaning rules for Unix-based OS ###################
# Cleans complete project
.PHONY: clean
clean:
	@$(RM) -f 2>/dev/null dist
# Cleans only all files with the extension .d
.PHONY: cleandep
cleandep:
	$(RM) $(DEP)

#################### Cleaning rules for Windows OS #####################
# Cleans complete project
.PHONY: cleanw
cleanw:
	$(DEL) $(WDELOBJ) $(DEP) $(APPNAME)$(EXE)

# Cleans only all files with the extension .d
.PHONY: cleandepw
cleandepw:
	$(DEL) $(DEP)
