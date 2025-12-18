# Compiler settings - Can be customized.
DEBUG ?= 0
PYTHON_VERSION = 3.11
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
REQUIRED_PACKAGES =  python3-ansible-runner \
			libportaudio2 \
			portaudio19-dev \
			socat \
			gcc-mingw-w64-x86-64-win32
# UNIX-based OS variables & settings
RM = /bin/rm
PYTHON = /home/parallels/workspace/.pyenv/shims/python3
VENV = /home/parallels/workspace/.pyenv/shims/python3 -m venv
METASPLOIT_IMAGE_NAME = diamondback_metasploit
TAG = latest
VERSION_FILE := ./VERSION.txt
VERSION := $(shell cat ${VERSION_FILE})
ARCHITECTURE = $(shell dpkg --print-architecture)


all: 
	-@./increment_version.sh
	-@update-toml update --path project.version --value `cat VERSION.txt` --file pyproject.toml
	@echo "built"
	@hatch build

develop: 
	DEBIAN_FRONTEND=noninteractive sudo apt-get update
	DEBIAN_FRONTEND=noninteractive sudo apt-get install -y $(REQUIRED_PACKAGES)
	$(VENV) $(VIRTUAL_ENV)
	@$(PIP) install -r requirements.txt
	$(MAKE) -C ansible develop
	mkdir data 2> /dev/null && cd data && python -m piper.download_voices en_US-amy-medium
	curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
	sudo sh /tmp/get-docker.sh 
	@$(PIP) install hatch==1.16.2
	@$(PIP) install update_toml==0.2.1

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

.PHONY: metasploit
metasploit:
	docker buildx build -t $(METASPLOIT_IMAGE_NAME):$(VERSION) --build-arg ARCHITECTURE=$(ARCHITECTURE) \
	-f application/metasploit/Dockerfile ./application/metasploit

.PHONY: test
test:
	@python -m unittest discover test/

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
