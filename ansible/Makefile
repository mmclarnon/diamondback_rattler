1PASSWORD_CLI = /usr/bin/op
BECOME_PASSWORD = .become_password
VAULT_PASSWORD = .vault_password
INVENTORY = inventory/cyberguardian/homenet
REQUIRED_PACKAGES = build-essential \
					libssl-dev \
					zlib1g-dev \
					libbz2-dev \
					libreadline-dev \
					libsqlite3-dev \
					curl \
					git \
					libncursesw5-dev \
					xz-utils \
					tk-dev \
					libxml2-dev \
					libxmlsec1-dev \
					libffi-dev \
					sshpass \
					liblzma-dev

.PHONY: .become-password .vault_password develop

# Create .become_password file if it doesn't exist (POSIX-compatible)
.become_password:
	@if [ ! -f $(BECOME_PASSWORD) ]; then \
		echo "Creating $(BECOME_PASSWORD) file..."; \
		printf "Enter become password: "; \
		stty -echo; \
		read password; \
		stty echo; \
		echo; \
		echo "$$password" > $(BECOME_PASSWORD); \
		chmod 600 $(BECOME_PASSWORD); \
		echo "✓ $(BECOME_PASSWORD) file created with restricted permissions (600)"; \
	else \
		echo "✓ $(BECOME_PASSWORD) file already exists"; \
	fi

.vault_password:
	@if [ ! -f $(VAULT_PASSWORD) ]; then \
		echo "Creating $(VAULT_PASSWORD) file..."; \
		printf "Enter vault password: "; \
		stty -echo; \
		read password; \
		stty echo; \
		echo; \
		echo "$$password" > $(VAULT_PASSWORD); \
		chmod 600 $(VAULT_PASSWORD); \
		echo "✓ $(VAULT_PASSWORD) file created with restricted permissions (600)"; \
	else \
		echo "✓ $(VAULT_PASSWORD) file already exists"; \
	fi

develop: .become_password .vault_password
	sudo apt install -y $(REQUIRED_PACKAGES)
	ansible-galaxy install -r requirements.yml

vault:
	ansible-vault create --vault-id diamondback@prompt vault.yml

pwncat:
	ansible-playbook -i $(INVENTORY) --vault-password-file .vault_password --become-password-file .become_password install_pwncat.yml --extra-vars '{ "user":"sysadmin" }'
