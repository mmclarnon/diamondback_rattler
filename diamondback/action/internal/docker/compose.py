import logging
import time
import docker
import subprocess
import os
import yaml
import re

from diamondback.action import call_before_decorator,Action

class DockerComposeBot:
    def __init__(self, compose_file, env_file=".env"):
        self.logger = logging.getLogger( 'composebot' )

        if not os.path.exists(compose_file):
            raise FileNotFoundError(f"Compose file not found: {compose_file}")
        self.compose_file = compose_file
        self.client = docker.from_env()

        # Load environment variables from .env file if present
        if os.path.exists(env_file):
            self._load_env_file(env_file)

        with open(compose_file, 'r') as f:
            raw_content = f.read()

        # Perform environment variable substitution like ${VAR}
        substituted_content = self._substitute_env_vars(raw_content)

        # Parse YAML after substitution
        self.compose_config = yaml.safe_load(substituted_content)

    def _load_env_file(self, env_file):
        """Load variables from a .env file into os.environ"""
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    os.environ.setdefault(key.strip(), val.strip())

    def _substitute_env_vars(self, content: str) -> str:
        """
        Replace ${VAR} with environment variable values.
        Supports default syntax ${VAR:-default}.
        """
        pattern = re.compile(r"\$\{([^}:\s]+)(?::-([^}]+))?\}")

        def replacer(match):
            var_name = match.group(1)
            default_val = match.group(2)
            return os.environ.get(var_name, default_val if default_val else "")

        return pattern.sub(replacer, content)

    def _wait_for_health(self, container, timeout=60):
        """Wait until container healthcheck passes or timeout expires"""
        start = time.time()
        while time.time() - start < timeout:
            container.reload()
            health = container.attrs.get("State", {}).get("Health", {}).get("Status")
            if health == "healthy":
                self.logger.info(f"Container {container.name} is healthy.")
                return True
            elif health == "unhealthy":
                self.logger.info(f"Container {container.name} reported unhealthy.")
                return False
            time.sleep(2)
        self.logger.info(f"Timeout waiting for {container.name} to become healthy.")
        return False

    def _stream_logs(self, container, tail=20):
        """Stream logs from a container during startup"""
        self.logger.info(f"--- Logs for {container.name} ---")
        for line in container.logs(stream=True, tail=tail):
            self.logger.debug(line.decode("utf-8").rstrip())
        self.logger.info(f"--- End logs for {container.name} ---")

    def up(self):
        # Create networks
        networks = self.compose_config.get("networks", {})
        for net_name, net_config in networks.items():
            try:
                self.client.networks.get(net_name)
                self.logger.info(f"Network {net_name} already exists.")
            except docker.errors.NotFound:
                self.logger.info(f"Creating network {net_name}...")
                self.client.networks.create(net_name, driver=net_config.get("driver", "bridge"))

        # Create volumes
        volumes = self.compose_config.get("volumes", {})
        for vol_name, vol_config in volumes.items():
            try:
                self.client.volumes.get(vol_name)
                self.logger.info(f"Volume {vol_name} already exists.")
            except docker.errors.NotFound:
                self.logger.info(f"Creating volume {vol_name}...")
                self.client.volumes.create(name=vol_name, driver=vol_config.get("driver", "local"))

        # Handle service dependencies
        services = self.compose_config.get("services", {})
        started = set()

        def start_service(name):
            if name in started:
                return
            config = services[name]
            depends_on = config.get("depends_on", {})

            # Handle dependencies first
            for dep, dep_opts in (depends_on.items() if isinstance(depends_on, dict) else [(d, {}) for d in depends_on]):
                if dep in services:
                    start_service(dep)
                    # If condition is service_healthy, wait for healthcheck
                    if isinstance(dep_opts, dict) and dep_opts.get("condition") == "service_healthy":
                        try:
                            dep_container = self.client.containers.get(dep)
                            self._wait_for_health(dep_container)
                        except docker.errors.NotFound:
                            self.logger.info(f"Dependency container {dep} not found.")

            image = config["image"]
            ports = config.get("ports", [])
            volumes = config.get("volumes", [])
            environment = config.get("environment", {})
            networks = config.get("networks", [])
            restart_policy = config.get("restart", None)

            # Translate restart policy
            restart_config = None
            if restart_policy:
                if restart_policy == "always":
                    restart_config = {"Name": "always"}
                elif restart_policy == "on-failure":
                    restart_config = {"Name": "on-failure", "MaximumRetryCount": 5}
                elif restart_policy == "unless-stopped":
                    restart_config = {"Name": "unless-stopped"}

            try:
                container = self.client.containers.get(name)
                if container.status != "running":
                    self.logger.info(f"Starting existing container {name}...")
                    container.start()
                else:
                    self.logger.info(f"Container {name} already running.")
            except docker.errors.NotFound:
                self.logger.info(f"Creating and starting container {name}...")
                container = self.client.containers.run(
                    image,
                    name=name,
                    detach=True,
                    tty=True,
                    stdin_open=True,
                    ports={p.split(":")[0]: p.split(":")[1] for p in ports},
                    volumes={v.split(":")[0]: {"bind": v.split(":")[1], "mode": "rw"} for v in volumes},
                    environment=environment,
                    network=networks[0] if networks else None,
                    restart_policy=restart_config,
                    healthcheck=config.get("healthcheck")  # optional healthcheck config
                )

            # Stream logs after startup
            #self._stream_logs(container)

            started.add(name)

        # Start all services respecting dependencies and healthchecks
        for service_name in services.keys():
            start_service(service_name)

    def down(self):
        # Stop and remove containers
        services = self.compose_config.get("services", {})
        for name in services.keys():
            try:
                container = self.client.containers.get(name)
                self.logger.info(f"Stopping and removing container {name}...")
                container.stop()
                container.remove()
            except docker.errors.NotFound:
                self.logger.info(f"Container {name} not found, skipping.")

        # Remove networks
        networks = self.compose_config.get("networks", {})
        for net_name in networks.keys():
            try:
                net = self.client.networks.get(net_name)
                self.logger.info(f"Removing network {net_name}...")
                net.remove()
            except docker.errors.NotFound:
                self.logger.info(f"Network {net_name} not found, skipping.")

        # Remove volumes
        volumes = self.compose_config.get("volumes", {})
        for vol_name in volumes.keys():
            try:
                vol = self.client.volumes.get(vol_name)
                self.logger.info(f"Removing volume {vol_name}...")
                vol.remove()
            except docker.errors.NotFound:
                self.logger.info(f"Volume {vol_name} not found, skipping.")

class DockerCompose(Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logger = logging.getLogger( 'dockercompose' )

        # Required compose file path
        if 'compose' not in kwargs:
            raise ValueError("Missing required 'compose' argument in kwargs")
        self.path_to_compose = kwargs['compose']

        # Track action argument
        self.action = kwargs.get('action', 'up')  # default to "up"

        # Optional .env file
        self.env_file = kwargs.get('env_file', '.env')

        # Create an instance of DockerComposeLike
        self.compose_like = DockerComposeBot(self.path_to_compose, env_file=self.env_file)

    @call_before_decorator
    def run(self):
        if self.action == "up":
            self.logger.info("Bringing services up...")
            self.compose_like.up()
        elif self.action == "down":
            self.logger.info("Bringing services down...")
            self.compose_like.down()
        else:
            raise ValueError(f"Unsupported action: {self.action}")