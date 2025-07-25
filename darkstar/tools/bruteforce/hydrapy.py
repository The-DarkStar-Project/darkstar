# core/bruteforce/hydrapy.py


import asyncio
import re
import logging
import json
import time
from datetime import datetime
from typing import Optional, Dict, List, Union
from dataclasses import dataclass
from pathlib import Path
import argparse

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    target: str
    protocol: str
    credentials: List[Dict[str, str]]
    start_time: float
    end_time: float
    status: str
    port: Optional[str] = None
    error: Optional[str] = None


class HydraConfig:
    DEFAULT_WORDLISTS_DIR = Path("darkstar/tools/bruteforce/wordlists")

    def __init__(self):
        self.DEFAULT_WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)

    def get_default_wordlist_path(self, protocol: str, type_: str) -> Path:
        return self.DEFAULT_WORDLISTS_DIR / f"{protocol}_{type_}.txt"

    @staticmethod
    def create_custom_wordlist(words: List[str], output_path: Path):
        with open(output_path, "w") as f:
            f.write("\n".join(words))


class HydraAttack:
    def __init__(self, output_dir: str = "results"):
        self.config = HydraConfig()
        self.results_dir = Path(output_dir)
        self.results_dir.mkdir(exist_ok=True)

    def validate_ip(self, ip: str) -> bool:
        ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        ipv6_pattern = re.compile(r"^[0-9a-fA-F:]+$")

        if ipv4_pattern.match(ip):
            parts = ip.split(".")
            return all(0 <= int(part) <= 255 for part in parts)
        elif ipv6_pattern.match(ip):
            return True
        return False

    def validate_hostname(self, hostname: str) -> bool:
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile(r"^(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(part) for part in hostname.split("."))

    def validate_target(
        self, ip: Optional[str], hostname: Optional[str]
    ) -> Optional[str]:
        if ip:
            if not self.validate_ip(ip):
                logger.error("Invalid IP address provided.")
                return None
            return ip

        if hostname:
            if not self.validate_hostname(hostname):
                logger.error("Invalid hostname provided.")
                return None
            return hostname

        logger.error("Either 'ip' or 'hostname' must be provided.")
        return None

    async def process_hydra_output(
        self,
        stream: asyncio.StreamReader,
        is_error: bool,
        process: asyncio.subprocess.Process,
        results: List[Dict[str, str]],
    ) -> bool:
        while True:
            line = await stream.readline()
            if not line:
                break

            line = line.decode().strip()
            if not line:
                continue

            if is_error:
                logger.warning(line)

            else:
                if "[" in line and "]" in line and "host:" in line:
                    logger.info(f"Found valid credentials: {line}")
                    creds = self._parse_credentials(line)
                    if creds:
                        results.append(creds)
                    # Stop on first success if configured
                    if self.stop_on_success:
                        try:
                            # Terminate the process - works for both real processes and mocks
                            process.terminate()
                            return True
                        except Exception as e:
                            logger.error(f"Error terminating process: {e}")
                            return True
                else:
                    logger.info(line)
        return False

    def _parse_credentials(self, line: str) -> Optional[Dict[str, Union[str, int]]]:
        try:
            # Check for SNMP credentials:
            # Example format: [161][snmp] host: 127.0.0.1 password: public
            if "[snmp]" in line:
                parts = re.search(
                    r"\[(\d+)\]\[\S+\] host: .*?\s+password: (.*?)(?:\s|$)", line
                )
                if parts:
                    return {
                        "port": parts.group(1),
                        "password": parts.group(2),
                        "timestamp": datetime.now().isoformat(),
                    }

            else:
                # Example format: [21][ftp] host: 127.0.0.1   login: admin   password: 123456
                parts = re.search(
                    r"\[(\d+)\]\[\S+\]\s+host:\s+.*?\s+login:\s+(.*?)\s+password:\s+(.*?)(?:\s|$)",
                    line,
                )
                if parts:
                    return {
                        "port": parts.group(1),
                        "username": parts.group(2),
                        "password": parts.group(3),
                        "timestamp": datetime.now().isoformat(),
                    }
        except Exception as e:
            logger.error(f"Error parsing credentials: {e}")
        return None

    def save_results(self, result: AttackResult):
        output_file = (
            self.results_dir
            / f"attack_{result.protocol}_{result.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        data = {
            "target": result.target,
            "protocol": result.protocol,
            "port": result.port,
            "credentials": result.credentials,
            "duration": result.end_time - result.start_time,
            "status": result.status,
            "error": result.error,
            "timestamp": datetime.now().isoformat(),
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Results saved to {output_file}")

    async def run_attack(
        self,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        protocol: Optional[str] = None,
        login_file: Optional[str] = None,
        password_file: Optional[str] = None,
        tasks: int = 16,
        port: Optional[int] = None,
        stop_on_success: bool = True,
        timeout: int = 3600,
    ) -> AttackResult:
        self.stop_on_success = stop_on_success
        start_time = time.time()

        validated_target = self.validate_target(ip, hostname)
        if not validated_target:
            return AttackResult(
                target=ip or hostname or "unknown",
                protocol=protocol or "unknown",
                credentials=[],
                start_time=start_time,
                end_time=time.time(),
                status="failed",
                error="Invalid target",
            )

        process = None
        try:
            command = self._build_command(
                validated_target,
                protocol,
                login_file,
                password_file,
                tasks,
                port,
                stop_on_success,
            )

            logger.info(
                f"Starting Hydra attack against {validated_target} on {protocol}"
            )

            # Run attack
            found_credentials = []
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout_result, stderr_result = await asyncio.wait_for(
                    asyncio.gather(
                        self.process_hydra_output(
                            process.stdout, False, process, found_credentials
                        ),
                        self.process_hydra_output(
                            process.stderr, True, process, found_credentials
                        ),
                    ),
                    timeout=timeout,
                )

                # Wait for process to terminate
                try:
                    await asyncio.wait_for(process.wait(), timeout=10)
                except asyncio.TimeoutError:
                    if process and process.returncode is None:
                        process.kill()
                        try:
                            await asyncio.wait_for(process.wait(), timeout=10)
                        except asyncio.TimeoutError:
                            pass
                    logger.warning("Force killed Hydra process")

                status = "success" if found_credentials else "completed"
                error = None

            except asyncio.TimeoutError:
                status = "timeout"
                error = f"Attack timed out after {timeout} seconds"
                if process and process.returncode is None:
                    logger.info("Attempting to terminate Hydra process...")
                    # Try SIGTERM to kill process
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=5.0)

            extracted_port = (
                found_credentials[0].pop("port", None) if found_credentials else None
            )
            final_port = str(port) if port is not None else extracted_port

            result = AttackResult(
                target=validated_target,
                protocol=protocol,
                port=final_port,
                credentials=found_credentials,
                start_time=start_time,
                end_time=time.time(),
                status=status,
                error=error,
            )

            self.save_results(result)
            return result

        except FileNotFoundError:
            error = "Hydra is not installed or not found in PATH"
            logger.error(error)
            return AttackResult(
                target=validated_target,
                protocol=protocol,
                credentials=[],
                start_time=start_time,
                end_time=time.time(),
                status="failed",
                error=error,
            )
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
            logger.error(error)
            return AttackResult(
                target=validated_target,
                protocol=protocol,
                credentials=[],
                start_time=start_time,
                end_time=time.time(),
                status="failed",
                error=error,
            )
        finally:
            # Ensure process is cleaned up if it exists and is still running
            if process and process.returncode is None:
                process.kill()
                try:
                    await asyncio.wait_for(process.wait(), timeout=1.0)
                except (asyncio.TimeoutError, Exception):
                    pass

    def _build_command(
        self, target, protocol, login_file, password_file, tasks, port, stop_on_success
    ):
        login_file = login_file or self.config.get_default_wordlist_path(
            protocol, "logins"
        )
        password_file = password_file or self.config.get_default_wordlist_path(
            protocol, "passwords"
        )

        command = ["hydra", "-P", str(password_file), "-t", str(tasks), "-q", "-I"]
        # "-o", str(self.results_dir / f"hydra_{protocol}_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"),

        if protocol not in ["snmp"]:
            command.extend(["-L", str(login_file)])

        if stop_on_success:
            command.append("-f")

        if port:
            command.extend(["-s", str(port)])

        command.append(f"{protocol}://{target}")
        return command


def setup_argparse():
    parser = argparse.ArgumentParser(description="Advanced Hydra Attack Framework")
    parser.add_argument("--ip", help="Target IP address")
    parser.add_argument("--hostname", help="Target hostname")
    parser.add_argument(
        "--protocol",
        required=True,
        help="Protocol to attack (e.g., ssh, ftp, postgres)",
    )
    parser.add_argument("-L", "--login_file", help="Path to login wordlist")
    parser.add_argument("-P", "--password_file", help="Path to password wordlist")
    parser.add_argument("-p", "--port", type=int, help="Target port")
    parser.add_argument(
        "-t", "--tasks", type=int, default=16, help="Number of parallel tasks"
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="Attack timeout in seconds"
    )
    parser.add_argument(
        "--continue-on-success",
        action="store_true",
        help="Continue after finding credentials",
    )
    return parser


async def main():
    try:
        parser = setup_argparse()
        args = parser.parse_args()

        attack = HydraAttack()
        result = await attack.run_attack(
            ip=args.ip,
            hostname=args.hostname,
            protocol=args.protocol,
            login_file=args.login_file,
            password_file=args.password_file,
            tasks=args.tasks,
            port=args.port,
            stop_on_success=not args.continue_on_success,
            timeout=args.timeout,
        )

        logger.info("[*] Attack Summary:")
        logger.info(f"[*] Target: {result.target}")
        logger.info(f"[*] Protocol: {result.protocol}")
        logger.info(f"[*] Status: {result.status}")
        logger.info(f"[*] Credentials found: {len(result.credentials)}")
        logger.info(f"[*] Duration: {result.end_time - result.start_time:.2f} seconds")
        if result.error:
            logger.error(f"Error: {result.error}")

    except asyncio.TimeoutError:
        logger.error("Attack timed out.")
    except Exception as e:
        logger.error(f"Fatal error: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user")
