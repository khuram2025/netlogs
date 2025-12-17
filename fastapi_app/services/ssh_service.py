"""
SSH Service for connecting to network devices and executing commands.
"""

import asyncio
import logging
import re
import time
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    SSHException,
    NoValidConnectionsError
)

logger = logging.getLogger(__name__)


@dataclass
class SSHResult:
    """Result of SSH command execution."""
    success: bool
    output: str
    error: Optional[str] = None
    duration_ms: int = 0


class SSHService:
    """SSH service for network device management."""

    # Timeout settings
    CONNECT_TIMEOUT = 10  # seconds
    COMMAND_TIMEOUT = 60  # seconds
    BANNER_TIMEOUT = 5
    PROMPT_TIMEOUT = 60  # seconds

    # Common paging prompts used by network devices
    _PAGING_PATTERNS = [
        re.compile(r"--\s*more\s*--", re.IGNORECASE),
        re.compile(r"press\s+any\s+key\s+to\s+continue", re.IGNORECASE),
    ]

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Remove ANSI escape sequences from output."""
        # https://stackoverflow.com/a/14693789
        return re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)

    @classmethod
    def connect_and_execute(
        cls,
        host: str,
        username: str,
        password: str,
        command: str,
        port: int = 22
    ) -> SSHResult:
        """
        Connect to device and execute command.
        Returns SSHResult with output or error.
        """
        start_time = time.time()
        client = None

        # Ensure proper types
        host = str(host) if host else ""
        port = int(port) if port else 22
        username = str(username) if username else ""
        password = str(password) if password else ""

        if not host:
            return SSHResult(
                success=False,
                output="",
                error="Host address is required",
                duration_ms=0
            )

        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logger.info(f"Connecting to {host}:{port} as {username}")

            # Connect
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=cls.CONNECT_TIMEOUT,
                banner_timeout=cls.BANNER_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )

            logger.info(f"Connected to {host}, executing command: {command[:50]}...")

            # Execute command
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=cls.COMMAND_TIMEOUT
            )

            # Read output
            output = stdout.read().decode('utf-8', errors='replace')
            error_output = stderr.read().decode('utf-8', errors='replace')

            duration_ms = int((time.time() - start_time) * 1000)

            if error_output and not output:
                return SSHResult(
                    success=False,
                    output="",
                    error=error_output,
                    duration_ms=duration_ms
                )

            return SSHResult(
                success=True,
                output=output,
                error=error_output if error_output else None,
                duration_ms=duration_ms
            )

        except AuthenticationException as e:
            logger.error(f"Authentication failed for {host}: {e}")
            return SSHResult(
                success=False,
                output="",
                error=f"Authentication failed: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
        except NoValidConnectionsError as e:
            logger.error(f"Connection refused for {host}: {e}")
            return SSHResult(
                success=False,
                output="",
                error=f"Connection refused: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
        except SSHException as e:
            logger.error(f"SSH error for {host}: {e}")
            return SSHResult(
                success=False,
                output="",
                error=f"SSH error: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
        except Exception as e:
            logger.error(f"Error connecting to {host}: {type(e).__name__}: {e}")
            return SSHResult(
                success=False,
                output="",
                error=f"{type(e).__name__}: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass

    @classmethod
    def connect_interactive(
        cls,
        host: str,
        username: str,
        password: str,
        commands: List[str],
        port: int = 22,
        prompt_pattern: str = r'[#$>]\s*$'
    ) -> SSHResult:
        """
        Connect to device using interactive shell (for Fortinet and similar).
        Sends commands one by one and waits for prompt.
        """
        start_time = time.time()
        client = None
        channel = None
        prompt_regex = re.compile(prompt_pattern)

        # Ensure proper types
        host = str(host) if host else ""
        port = int(port) if port else 22
        username = str(username) if username else ""
        password = str(password) if password else ""

        if not host:
            return SSHResult(
                success=False,
                output="",
                error="Host address is required",
                duration_ms=0
            )

        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logger.info(f"Connecting interactively to {host}:{port} as {username}")

            # Connect with password authentication only
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=cls.CONNECT_TIMEOUT,
                banner_timeout=cls.BANNER_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
                disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']},
            )

            # Get interactive shell
            channel = client.invoke_shell(width=200, height=1000)
            channel.settimeout(cls.COMMAND_TIMEOUT)

            # Wait for initial prompt
            time.sleep(0.75)
            initial_output, prompt_found = cls._wait_for_prompt(
                channel,
                prompt_regex=prompt_regex,
                timeout=cls.PROMPT_TIMEOUT,
            )
            if not prompt_found:
                # Try to coax a prompt if we landed mid-banner/output
                channel.send("\n")
                time.sleep(0.25)
                initial_output, prompt_found = cls._wait_for_prompt(
                    channel,
                    prompt_regex=prompt_regex,
                    timeout=cls.PROMPT_TIMEOUT,
                )
            if not prompt_found:
                duration_ms = int((time.time() - start_time) * 1000)
                return SSHResult(
                    success=False,
                    output=initial_output,
                    error="Timed out waiting for device prompt after connect",
                    duration_ms=duration_ms,
                )

            all_output = []

            for cmd in commands:
                logger.debug(f"Executing: {cmd}")
                # Send command
                channel.send(cmd + '\n')
                time.sleep(0.5)

                # Read output until prompt
                output, prompt_found = cls._wait_for_prompt(
                    channel,
                    prompt_regex=prompt_regex,
                    timeout=cls.PROMPT_TIMEOUT,
                )
                all_output.append(output)

                if not prompt_found:
                    duration_ms = int((time.time() - start_time) * 1000)
                    return SSHResult(
                        success=False,
                        output="\n".join(all_output),
                        error=f"Timed out waiting for prompt after command: {cmd}",
                        duration_ms=duration_ms,
                    )

            duration_ms = int((time.time() - start_time) * 1000)

            return SSHResult(
                success=True,
                output='\n'.join(all_output),
                duration_ms=duration_ms
            )

        except Exception as e:
            logger.error(f"Interactive SSH error for {host}: {type(e).__name__}: {e}")
            return SSHResult(
                success=False,
                output="",
                error=f"{type(e).__name__}: {str(e)}",
                duration_ms=int((time.time() - start_time) * 1000)
            )
        finally:
            if channel:
                try:
                    channel.close()
                except Exception:
                    pass
            if client and hasattr(client, '_transport') and client._transport:
                try:
                    client._transport.close()
                except Exception:
                    pass

    @classmethod
    def _wait_for_prompt(
        cls,
        channel,
        prompt_regex: re.Pattern,
        timeout: int,
    ) -> Tuple[str, bool]:
        """Wait for shell prompt and return (output, prompt_found)."""
        output = ""
        start = time.time()

        while time.time() - start < timeout:
            if channel.recv_ready():
                chunk = channel.recv(65535).decode('utf-8', errors='replace')
                output += chunk

                tail = cls._strip_ansi(output[-1000:]).replace("\x08", "")

                # Handle paging prompts (e.g., FortiGate: --More--)
                if any(pattern.search(tail) for pattern in cls._PAGING_PATTERNS):
                    for pattern in cls._PAGING_PATTERNS:
                        output = pattern.sub("", output)
                    try:
                        channel.send(" ")
                    except Exception:
                        pass
                    time.sleep(0.05)
                    continue

                # Check if prompt reached (match against cleaned tail)
                if prompt_regex.search(tail):
                    return output, True
            else:
                time.sleep(0.1)

        return output, False

    @classmethod
    def get_fortinet_routing_table(
        cls,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        vdom: Optional[str] = None
    ) -> SSHResult:
        """
        Get routing table from Fortinet device.
        Uses the 'get router info routing-table all' command.
        If vdom is specified, enters that VDOM context first.

        VDOM command sequence:
        1. config vdom
        2. edit <vdom_name>
        3. get router info routing-table all
        4. end
        """
        commands = []

        if vdom:
            vdom_clean = str(vdom).strip()
            if not vdom_clean or any(ch in vdom_clean for ch in ("\r", "\n")):
                return SSHResult(
                    success=False,
                    output="",
                    error="Invalid VDOM name",
                    duration_ms=0,
                )

            vdom_arg = vdom_clean.replace('"', '\\"')
            edit_cmd = f'edit "{vdom_arg}"' if re.search(r"\s", vdom_arg) else f"edit {vdom_arg}"
            # Enter VDOM configuration and then the specific VDOM
            commands.append("config vdom")
            commands.append(edit_cmd)

        # Get routing table
        commands.append("get router info routing-table all")

        if vdom:
            # Exit VDOM context
            commands.append("end")

        # Log the commands being executed
        logger.info(f"Fortinet VDOM commands for {host} (VDOM: {vdom or 'global'}): {' -> '.join(commands)}")

        return cls.connect_interactive(
            host=host,
            username=username,
            password=password,
            commands=commands,
            port=port,
            prompt_pattern=r'[#$>]\s*$'
        )

    @classmethod
    def get_fortinet_vdom_list(
        cls,
        host: str,
        username: str,
        password: str,
        port: int = 22
    ) -> SSHResult:
        """
        Get list of VDOMs from Fortinet device.
        Uses 'config vdom' then 'edit ?' to see available VDOMs.
        """
        commands = [
            "config vdom",
            "edit ?",
            "end"
        ]
        return cls.connect_interactive(
            host=host,
            username=username,
            password=password,
            commands=commands,
            port=port,
            prompt_pattern=r'[#$>]\s*$'
        )

    @classmethod
    def test_connection(
        cls,
        host: str,
        username: str,
        password: str,
        port: int = 22
    ) -> SSHResult:
        """Test SSH connection to device."""
        return cls.connect_interactive(
            host=host,
            username=username,
            password=password,
            commands=["get system status"],  # Fortinet status command
            port=port,
            prompt_pattern=r'[#$>]\s*$'
        )
