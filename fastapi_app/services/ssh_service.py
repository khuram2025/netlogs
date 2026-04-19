"""
SSH Service for connecting to network devices and executing commands.
"""

import asyncio
import logging
import re
import socket
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
        prompt_pattern: str = r'[#$>]\s*$',
        prompt_timeout: Optional[int] = None,
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

            # Get interactive shell. If the account has no shell privilege
            # (e.g. PAN-OS users without the `superreader`/`superuser` role,
            # or SCP/SFTP-only accounts), the channel is allocated but the
            # remote closes it almost immediately. Detect that distinctly so
            # we can return an actionable error rather than a generic OSError.
            try:
                channel = client.invoke_shell(width=200, height=1000)
                channel.settimeout(cls.COMMAND_TIMEOUT)
            except (OSError, paramiko.ChannelException, EOFError) as e:
                duration_ms = int((time.time() - start_time) * 1000)
                return SSHResult(
                    success=False,
                    output="",
                    error=(
                        "Authenticated but device refused to open an SSH shell — "
                        "the account likely has no CLI shell privilege. "
                        f"({type(e).__name__}: {e})"
                    ),
                    duration_ms=duration_ms,
                )

            # Wait for initial prompt
            effective_prompt_timeout = prompt_timeout if prompt_timeout is not None else cls.PROMPT_TIMEOUT
            time.sleep(0.75)
            initial_output, prompt_found = cls._wait_for_prompt(
                channel,
                prompt_regex=prompt_regex,
                timeout=effective_prompt_timeout,
            )
            if not prompt_found:
                # Try to coax a prompt if we landed mid-banner/output. If the
                # channel was closed by the remote (no shell access), this
                # send raises OSError; treat that as terminal and fall through
                # to the no-prompt error reporter below.
                try:
                    channel.send("\n")
                    time.sleep(0.25)
                    initial_output, prompt_found = cls._wait_for_prompt(
                        channel,
                        prompt_regex=prompt_regex,
                        timeout=effective_prompt_timeout,
                    )
                except OSError:
                    pass  # prompt_found stays False; handled by branch below
            if not prompt_found:
                duration_ms = int((time.time() - start_time) * 1000)
                # If the remote already closed the channel, the user
                # authenticated but lacks CLI shell privilege — common on
                # PAN-OS / Cisco accounts limited to SCP/SFTP/EDL-serving.
                try:
                    channel_closed = bool(getattr(channel, 'closed', False)) or channel.eof_received
                except Exception:
                    channel_closed = False

                hint = (initial_output or "").strip().replace("\r", "").replace("\n", " ")
                if len(hint) > 200:
                    hint = hint[:200] + "…"

                if channel_closed:
                    error_msg = (
                        "Authenticated but device closed the SSH channel without a CLI prompt — "
                        "the account likely has no shell access. Use a role that grants "
                        "operational CLI (e.g. PAN-OS 'superreader')."
                    )
                else:
                    error_msg = "Timed out waiting for device CLI prompt"
                    if hint:
                        error_msg += f" — device sent: '{hint}'"
                    else:
                        error_msg += " (no banner). Account may be restricted (e.g. EDL/SCP-only)."
                return SSHResult(
                    success=False,
                    output=initial_output,
                    error=error_msg,
                    duration_ms=duration_ms,
                )

            all_output = []

            for idx, cmd in enumerate(commands):
                is_last = (idx == len(commands) - 1)
                logger.debug(f"Executing: {cmd}")
                try:
                    channel.send(cmd + '\n')
                except OSError as e:
                    # Some devices (e.g. PAN-OS on a closing op-mode session)
                    # may close the socket between commands. If we already
                    # collected output for the previous command(s), treat as
                    # success rather than discarding the work.
                    if all_output:
                        logger.warning(f"Channel closed before command '{cmd}': {e}")
                        break
                    raise

                time.sleep(0.5)

                output, prompt_found = cls._wait_for_prompt(
                    channel,
                    prompt_regex=prompt_regex,
                    timeout=effective_prompt_timeout,
                )
                all_output.append(output)

                if not prompt_found:
                    # If this was the last command and the device hung up
                    # (output ended without the prompt), accept what we got —
                    # we sent the show command, the data is in `output`.
                    if is_last and output:
                        break
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
        """Wait for shell prompt and return (output, prompt_found).

        If the remote side closes the channel before a prompt arrives — common
        for accounts that authenticate but lack CLI shell privilege (e.g.
        PAN-OS EDL/SCP-only users) — return what we read so far instead of
        letting paramiko's `OSError: Socket is closed` bubble up. The caller
        can then surface a clear "no shell access" message.
        """
        output = ""
        start = time.time()

        while time.time() - start < timeout:
            # If the remote closed the channel and there's nothing left to
            # read, bail out early so we don't spin until the timeout fires.
            try:
                channel_closed = bool(getattr(channel, 'closed', False)) or channel.eof_received
            except Exception:
                channel_closed = False
            try:
                ready = channel.recv_ready()
            except OSError:
                return output, False
            if channel_closed and not ready:
                return output, False

            if ready:
                try:
                    chunk = channel.recv(65535).decode('utf-8', errors='replace')
                except OSError:
                    return output, False
                if not chunk:
                    return output, False
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
            prompt_pattern=r'[#$>]\s*$',
            prompt_timeout=15,
        )

    @classmethod
    def get_paloalto_routing_table(
        cls,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        virtual_router: Optional[str] = None,
    ) -> SSHResult:
        """
        Get routing table from Palo Alto Networks (PAN-OS) device.

        Per the PAN-OS CLI Quick Start (operational mode commands):
          - `set cli pager off`           — disable paging so we get one shot
          - `set cli scripting-mode on`   — strip ANSI / minimise prompt noise
          - `show routing route`          — render the active routing table
            (use `show routing route virtual-router <name>` for a specific VR)

        The default PAN-OS prompt after login is `username@hostname>` for
        operational mode (`#` after entering configure). We exit via `exit`.
        """
        # Operational-mode commands. We deliberately do NOT append `exit` —
        # PAN-OS closes the SSH session on `exit`, and the subsequent prompt
        # read in connect_interactive's loop would then raise
        # "OSError: Socket is closed". The finally-block in
        # connect_interactive closes the channel cleanly.
        commands = [
            "set cli pager off",
            "set cli scripting-mode on",
        ]
        if virtual_router:
            vr_clean = str(virtual_router).strip()
            if not vr_clean or any(ch in vr_clean for ch in ("\r", "\n", " ")):
                return SSHResult(
                    success=False, output="",
                    error="Invalid virtual-router name", duration_ms=0,
                )
            commands.append(f"show routing route virtual-router {vr_clean}")
        else:
            commands.append("show routing route")

        logger.info(
            f"PAN-OS routing commands for {host} (VR: {virtual_router or 'all'}): "
            f"{' -> '.join(commands)}"
        )
        return cls.connect_interactive(
            host=host,
            username=username,
            password=password,
            commands=commands,
            port=port,
            # PAN-OS default prompts: 'admin@PA-VM>' (op) or 'admin@PA-VM#' (cfg)
            prompt_pattern=r'[#>]\s*$',
            prompt_timeout=15,
        )

    @classmethod
    def get_fortinet_policies(
        cls,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        vdom: Optional[str] = None,
    ) -> SSHResult:
        """
        Fetch the FortiGate rule base + referenced objects in one session.

        Per the FortiGate CLI Reference, all five `show` commands run in
        operational/global context and emit the standard `config / edit /
        set / next / end` block format. Pulling them all in a single SSH
        session keeps the on-device load low and avoids 5x setup cost.

        For VDOM-aware boxes, we enter the VDOM first via `config vdom; edit X`
        so each `show` is scoped to that VDOM.
        """
        commands = []
        if vdom:
            v = str(vdom).strip()
            if not v or any(c in v for c in ("\r", "\n")):
                return SSHResult(success=False, output="",
                                 error="Invalid VDOM name", duration_ms=0)
            v_arg = v.replace('"', '\\"')
            edit_cmd = f'edit "{v_arg}"' if re.search(r"\s", v_arg) else f"edit {v_arg}"
            commands += ["config vdom", edit_cmd]

        # Order matters only for human readability; the parser scans the
        # whole stream regardless.
        commands += [
            "show firewall address",
            "show firewall addrgrp",
            "show firewall service custom",
            "show firewall service group",
            "show firewall policy",
        ]

        if vdom:
            commands.append("end")

        logger.info(
            f"FortiGate policy fetch for {host} (VDOM: {vdom or 'global'}): "
            f"{len(commands)} commands"
        )
        return cls.connect_interactive(
            host=host,
            username=username,
            password=password,
            commands=commands,
            port=port,
            prompt_pattern=r'[#$>]\s*$',
            prompt_timeout=15,
        )

    @classmethod
    def get_paloalto_zone_data(
        cls,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        vsys: Optional[str] = None,
    ) -> SSHResult:
        """
        Fetch zone + interface mapping from PAN-OS.

        Per the PAN-OS CLI Quick Start, `show interface all` (operational
        mode) prints two tables in one call: per-interface state, and a
        second table with `name id ip vsys zone`. That single command gives
        us everything `Fetch Zones` needs (which interfaces exist, which
        zones they're assigned to, and the IP/CIDR per interface).

        For multi-vsys boxes, the request can be scoped via
        `set system setting target-vsys <vsysN>`; otherwise the call covers
        all vsys the user can see.
        """
        commands = [
            "set cli pager off",
            "set cli scripting-mode on",
        ]
        if vsys:
            vsys_clean = str(vsys).strip()
            if vsys_clean and not any(ch in vsys_clean for ch in ("\r", "\n", " ")):
                commands.append(f"set system setting target-vsys {vsys_clean}")
        commands.append("show interface all")

        logger.info(
            f"PAN-OS zone commands for {host} (vsys: {vsys or 'all'}): "
            f"{' -> '.join(commands)}"
        )
        return cls.connect_interactive(
            host=host,
            username=username,
            password=password,
            commands=commands,
            port=port,
            prompt_pattern=r'[#>]\s*$',
            prompt_timeout=15,
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
        """Test SSH credential by performing TCP+SSH handshake and authentication only.

        The previous implementation opened a full interactive shell and ran a
        Fortinet-specific command, which timed out (~120s) on restricted users
        like SFTP-only accounts. A credential test should validate "can I log
        in?", not "can I run vendor X's CLI" — that's the fetch step's job.
        """
        start_time = time.time()

        if not host:
            return SSHResult(success=False, output="", error="Host address is required", duration_ms=0)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=cls.CONNECT_TIMEOUT,
                banner_timeout=cls.BANNER_TIMEOUT,
                auth_timeout=cls.CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )
            return SSHResult(
                success=True,
                output="Authenticated",
                error=None,
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except AuthenticationException as e:
            return SSHResult(
                success=False, output="",
                error=f"Authentication failed: {e}",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except SSHException as e:
            return SSHResult(
                success=False, output="",
                error=f"SSH protocol error: {e}",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except (socket.timeout, TimeoutError) as e:
            return SSHResult(
                success=False, output="",
                error=f"Connection timeout to {host}:{port}",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        except OSError as e:
            return SSHResult(
                success=False, output="",
                error=f"Network error reaching {host}:{port}: {e}",
                duration_ms=int((time.time() - start_time) * 1000),
            )
        finally:
            try:
                client.close()
            except Exception:
                pass
