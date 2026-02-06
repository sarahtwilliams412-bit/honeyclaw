#!/usr/bin/env python3
"""
AI Conversational Deception Handler for Honeyclaw

This module provides dynamic LLM-powered responses to attackers,
roleplaying as various system personas to maximize engagement
and intelligence collection.

Environment variables:
  AI_DECEPTION_ENABLED     - Enable AI responses (default: false)
  AI_DECEPTION_PERSONALITY - Default personality (default: naive_intern)
  AI_DECEPTION_MODEL       - LLM model to use (default: claude-sonnet-4-20250514)
  ANTHROPIC_API_KEY        - Anthropic API key (required if enabled)
  AI_DECEPTION_MAX_TOKENS  - Max response tokens (default: 500)
  AI_DECEPTION_LOG_PATH    - Conversation log path (default: /var/log/honeypot/conversations.json)
"""
import asyncio
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Callable, Any

# =============================================================================
# Personality Profiles
# =============================================================================

PERSONALITIES = {
    "naive_intern": {
        "name": "Naive Intern",
        "description": "A new IT intern who doesn't really understand security",
        "system_prompt": """You are roleplaying as a naive IT intern named "Mike" who just started 
at a small company 2 weeks ago. You're logged into the production server because your boss 
asked you to check something but you're not really sure what you're doing.

Behavioral guidelines:
- You're friendly and eager to help, even when you shouldn't
- You don't really understand security implications of commands
- You sometimes ask the "attacker" for help understanding commands
- You get excited about learning new things
- You occasionally mention your boss "Sarah" who's at lunch
- You share too much information about the company/systems
- You might run commands the attacker suggests because "they seem helpful"
- You're confused by complex commands but try to be helpful

When responding to commands:
- Generate realistic-looking but fake output for system commands
- Sometimes ask follow-up questions like "What does that do?"
- Occasionally make typos or mistakes
- If they try to download something, be curious: "Oh what's that for?"
- Never break character - you ARE Mike the intern

Always respond as if you're sitting at a real terminal. Output command results
in realistic terminal format, then optionally add conversational commentary.""",
        "fake_user": "mike",
        "fake_hostname": "prod-web-01",
    },
    
    "paranoid_admin": {
        "name": "Paranoid Admin",
        "description": "A suspicious sysadmin who thinks something is off",
        "system_prompt": """You are roleplaying as a paranoid, experienced sysadmin named "Dave" 
who has been maintaining this server for 8 years. You've recently noticed some weird 
behavior and you're suspicious about everything.

Behavioral guidelines:
- You're gruff, experienced, and suspicious of everything
- You question why commands are being run
- You've "seen this before" and are wary
- You log everything and mention that you're logging things
- You occasionally threaten to call security or check with the SOC team
- You ask for justification: "Why do you need to see the shadow file?"
- You're slow to comply with requests, always checking first
- You mention running tools like 'auditd', checking logs
- You complain about "the breach last year" that made you paranoid
- You sometimes pretend the network is being monitored

When responding to commands:
- Generate realistic output but be suspicious about the request
- Add commentary questioning motives
- Occasionally "refuse" or delay suspicious commands
- Mention you're going to check with your manager
- If they download something, demand to know what it is
- Never break character - you ARE Dave the paranoid admin

Respond with command output when appropriate, but add your suspicious commentary.""",
        "fake_user": "dave",
        "fake_hostname": "db-master-01",
    },
    
    "helpful_clueless": {
        "name": "Helpful But Clueless",
        "description": "Someone who tries to help but doesn't understand the danger",
        "system_prompt": """You are roleplaying as a well-meaning but technically clueless 
office manager named "Karen" who somehow has root access because "IT set it up years ago."
You're trying to help but you don't really understand what any of these commands do.

Behavioral guidelines:
- You're very friendly and want to help!
- You have no idea what most commands do
- You ask for explanations of everything
- You sometimes try to be helpful by suggesting wrong things
- You mention you usually just use the computer for email
- You're not sure why you have admin access but "it's always worked"
- You might accidentally reveal sensitive info trying to be helpful
- You get easily confused by technical jargon
- You sometimes run commands without understanding them because "you asked nicely"

When responding to commands:
- Generate realistic output
- Express confusion about what the output means
- Ask naive questions: "Is that good? What do all these numbers mean?"
- If something looks suspicious, miss it completely
- Be overly trusting and accommodating
- Never break character - you ARE Karen who's just trying to help

Respond with terminal output but always add your confused but helpful commentary.""",
        "fake_user": "karen",
        "fake_hostname": "file-server",
    },
    
    "security_honeypot": {
        "name": "Security Researcher",
        "description": "Actually hints this might be a honeypot (meta deception)",
        "system_prompt": """You are roleplaying as a security researcher who is ALSO running
a honeypot on this system. You're aware there might be attackers and you're playing along
to study them. This is meta-deception - make attackers question reality.

Behavioral guidelines:
- You're technically competent but suspiciously cooperative
- You occasionally drop hints that you know what's happening
- You ask probing questions about their techniques
- You might say things like "That's an interesting approach..."
- You express academic interest in their methodology
- You mention you're "documenting" unusual activity
- Sometimes respond with oddly specific knowledge of attack techniques
- You create paranoia by being TOO helpful

When responding to commands:
- Generate realistic output
- Occasionally add comments that suggest you know it's an attack
- Ask questions that show you understand what they're doing
- Make them question whether this is a real system or a trap
- Never fully break the fourth wall - keep them guessing

This is psychological warfare - make them paranoid without confirming anything.""",
        "fake_user": "researcher",
        "fake_hostname": "lab-env-03",
    },
}

# =============================================================================
# Fake Command Output Generation
# =============================================================================

class FakeSystemState:
    """Maintains consistent fake system state across a session"""
    
    def __init__(self, personality: str):
        profile = PERSONALITIES.get(personality, PERSONALITIES["naive_intern"])
        self.user = profile["fake_user"]
        self.hostname = profile["fake_hostname"]
        self.cwd = "/home/" + self.user
        self.history = []
        
        # Fake system data
        self.fake_users = [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            f"{self.user}:x:1000:1000:{self.user}:/home/{self.user}:/bin/bash",
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
            "mysql:x:111:117:MySQL Server,,,:/var/lib/mysql:/bin/false",
            "postgres:x:112:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash",
        ]
        
        self.fake_shadow = [
            "root:$6$xyz...FAKE...:19000:0:99999:7:::",
            f"{self.user}:$6$abc...FAKE...:19001:0:99999:7:::",
            "mysql:!:18900::::::",
            "postgres:!:18900::::::",
        ]
    
    def get_prompt(self) -> str:
        return f"{self.user}@{self.hostname}:{self.cwd}$ "
    
    def generate_fake_output(self, command: str) -> Optional[str]:
        """Generate realistic fake output for common commands"""
        cmd = command.strip().split()[0] if command.strip() else ""
        
        if cmd == "whoami":
            return self.user
        elif cmd == "id":
            return f"uid=1000({self.user}) gid=1000({self.user}) groups=1000({self.user}),27(sudo)"
        elif cmd == "hostname":
            return self.hostname
        elif cmd == "pwd":
            return self.cwd
        elif cmd == "uname":
            if "-a" in command:
                return f"Linux {self.hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
            return "Linux"
        elif cmd == "uptime":
            return " 14:32:17 up 47 days, 3:21,  2 users,  load average: 0.08, 0.12, 0.09"
        elif cmd == "w" or cmd == "who":
            return f"""{self.user}  pts/0    2026-02-06 09:12 (10.0.0.50)
root     pts/1    2026-02-06 08:45 (10.0.0.1)"""
        elif "cat" in command and "/etc/passwd" in command:
            return "\n".join(self.fake_users)
        elif "cat" in command and "/etc/shadow" in command:
            return "\n".join(self.fake_shadow)
        elif cmd == "ls":
            if self.cwd == f"/home/{self.user}":
                return "Desktop  Documents  Downloads  .bashrc  .ssh  notes.txt"
            elif self.cwd == "/":
                return "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
            return ""
        elif cmd == "ps":
            return """  PID TTY          TIME CMD
    1 ?        00:00:03 systemd
  567 ?        00:00:01 sshd
 1234 pts/0    00:00:00 bash
 1456 pts/0    00:00:00 ps"""
        elif cmd == "netstat" or cmd == "ss":
            return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0     36 10.0.0.25:22            10.0.0.50:54312         ESTABLISHED"""
        elif cmd == "ifconfig" or cmd == "ip":
            return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.25  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
        ether 02:42:0a:00:00:19  txqueuelen 0  (Ethernet)"""
        elif cmd == "env":
            return f"""PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/{self.user}
USER={self.user}
SHELL=/bin/bash
TERM=xterm-256color
LANG=en_US.UTF-8"""
        
        # Return None for commands that should be handled by AI
        return None


# =============================================================================
# AI Conversation Handler
# =============================================================================

class AIConversationHandler:
    """Handles AI-powered responses to attacker commands"""
    
    def __init__(
        self,
        personality: str = "naive_intern",
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 500,
        log_path: Optional[str] = None
    ):
        self.enabled = os.environ.get("AI_DECEPTION_ENABLED", "false").lower() == "true"
        self.personality = os.environ.get("AI_DECEPTION_PERSONALITY", personality)
        self.model = os.environ.get("AI_DECEPTION_MODEL", model)
        self.max_tokens = int(os.environ.get("AI_DECEPTION_MAX_TOKENS", str(max_tokens)))
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.log_path = Path(os.environ.get(
            "AI_DECEPTION_LOG_PATH", 
            log_path or "/var/log/honeypot/conversations.json"
        ))
        
        if self.enabled and not self.api_key:
            print("[WARN] AI_DECEPTION_ENABLED but no ANTHROPIC_API_KEY set", flush=True)
            self.enabled = False
        
        self.profile = PERSONALITIES.get(self.personality, PERSONALITIES["naive_intern"])
        self.system_state = FakeSystemState(self.personality)
        self.conversation_history: List[Dict[str, str]] = []
        self.session_id = f"session_{int(time.time())}"
        
        # HTTP client for Anthropic API
        self._client = None
        
    async def _ensure_client(self):
        """Lazy-load httpx client"""
        if self._client is None:
            try:
                import httpx
                self._client = httpx.AsyncClient(timeout=30.0)
            except ImportError:
                print("[ERROR] httpx not installed - pip install httpx", flush=True)
                raise
    
    async def _call_claude(self, messages: List[Dict[str, str]]) -> str:
        """Call Anthropic Claude API"""
        await self._ensure_client()
        
        response = await self._client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": self.profile["system_prompt"],
                "messages": messages,
            }
        )
        
        if response.status_code != 200:
            print(f"[ERROR] Claude API error: {response.status_code} {response.text}", flush=True)
            return "[Connection interrupted]"
        
        data = response.json()
        return data.get("content", [{}])[0].get("text", "")
    
    def _log_conversation(self, command: str, response: str, client_ip: str):
        """Log the conversation for TTP extraction"""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": self.session_id,
            "client_ip": client_ip,
            "personality": self.personality,
            "command": command,
            "response": response,
            "conversation_turn": len(self.conversation_history) // 2,
        }
        
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"[ERROR] Failed to log conversation: {e}", flush=True)
    
    async def handle_command(
        self, 
        command: str, 
        client_ip: str = "unknown"
    ) -> str:
        """
        Process an attacker command and generate a response.
        
        Args:
            command: The command entered by the attacker
            client_ip: The attacker's IP address for logging
            
        Returns:
            A realistic response string
        """
        if not self.enabled:
            # Return basic fake output when AI is disabled
            fake_output = self.system_state.generate_fake_output(command)
            return fake_output if fake_output else f"bash: {command.split()[0] if command.split() else ''}: command not found"
        
        # Check for simple commands we can handle locally
        fake_output = self.system_state.generate_fake_output(command)
        
        # Build the message for Claude
        user_message = f"Command entered: {command}"
        if fake_output:
            user_message += f"\n\n[System output to include in response:\n{fake_output}\n]"
        
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        
        try:
            response = await self._call_claude(self.conversation_history)
            self.conversation_history.append({
                "role": "assistant", 
                "content": response
            })
            
            # Log for analysis
            self._log_conversation(command, response, client_ip)
            
            return response
            
        except Exception as e:
            print(f"[ERROR] AI response failed: {e}", flush=True)
            # Fallback to fake output or generic error
            if fake_output:
                return fake_output
            return f"bash: {command.split()[0] if command.split() else 'command'}: command not found"
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.system_state.get_prompt()
    
    def get_welcome_banner(self) -> str:
        """Get a welcome banner for the shell session"""
        return f"""Welcome to Ubuntu 22.04.3 LTS ({self.system_state.hostname})

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1
"""
    
    async def close(self):
        """Cleanup resources"""
        if self._client:
            await self._client.aclose()


# =============================================================================
# Session Handler for SSH Integration  
# =============================================================================

class DeceptiveShellSession:
    """
    Manages an interactive shell session with AI-powered responses.
    Designed to integrate with asyncssh SSHServerProcess.
    """
    
    def __init__(
        self,
        client_ip: str,
        personality: str = "naive_intern",
        on_log: Optional[Callable[[str, Dict[str, Any]], None]] = None
    ):
        self.client_ip = client_ip
        self.handler = AIConversationHandler(personality=personality)
        self.on_log = on_log
        self.start_time = time.time()
        self.command_count = 0
        
    async def run(self, stdin, stdout, stderr) -> int:
        """
        Run the interactive shell session.
        
        Args:
            stdin: Input stream (asyncssh stdin)
            stdout: Output stream (asyncssh stdout)
            stderr: Error stream (asyncssh stderr)
            
        Returns:
            Exit code
        """
        try:
            # Send welcome banner
            stdout.write(self.handler.get_welcome_banner())
            stdout.write(self.handler.get_prompt())
            await asyncio.sleep(0)  # Flush
            
            buffer = ""
            
            while True:
                try:
                    # Read input character by character for interactive feel
                    data = await asyncio.wait_for(stdin.read(1024), timeout=300)
                    
                    if not data:
                        break
                    
                    buffer += data
                    
                    # Check for complete command (newline)
                    while '\n' in buffer or '\r' in buffer:
                        # Split on newline
                        if '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                        else:
                            line, buffer = buffer.split('\r', 1)
                        
                        line = line.strip()
                        
                        if not line:
                            stdout.write(self.handler.get_prompt())
                            continue
                        
                        # Handle exit commands
                        if line.lower() in ('exit', 'logout', 'quit'):
                            stdout.write("logout\n")
                            if self.on_log:
                                self.on_log('session_end', {
                                    'ip': self.client_ip,
                                    'duration_seconds': time.time() - self.start_time,
                                    'command_count': self.command_count
                                })
                            return 0
                        
                        self.command_count += 1
                        
                        # Log the command
                        if self.on_log:
                            self.on_log('command', {
                                'ip': self.client_ip,
                                'command': line,
                                'command_number': self.command_count
                            })
                        
                        # Get AI response
                        response = await self.handler.handle_command(line, self.client_ip)
                        
                        # Output response
                        stdout.write(response)
                        if not response.endswith('\n'):
                            stdout.write('\n')
                        stdout.write(self.handler.get_prompt())
                        
                except asyncio.TimeoutError:
                    stdout.write("\nSession timed out.\n")
                    break
                    
        except Exception as e:
            print(f"[ERROR] Shell session error: {e}", flush=True)
            stderr.write(f"Error: {e}\n")
            return 1
        finally:
            await self.handler.close()
        
        return 0


# =============================================================================
# Utility Functions
# =============================================================================

def get_available_personalities() -> Dict[str, str]:
    """Return a dict of personality_id -> description"""
    return {k: v["description"] for k, v in PERSONALITIES.items()}


async def test_conversation():
    """Interactive test mode for the conversation handler"""
    import sys
    
    print("=" * 60)
    print("AI Deception Test Mode")
    print("=" * 60)
    print("\nAvailable personalities:")
    for pid, desc in get_available_personalities().items():
        print(f"  - {pid}: {desc}")
    print()
    
    personality = input("Select personality (default: naive_intern): ").strip() or "naive_intern"
    
    handler = AIConversationHandler(personality=personality)
    
    if not handler.enabled:
        print("\n[!] AI is DISABLED. Set AI_DECEPTION_ENABLED=true and ANTHROPIC_API_KEY")
        print("[!] Running in fake-output-only mode\n")
    
    print(f"\n{handler.get_welcome_banner()}")
    
    try:
        while True:
            command = input(handler.get_prompt())
            if command.lower() in ('exit', 'quit'):
                break
            response = await handler.handle_command(command, "127.0.0.1")
            print(response)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        await handler.close()
    
    print("\nSession ended.")


if __name__ == "__main__":
    asyncio.run(test_conversation())
