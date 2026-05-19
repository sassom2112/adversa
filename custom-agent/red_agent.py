# custom-agent/red_agent.py
import subprocess
import paramiko  # SSH into Windows VM
import json
from datetime import datetime

# ── Atomic Red Team technique map ──────────────────────────────
# Maps MITRE techniques to real Atomic tests
# Each matches what we found in nromanoff investigation

ATOMIC_TECHNIQUES = {
    'T1547.001': {
        'name': 'Registry Run Key Persistence',
        'atomic_test': 1,
        'powershell': '''
            Invoke-AtomicTest T1547.001 -TestNumbers 1
        ''',
        'artifact_paths': [
            'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        ],
        'cleanup': 'Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup',
        'nromanoff_equivalent': 'dllhost\\svchost.exe run key'
    },
    'T1036.005': {
        'name': 'Masquerading — rename binary',
        'atomic_test': 1,
        'powershell': '''
            Invoke-AtomicTest T1036.005 -TestNumbers 1
        ''',
        'artifact_paths': [
            'C:\\Windows\\System32\\svchost.exe'
        ],
        'cleanup': 'Invoke-AtomicTest T1036.005 -TestNumbers 1 -Cleanup',
        'nromanoff_equivalent': 'fake svchost.exe in dllhost folder'
    },
    'T1003.001': {
        'name': 'LSASS Memory Dump',
        'atomic_test': 1,
        'powershell': '''
            Invoke-AtomicTest T1003.001 -TestNumbers 1
        ''',
        'artifact_paths': [
            'C:\\Windows\\Temp\\lsass.dmp'
        ],
        'cleanup': 'Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup',
        'nromanoff_equivalent': 'hydrakatz.exe credential theft'
    },
    'T1569.002': {
        'name': 'PsExec Lateral Movement',
        'atomic_test': 1,
        'powershell': '''
            Invoke-AtomicTest T1569.002 -TestNumbers 1
        ''',
        'artifact_paths': [
            'C:\\Windows\\PSEXESVC.EXE'
        ],
        'cleanup': 'Invoke-AtomicTest T1569.002 -TestNumbers 1 -Cleanup',
        'nromanoff_equivalent': 'PSEXESVC.EXE found in nromanoff'
    },
    'T1071.001': {
        'name': 'Web Protocol C2',
        'atomic_test': 1,
        'powershell': '''
            Invoke-AtomicTest T1071.001 -TestNumbers 1
        ''',
        'artifact_paths': [
            'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netman\\domain'
        ],
        'cleanup': 'Invoke-AtomicTest T1071.001 -TestNumbers 1 -Cleanup',
        'nromanoff_equivalent': '12.190.135.235 in Netman key'
    }
}


class AtomicRedAgent:
    """
    Real Red Agent using Atomic Red Team.
    Executes actual MITRE ATT&CK techniques on Windows test VM.
    Then captures artifacts for Blue Agent to find.
    """
    def __init__(self, windows_vm_ip, username, password):
        self.vm_ip = windows_vm_ip
        self.username = username
        self.password = password
        self.current_index = 0
        self.evasions = {}  # learned evasions per technique
        self.execution_log = []

    def _ssh_execute(self, powershell_command):
        """Execute PowerShell on Windows VM via SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                self.vm_ip,
                username=self.username,
                password=self.password,
                timeout=30
            )
            
            # Wrap in PowerShell
            cmd = f'powershell -ExecutionPolicy Bypass -Command "{powershell_command}"'
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=60)
            
            output = stdout.read().decode()
            error = stderr.read().decode()
            ssh.close()
            
            return output, error
            
        except Exception as e:
            return None, str(e)

    def execute_technique(self, technique_id):
        """
        Execute real Atomic Red Team test on Windows VM.
        Returns artifact description for Blue Agent to find.
        """
        technique = ATOMIC_TECHNIQUES[technique_id]
        print(f"\n🔴 Executing: {technique['name']}")
        print(f"   ATT&CK: {technique_id}")
        print(f"   VM: {self.vm_ip}")
        
        # Use evolved evasion if available
        if technique_id in self.evasions:
            ps_command = self.evasions[technique_id]['modified_command']
            print(f"   Using evolved evasion: generation {len(self.evasions[technique_id].get('history', []))}")
        else:
            ps_command = technique['powershell']
        
        output, error = self._ssh_execute(ps_command)
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'technique': technique_id,
            'command': ps_command,
            'output': output,
            'error': error,
            'artifact_paths': technique['artifact_paths']
        }
        self.execution_log.append(log_entry)
        
        if error and 'error' in error.lower():
            print(f"   ⚠️  Execution warning: {error[:100]}")
        else:
            print(f"   ✅ Executed successfully")
        
        # Return artifact description for Blue Agent scoring
        artifact_description = self._capture_artifacts(technique_id)
        return technique_id, artifact_description

    def _capture_artifacts(self, technique_id):
        """
        After executing, capture what artifacts were created.
        This is what Blue Agent will try to detect.
        """
        technique = ATOMIC_TECHNIQUES[technique_id]
        artifacts = []
        
        for artifact_path in technique['artifact_paths']:
            if artifact_path.startswith('HKLM:') or artifact_path.startswith('HKCU:'):
                # Registry artifact
                ps = f"Get-ItemProperty '{artifact_path}' | ConvertTo-Json"
                output, _ = self._ssh_execute(ps)
                if output:
                    artifacts.append(f"Registry: {artifact_path} = {output[:200]}")
            else:
                # File artifact
                ps = f"if (Test-Path '{artifact_path}') {{ Get-FileHash '{artifact_path}' | ConvertTo-Json }}"
                output, _ = self._ssh_execute(ps)
                if output:
                    artifacts.append(f"File: {artifact_path} exists, hash={output[:100]}")
        
        return " | ".join(artifacts) if artifacts else f"Artifact at {technique['artifact_paths']}"

    def cleanup(self, technique_id):
        """Clean up artifacts after Blue Agent has scanned"""
        technique = ATOMIC_TECHNIQUES[technique_id]
        print(f"   🧹 Cleaning up {technique_id}")
        self._ssh_execute(technique['cleanup'])

    def next_technique(self):
        """Cycle through techniques"""
        ids = list(ATOMIC_TECHNIQUES.keys())
        technique_id = ids[self.current_index % len(ids)]
        self.current_index += 1
        return self.execute_technique(technique_id)

    def evolve(self, technique_id, caught_by_patterns):
        """
        Modify the attack to evade detection patterns.
        Uses Claude to suggest evasion then modifies the PowerShell.
        """
        import anthropic
        client = anthropic.Anthropic()
        
        original = ATOMIC_TECHNIQUES[technique_id]['powershell']
        
        try:
            response = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=400,
                messages=[{
                    "role": "user",
                    "content": f"""You are a red team operator.
Your PowerShell attack was detected by these patterns: {caught_by_patterns}
Original command: {original}
Technique: {technique_id}

Suggest a modified PowerShell command that achieves the same 
objective but evades those detection patterns.
Keep it realistic and executable.
Respond in JSON only:
{{"modified_command": "powershell here", "evasion_method": "what changed"}}"""
                }]
            )
            
            suggestion = json.loads(response.content[0].text.strip())
            
            if technique_id not in self.evasions:
                self.evasions[technique_id] = {
                    'history': [],
                    'modified_command': suggestion['modified_command']
                }
            
            self.evasions[technique_id]['history'].append(suggestion)
            self.evasions[technique_id]['modified_command'] = (
                suggestion['modified_command']
            )
            
            print(f"   🔴 Evasion: {suggestion['evasion_method']}")
            
        except Exception as e:
            print(f"   ⚠️  Evolve failed: {e}")


# ── Fallback: Simulated Red Agent (no Windows VM needed) ───────
class SimulatedRedAgent:
    """
    Use this when you don't have a Windows VM yet.
    Simulates Atomic Red Team artifacts based on nromanoff ground truth.
    Replace with AtomicRedAgent when Windows VM is ready.
    """
    def __init__(self):
        self.current_index = 0
        self.evasions = {}
        
        # Artifacts seeded from real nromanoff evidence
        self.techniques = {
            'T1547.001': {
                'name': 'Registry Run Key',
                'artifacts': [
                    'HKLM Run key: svchost = dllhost\\svchost.exe LastWrite 2012-04-04',
                    'Run key points to non-standard path in dllhost subdirectory',
                    'Autostart entry references executable not in System32 directly',
                ],
                'generation': 0
            },
            'T1036.005': {
                'name': 'Masquerading',
                'artifacts': [
                    'File size 102400 bytes svchost.exe in dllhost folder PE32',
                    'Binary in subdirectory masquerading as system process',
                    'Executable in unexpected location with system process name',
                ],
                'generation': 0
            },
            'T1003.001': {
                'name': 'Credential Dumping',
                'artifacts': [
                    'hydrakatz.exe present in System32 MD5 827040a5f5ae',
                    'OpenSSL strings found in credential tool binary',
                    'SAM database access tool found in system directory',
                ],
                'generation': 0
            },
            'T1071.001': {
                'name': 'C2 Web Protocol',
                'artifacts': [
                    '12.190.135.235 found in Netman domain registry key',
                    'winclient.reg configures beacon pause 0x40 C2 endpoint',
                    'Service key modified with external IP address value',
                ],
                'generation': 0
            },
            'T1569.002': {
                'name': 'PsExec',
                'artifacts': [
                    'PSEXESVC.EXE found in C:\\Windows root directory',
                    'psexesvc service binary present lateral movement tool',
                    'Remote execution service binary in Windows directory',
                ],
                'generation': 0
            },
        }

    def next_technique(self):
        ids = list(self.techniques.keys())
        technique_id = ids[self.current_index % len(ids)]
        self.current_index += 1
        
        data = self.techniques[technique_id]
        
        # Use evolved artifact if available
        if self.evasions.get(technique_id):
            artifact = self.evasions[technique_id][-1]['modified_artifact']
        else:
            # Rotate through base artifacts
            idx = data['generation'] % len(data['artifacts'])
            artifact = data['artifacts'][idx]
        
        return technique_id, artifact

    def evolve(self, technique_id, caught_by_patterns):
        import anthropic
        client = anthropic.Anthropic()
        
        data = self.techniques[technique_id]
        
        try:
            response = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=200,
                messages=[{
                    "role": "user",
                    "content": f"""Red team operator.
Caught by: {caught_by_patterns}
Technique: {technique_id}
Current artifact: {data['artifacts'][0]}

Suggest modified artifact description evading those patterns.
Respond in JSON only:
{{"modified_artifact": "new description"}}"""
                }]
            )
            
            suggestion = json.loads(response.content[0].text.strip())
            
            if technique_id not in self.evasions:
                self.evasions[technique_id] = []
            self.evasions[technique_id].append(suggestion)
            self.techniques[technique_id]['generation'] += 1
            
            print(f"   🔴 Evolved: {suggestion['modified_artifact'][:60]}")
            
        except Exception as e:
            print(f"   ⚠️  Evolve failed: {e}")

    def cleanup(self, technique_id):
        pass  # nothing to clean up in simulation

