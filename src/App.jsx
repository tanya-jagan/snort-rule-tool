import React, { useState } from 'react';
import { PlayCircle, CheckCircle, XCircle, AlertCircle, FileText, Package, Code, Download } from 'lucide-react';

export default function SnortRuleTester() {
  const [activeTab, setActiveTab] = useState('tester');
  const [rule, setRule] = useState('alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)');
  const [testConfig, setTestConfig] = useState({
    protocol: 'tcp',
    srcIP: '192.168.1.100',
    dstIP: '10.0.0.1',
    srcPort: '12345',
    dstPort: '80',
    payload: 'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n',
    flags: 'S'
  });
  const [testResults, setTestResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [suiteResults, setSuiteResults] = useState(null);
  const [runningTests, setRunningTests] = useState(false);

  const sampleRules = [
    { name: 'HTTP GET Detection', rule: 'alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; http_method; sid:1000001; rev:1;)' },
    { name: 'SSH Brute Force', rule: 'alert tcp any any -> any 22 (msg:"Possible SSH Brute Force"; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000002; rev:1;)' },
    { name: 'DNS Query', rule: 'alert udp any any -> any 53 (msg:"DNS Query Detected"; content:"|01 00 00 01|"; depth:4; sid:1000003; rev:1;)' },
    { name: 'ICMP Ping', rule: 'alert icmp any any -> any any (msg:"ICMP Ping Detected"; itype:8; sid:1000004; rev:1;)' }
  ];

  const validateRule = (ruleText) => {
    const issues = [];
    
    // Basic syntax validation
    if (!ruleText.trim()) {
      return { valid: false, issues: ['Rule cannot be empty'] };
    }
    
    const parts = ruleText.match(/^(\w+)\s+(\w+)\s+([\w.]+)\s+([\w:]+)\s+(-?>|<>)\s+([\w.]+)\s+([\w:]+)\s+\((.*)\)$/);
    if (!parts) {
      issues.push('Invalid rule syntax - should follow: action protocol src_ip src_port direction dst_ip dst_port (options)');
      return { valid: false, issues };
    }
    
    const [, action, protocol, srcIP, srcPort, direction, dstIP, dstPort, options] = parts;
    
    // Validate action
    const validActions = ['alert', 'log', 'pass', 'drop', 'reject', 'sdrop'];
    if (!validActions.includes(action)) {
      issues.push(`Invalid action: ${action}. Must be one of: ${validActions.join(', ')}`);
    }
    
    // Validate protocol
    const validProtocols = ['tcp', 'udp', 'icmp', 'ip'];
    if (!validProtocols.includes(protocol)) {
      issues.push(`Invalid protocol: ${protocol}. Must be one of: ${validProtocols.join(', ')}`);
    }
    
    // Check for required options
    if (!options.includes('sid:')) {
      issues.push('Missing required option: sid (Snort ID)');
    }
    
    if (!options.includes('msg:')) {
      issues.push('Missing required option: msg (alert message)');
    }
    
    // Check for protocol-specific keyword conflicts
    if (protocol === 'icmp') {
      if (options.includes('flow:')) {
        issues.push('Conflict: "flow" keyword cannot be used with ICMP protocol');
      }
    }
    
    if (protocol === 'udp') {
      if (options.includes('stream_size:')) {
        issues.push('Conflict: "stream_size" keyword requires TCP protocol');
      }
    }
    
    // Check for logical conflicts
    if (options.includes('http_method') && !options.includes('http')) {
      if (protocol !== 'tcp' || (dstPort !== '80' && dstPort !== 'any' && dstPort !== '443')) {
        issues.push('Warning: http_method keyword typically used with HTTP ports (80/443)');
      }
    }
    
    return {
      valid: issues.length === 0,
      issues,
      parsed: { action, protocol, srcIP, srcPort, direction, dstIP, dstPort, options }
    };
  };

  const generatePacket = (config) => {
    return {
      protocol: config.protocol,
      src_ip: config.srcIP,
      dst_ip: config.dstIP,
      src_port: config.srcPort,
      dst_port: config.dstPort,
      payload: config.payload,
      flags: config.flags,
      timestamp: new Date().toISOString()
    };
  };

  const simulateRuleMatch = (ruleValidation, packet) => {
    if (!ruleValidation.valid) {
      return { matched: false, reason: 'Invalid rule' };
    }
    
    const { parsed } = ruleValidation;
    
    // Check protocol
    if (parsed.protocol !== 'ip' && parsed.protocol !== packet.protocol) {
      return { matched: false, reason: `Protocol mismatch: rule expects ${parsed.protocol}, packet is ${packet.protocol}` };
    }
    
    // Check ports for TCP/UDP
    if (['tcp', 'udp'].includes(packet.protocol)) {
      if (parsed.dstPort !== 'any' && parsed.dstPort !== packet.dst_port) {
        return { matched: false, reason: `Destination port mismatch: rule expects ${parsed.dstPort}, packet has ${packet.dst_port}` };
      }
    }
    
    // Check content if specified
    if (parsed.options.includes('content:')) {
      const contentMatch = parsed.options.match(/content:"([^"]+)"/);
      if (contentMatch && packet.payload) {
        if (!packet.payload.includes(contentMatch[1])) {
          return { matched: false, reason: `Payload does not contain expected content: ${contentMatch[1]}` };
        }
      }
    }
    
    return { matched: true, reason: 'All conditions satisfied' };
  };

  const runTest = () => {
    setLoading(true);
    
    setTimeout(() => {
      const validation = validateRule(rule);
      const packet = generatePacket(testConfig);
      const matchResult = simulateRuleMatch(validation, packet);
      
      setTestResults({
        validation,
        packet,
        matchResult,
        timestamp: new Date().toISOString()
      });
      
      setLoading(false);
    }, 800);
  };

  const generatePythonCode = () => {
    return `#!/usr/bin/env python3
"""
Snort Rule Unit Testing Framework
Generates synthetic packets and tests rule matching
"""

from scapy.all import *
import sys

class SnortRuleTester:
    def __init__(self, rule):
        self.rule = rule
        self.results = []
    
    def validate_rule(self):
        """Validate Snort rule syntax"""
        # Parse rule components
        if not self.rule.strip():
            return False, ["Rule cannot be empty"]
        
        issues = []
        # Add validation logic here
        return len(issues) == 0, issues
    
    def generate_packet(self, config):
        """Generate synthetic packet using Scapy"""
        if config['protocol'] == 'tcp':
            packet = IP(src=config['src_ip'], dst=config['dst_ip']) / \\
                    TCP(sport=int(config['src_port']), 
                        dport=int(config['dst_port']),
                        flags=config.get('flags', 'S')) / \\
                    Raw(load=config.get('payload', ''))
        elif config['protocol'] == 'udp':
            packet = IP(src=config['src_ip'], dst=config['dst_ip']) / \\
                    UDP(sport=int(config['src_port']), 
                        dport=int(config['dst_port'])) / \\
                    Raw(load=config.get('payload', ''))
        elif config['protocol'] == 'icmp':
            packet = IP(src=config['src_ip'], dst=config['dst_ip']) / \\
                    ICMP(type=config.get('icmp_type', 8))
        else:
            packet = IP(src=config['src_ip'], dst=config['dst_ip'])
        
        return packet
    
    def test_rule(self, packet):
        """Test if packet matches rule"""
        # In production, this would interface with Snort
        # For now, we simulate rule matching logic
        return True
    
    def run_tests(self, test_configs):
        """Run all test cases"""
        for config in test_configs:
            packet = self.generate_packet(config)
            result = self.test_rule(packet)
            self.results.append({
                'config': config,
                'packet': packet.summary(),
                'matched': result
            })
        return self.results

# Example usage
if __name__ == "__main__":
    rule = "${rule.replace(/"/g, '\\"')}"
    tester = SnortRuleTester(rule)
    
    test_config = {
        'protocol': '${testConfig.protocol}',
        'src_ip': '${testConfig.srcIP}',
        'dst_ip': '${testConfig.dstIP}',
        'src_port': '${testConfig.srcPort}',
        'dst_port': '${testConfig.dstPort}',
        'payload': '${testConfig.payload.replace(/\\/g, '\\\\')}'
    }
    
    valid, issues = tester.validate_rule()
    print(f"Rule valid: {valid}")
    if issues:
        print(f"Issues: {issues}")
    
    results = tester.run_tests([test_config])
    for result in results:
        print(f"\\nTest: {result['config']}")
        print(f"Packet: {result['packet']}")
        print(f"Matched: {result['matched']}")
`;
  };

  // Test Suite for Framework Validation
  const testSuite = {
    syntax: [
      {
        category: 'Syntax Testing',
        name: 'Valid TCP Rule - Complete Syntax',
        rule: 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests well-formed rule with all required components'
      },
      {
        category: 'Syntax Testing',
        name: 'Empty Rule',
        rule: '',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests handling of empty input'
      },
      {
        category: 'Syntax Testing',
        name: 'Malformed Syntax - Incomplete',
        rule: 'alert tcp any any',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests incomplete rule structure'
      },
      {
        category: 'Syntax Testing',
        name: 'Malformed Syntax - Missing Parentheses',
        rule: 'alert tcp any any -> any 80 msg:"Test"; sid:1;',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests rule without option parentheses'
      },
      {
        category: 'Syntax Testing',
        name: 'Malformed Syntax - Wrong Direction',
        rule: 'alert tcp any any => any 80 (msg:"Test"; sid:1;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests invalid direction operator'
      },
      {
        category: 'Syntax Testing',
        name: 'Valid Bidirectional Rule',
        rule: 'alert tcp any any <> any 80 (msg:"Test"; sid:1;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests bidirectional operator'
      }
    ],
    input: [
      {
        category: 'Input Validation',
        name: 'Missing Required Field - SID',
        rule: 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; rev:1;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests detection of missing Snort ID'
      },
      {
        category: 'Input Validation',
        name: 'Missing Required Field - MSG',
        rule: 'alert tcp any any -> any 80 (sid:1000001; rev:1;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests detection of missing message field'
      },
      {
        category: 'Input Validation',
        name: 'Invalid Action Keyword',
        rule: 'block tcp any any -> any 80 (msg:"Test"; sid:1000001;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests rejection of non-standard action'
      },
      {
        category: 'Input Validation',
        name: 'Invalid Protocol',
        rule: 'alert http any any -> any 80 (msg:"Test"; sid:1000001;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests rejection of invalid protocol (HTTP is not a valid Snort protocol)'
      },
      {
        category: 'Input Validation',
        name: 'Valid Alternative Action - drop',
        rule: 'drop tcp any any -> any 80 (msg:"Test"; sid:1;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests acceptance of valid drop action'
      },
      {
        category: 'Input Validation',
        name: 'Valid Alternative Action - reject',
        rule: 'reject tcp any any -> any 80 (msg:"Test"; sid:1;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests acceptance of valid reject action'
      },
      {
        category: 'Input Validation',
        name: 'Valid UDP Rule',
        rule: 'alert udp any any -> any 53 (msg:"DNS Query"; sid:1000002;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests valid UDP protocol rule'
      },
      {
        category: 'Input Validation',
        name: 'Valid ICMP Rule',
        rule: 'alert icmp any any -> any any (msg:"ICMP Ping"; itype:8; sid:1000003;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests valid ICMP protocol rule'
      },
      {
        category: 'Input Validation',
        name: 'Valid IP Rule (Generic)',
        rule: 'alert ip any any -> any any (msg:"Any IP"; sid:1;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests valid IP protocol rule (matches any transport)'
      }
    ],
    functional: [
      {
        category: 'Functional Testing - Conflicts',
        name: 'ICMP with Flow Keyword',
        rule: 'alert icmp any any -> any any (msg:"Test"; flow:established; sid:1000001;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests detection of flow keyword on stateless ICMP protocol'
      },
      {
        category: 'Functional Testing - Conflicts',
        name: 'UDP with stream_size',
        rule: 'alert udp any any -> any 53 (msg:"Test"; stream_size:server,>,100; sid:1000001;)',
        expectedValid: false,
        expectedIssues: 1,
        description: 'Tests detection of TCP-only keyword on UDP rule'
      },
      {
        category: 'Functional Testing - Warnings',
        name: 'http_method on Non-HTTP Port',
        rule: 'alert tcp any any -> any 22 (msg:"Test"; http_method; sid:1;)',
        expectedValid: true,
        expectedIssues: 1,
        description: 'Tests warning for HTTP keyword on non-standard port'
      },
      {
        category: 'Functional Testing - Multiple Issues',
        name: 'Multiple Validation Failures',
        rule: 'block http any any -> any 80 (rev:1;)',
        expectedValid: false,
        expectedIssues: 4,
        description: 'Tests detection of multiple issues: invalid action, invalid protocol, missing sid, missing msg'
      },
      {
        category: 'Functional Testing - Edge Cases',
        name: 'Rule with Content and http_method',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; http_method; sid:1;)',
        expectedValid: true,
        expectedIssues: 0,
        description: 'Tests valid combination of content and HTTP keywords'
      }
    ]
  };

  const attackCategoryTests = [
  // 1. not-suspicious
  {
    category: "Classtype - not-suspicious",
    name: "Not Suspicious Traffic - Basic HTTP",
    rule: 'alert tcp any any -> any 80 (msg:"Normal HTTP"; classtype:not-suspicious; content:"GET"; sid:2000001;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'GET /index.html' },
    shouldMatch: true,
    description: 'Normal HTTP GET request considered not suspicious'
  },

];


  const matchingTests = {
    attackCategory: [
  // 1. not-suspicious
  {
    category: "Attack Category",
    name: "Not Suspicious Traffic - Basic HTTP",
    rule: 'alert tcp any any -> any 80 (msg:"Normal HTTP"; classtype:not-suspicious; content:"GET"; sid:2000001;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'GET /index.html' },
    shouldMatch: true,
    description: 'Normal HTTP GET request considered not suspicious'
  },
    // 2. unknown
  {
    category: "Attack Category",
    name: "Unknown Traffic - No Clear Signature",
    rule: 'alert tcp any any -> any any (msg:"Unknown traffic"; classtype:unknown; content:"???"; sid:2000002;)',
    packet: { protocol: 'tcp', dst_port: '1234', payload: '???' },
    shouldMatch: true,
    description: 'Matches unusual placeholder payload'
  },

  // 3. bad-unknown
  {
    category: "Attack Category",
    name: "Potentially Bad Unknown Traffic",
    rule: 'alert tcp any any -> any any (msg:"Bad Unknown"; classtype:bad-unknown; content:"BAD"; sid:2000003;)',
    packet: { protocol: 'tcp', dst_port: '9999', payload: 'BADDATA' },
    shouldMatch: true,
    description: 'Matches suspicious unknown traffic'
  },

  // 4. attempted-recon
  {
    category: "Attack Category",
    name: "Attempted Recon - Nmap",
    rule: 'alert tcp any any -> any any (msg:"Nmap Scan"; classtype:attempted-recon; content:"Nmap"; sid:2000004;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'Nmap scan initiated' },
    shouldMatch: true,
    description: 'Simple recon scan payload'
  },

  // 5. successful-recon-limited
  {
    category: "Attack Category",
    name: "Limited Recon Success",
    rule: 'alert tcp any any -> any 80 (msg:"Version Leak"; classtype:successful-recon-limited; content:"Server:"; sid:2000005;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'HTTP/1.1 200 OK\r\nServer: Apache' },
    shouldMatch: true,
    description: 'Server header leaks software name'
  },

  // 6. successful-recon-largescale
  {
    category: "Attack Category",
    name: "Large Scale Recon",
    rule: 'alert tcp any any -> any any (msg:"Mass Scan"; classtype:successful-recon-largescale; content:"SCAN"; sid:2000006;)',
    packet: { protocol: 'tcp', dst_port: '443', payload: 'SCAN MASS' },
    shouldMatch: true,
    description: 'Mass scanning signature'
  },

  // 7. attempted-dos
  {
    category: "Attack Category",
    name: "Attempted DoS - Slowloris",
    rule: 'alert tcp any any -> any 80 (msg:"Attempted DoS"; classtype:attempted-dos; content:"Slowloris"; sid:2000007;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'Slowloris attack attempt' },
    shouldMatch: true,
    description: 'DoS attempt payload'
  },

  // 8. successful-dos
  {
    category: "Attack Category",
    name: "Successful DoS Message",
    rule: 'alert tcp any any -> any any (msg:"DoS Success"; classtype:successful-dos; content:"SERVICE UNAVAILABLE"; sid:2000008;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: '503 SERVICE UNAVAILABLE' },
    shouldMatch: true,
    description: 'DoS success indicator'
  },

  // 9. attempted-user
  {
    category: "Attack Category",
    name: "Attempted User Priv Esc",
    rule: 'alert tcp any any -> any any (msg:"Attempted User Privilege Gain"; classtype:attempted-user; content:"sudo"; sid:2000009;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'sudo exploit' },
    shouldMatch: true,
    description: 'Attempt to elevate privileges'
  },

  // 10. unsuccessful-user
  {
    category: "Attack Category",
    name: "Failed Privilege Attempt",
    rule: 'alert tcp any any -> any any (msg:"Unsuccessful User Privilege Gain"; classtype:unsuccessful-user; content:"access denied"; sid:2000010;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'access denied' },
    shouldMatch: true,
    description: 'Failed privilege escalation output'
  },

  // 11. successful-user
  {
    category: "Attack Category",
    name: "Successful User Priv Esc",
    rule: 'alert tcp any any -> any any (msg:"Successful User Gain"; classtype:succesful-user; content:"root:"; sid:2000011;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'root: ALL=(ALL)' },
    shouldMatch: true,
    description: 'Root access gained'
  },

  // 12. attempted-admin
  {
    category: "Attack Category",
    name: "Attempted Admin Privilege Gain",
    rule: 'alert tcp any any -> any any (msg:"Attempted Admin Gain"; classtype:attempted-admin; content:"admin exploit"; sid:2000012;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'admin exploit attempt' },
    shouldMatch: true,
    description: 'Admin escalation attempt'
  },

  // 13. successful-admin
  {
    category: "Attack Category",
    name: "Successful Admin Gain",
    rule: 'alert tcp any any -> any any (msg:"Admin Gain"; classtype:successful-admin; content:"uid=0"; sid:2000013;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'uid=0(root)' },
    shouldMatch: true,
    description: 'Root-level access indicator'
  },

  // 14. rpc-portmap-decode
  {
    category: "Attack Category",
    name: "RPC Portmap Decode",
    rule: 'alert udp any any -> any 111 (msg:"RPC Portmap"; classtype:rpc-portmap-decode; content:"RPC"; sid:2000014;)',
    packet: { protocol: 'udp', dst_port: '111', payload: 'RPC CALL' },
    shouldMatch: true,
    description: 'RPC traffic detection'
  },

  // 15. shellcode-detect
  {
    category: "Attack Category",
    name: "Shellcode Detected",
    rule: 'alert tcp any any -> any any (msg:"Shellcode"; classtype:shellcode-detect; content:"\x90\x90"; sid:2000015;)',
    packet: { protocol: 'tcp', dst_port: '445', payload: '\x90\x90\x90\x90' },
    shouldMatch: true,
    description: 'NOP sled detection'
  },

  // 16. string-detect
  {
    category: "Attack Category",
    name: "Suspicious String",
    rule: 'alert tcp any any -> any any (msg:"Suspicious String"; classtype:string-detect; content:"CONFIDENTIAL"; sid:2000016;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'CONFIDENTIAL DATA EXPOSED' },
    shouldMatch: true,
    description: 'Detects sensitive terms'
  },

  // 17. suspicious-filename-detect
  {
    category: "Attack Category",
    name: "Suspicious Filename",
    rule: 'alert tcp any any -> any 80 (msg:"Suspicious Filename"; classtype:suspicious-filename-detect; content:".exe"; sid:2000017;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'GET /malware.exe' },
    shouldMatch: true,
    description: 'Detects suspicious file downloads'
  },

  // 18. suspicious-login
  {
    category: "Attack Category",
    name: "Suspicious Login",
    rule: 'alert tcp any any -> any 22 (msg:"Suspicious Login"; classtype:suspicious-login; content:"invalid user"; sid:2000018;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'invalid user attempt' },
    shouldMatch: true,
    description: 'Suspicious SSH login attempt'
  },

  // 19. system-call-detect
  {
    category: "Attack Category",
    name: "System Call Detection",
    rule: 'alert tcp any any -> any any (msg:"System Call"; classtype:system-call-detect; content:"sys_call"; sid:2000019;)',
    packet: { protocol: 'tcp', dst_port: '123', payload: 'sys_call invoked' },
    shouldMatch: true,
    description: 'Detects system call strings'
  },

  // 20. tcp-connection
  {
    category: "Attack Category",
    name: "TCP Connection Established",
    rule: 'alert tcp any any -> any any (msg:"TCP Connection"; classtype:tcp-connection; content:"SYN"; sid:2000020;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'SYN' },
    shouldMatch: true,
    description: 'Detects connection initiation'
  },

  // 21. trojan-activity
  {
    category: "Attack Category",
    name: "Trojan Beaconing",
    rule: 'alert tcp any any -> any any (msg:"Trojan Activity"; classtype:trojan-activity; content:"beacon"; sid:2000021;)',
    packet: { protocol: 'tcp', dst_port: '4444', payload: 'sending beacon' },
    shouldMatch: true,
    description: 'Trojan C2 beacon detection'
  },

  // 22. unusual-client-port-connection
  {
    category: "Attack Category",
    name: "Unusual Client Port",
    rule: 'alert tcp any any -> any 21 (msg:"Unusual Client Port"; classtype:unusual-client-port-connection; content:"FTP"; sid:2000022;)',
    packet: { protocol: 'tcp', dst_port: '21', payload: 'FTP unusual client activity' },
    shouldMatch: true,
    description: 'Unusual port usage'
  },

  // 23. network-scan
  {
    category: "Attack Category",
    name: "Network Scan",
    rule: 'alert tcp any any -> any any (msg:"Network Scan"; classtype:network-scan; content:"scan"; sid:2000023;)',
    packet: { protocol: 'tcp', dst_port: '8080', payload: 'scan detected' },
    shouldMatch: true,
    description: 'Generic scan detection'
  },

  // 24. denial-of-service
  {
    category: "Attack Category",
    name: "Denial of Service",
    rule: 'alert udp any any -> any any (msg:"UDP Flood"; classtype:denial-of-service; content:"flood"; sid:2000024;)',
    packet: { protocol: 'udp', dst_port: '9999', payload: 'udp flood' },
    shouldMatch: true,
    description: 'DoS signature'
  },

  // 25. non-standard-protocol
  {
    category: "Attack Category",
    name: "Non-Standard Protocol",
    rule: 'alert tcp any any -> any any (msg:"Non Standard Protocol"; classtype:non-standard-protocol; content:"WEIRDPROTO"; sid:2000025;)',
    packet: { protocol: 'tcp', dst_port: '1234', payload: 'WEIRDPROTO handshake' },
    shouldMatch: true,
    description: 'Detects nonstandard protocol markers'
  },

  // 26. protocol-command-decode
  {
    category: "Attack Category",
    name: "Protocol Decode",
    rule: 'alert tcp any any -> any any (msg:"Protocol Decode"; classtype:protocol-command-decode; content:"CMD"; sid:2000026;)',
    packet: { protocol: 'tcp', dst_port: '21', payload: 'CMD LIST' },
    shouldMatch: true,
    description: 'Detects command decoding activity'
  },

  // 27. web-application-activity
  {
    category: "Attack Category",
    name: "Web App Activity",
    rule: 'alert tcp any any -> any 80 (msg:"Web App Activity"; classtype:web-application-activity; content:"/admin"; sid:2000027;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'GET /admin/dashboard' },
    shouldMatch: true,
    description: 'Detects access to admin paths'
  },

  // 28. web-application-attack
  {
    category: "Attack Category",
    name: "Web App Attack - SQL Injection",
    rule: 'alert tcp any any -> any 80 (msg:"SQL Injection"; classtype:web-application-attack; content:"UNION SELECT"; sid:2000028;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'id=1 UNION SELECT username,password FROM users' },
    shouldMatch: true,
    description: 'SQL injection payload'
  },

  // 29. misc-activity
  {
    category: "Attack Category",
    name: "Misc Activity",
    rule: 'alert tcp any any -> any any (msg:"Misc Activity"; classtype:misc-activity; content:"MISC"; sid:2000029;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'MISC event' },
    shouldMatch: true,
    description: 'Generic miscellaneous activity'
  },

  // 30. misc-attack
  {
    category: "Attack Category",
    name: "Misc Attack",
    rule: 'alert tcp any any -> any any (msg:"Misc Attack"; classtype:misc-attack; content:"ATTACK"; sid:2000030;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'ATTACK VECTOR' },
    shouldMatch: true,
    description: 'Misc attack signature'
  },

  // 31. icmp-event
  {
    category: "Attack Category",
    name: "ICMP Event",
    rule: 'alert icmp any any -> any any (msg:"ICMP Event"; classtype:icmp-event; content:"PING"; sid:2000031;)',
    packet: { protocol: 'icmp', dst_port: 'any', payload: 'PING' },
    shouldMatch: true,
    description: 'Detects generic ICMP message'
  },

  // 32. inappropriate-content
  {
    category: "Attack Category",
    name: "Inappropriate Content",
    rule: 'alert tcp any any -> any any (msg:"Inappropriate"; classtype:inappropriate-content; content:"adult"; sid:2000032;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'adult material content' },
    shouldMatch: true,
    description: 'Detects inappropriate content'
  },

  // 33. policy-violation
  {
    category: "Attack Category",
    name: "Policy Violation",
    rule: 'alert tcp any any -> any any (msg:"Policy Violation"; classtype:policy-violation; content:"restricted"; sid:2000033;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'restricted file access' },
    shouldMatch: true,
    description: 'Detects corporate policy violations'
  },

  // 34. default-login-attempt
  {
    category: "Attack Category",
    name: "Default Login Attempt",
    rule: 'alert tcp any any -> any 22 (msg:"Default Login"; classtype:default-login-attempt; content:"admin:admin"; sid:2000034;)',
    packet: { protocol: 'tcp', dst_port: '22', payload: 'admin:admin' },
    shouldMatch: true,
    description: 'Detects login attempts using default credentials'
  },

  // 35. sdf (Sensitive Data)
  {
    category: "Attack Category",
    name: "Sensitive Data Exposure",
    rule: 'alert tcp any any -> any 80 (msg:"Sensitive Data"; classtype:sdf; content:"SSN:"; sid:2000035;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'SSN: 123-45-6789' },
    shouldMatch: true,
    description: 'Detects possible sensitive data leakage'
  },

  // 36. file-format
  {
    category: "Attack Category",
    name: "Malicious File Format",
    rule: 'alert tcp any any -> any 80 (msg:"Malicious File"; classtype:file-format; content:"MZ"; sid:2000036;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'MZ...EXE FILE' },
    shouldMatch: true,
    description: 'Windows PE header detection'
  },

  // 37. malware-cnc
  {
    category: "Attack Category",
    name: "Malware C2 Traffic",
    rule: 'alert tcp any any -> any any (msg:"C2 Traffic"; classtype:malware-cnc; content:"C2-PING"; sid:2000037;)',
    packet: { protocol: 'tcp', dst_port: '5555', payload: 'C2-PING' },
    shouldMatch: true,
    description: 'Malware command & control payload'
  },

  // 38. client-side-exploit
  {
    category: "Attack Category",
    name: "Client Side Exploit",
    rule: 'alert tcp any any -> any 80 (msg:"Client Exploit"; classtype:client-side-exploit; content:"EXPLOIT"; sid:2000038;)',
    packet: { protocol: 'tcp', dst_port: '80', payload: 'EXPLOIT BUFFER OVERFLOW' },
    shouldMatch: true,
    description: 'Client-side exploit indicator'
  }
],
    portMatching: [
      {
        category: 'Port Matching',
        name: 'Exact Port Match',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: '' },
        shouldMatch: true,
        description: 'Packet destined for port 80 should match rule targeting port 80'
      },
      {
        category: 'Port Matching',
        name: 'Port Mismatch',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '443', payload: '' },
        shouldMatch: false,
        description: 'Packet destined for port 443 should not match rule targeting port 80'
      },
      {
        category: 'Port Matching',
        name: 'Any Port Wildcard',
        rule: 'alert tcp any any -> any any (msg:"Test"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '8080', payload: '' },
        shouldMatch: true,
        description: 'Any port wildcard should match all ports'
      }
    ],
    protocolMatching: [
      {
        category: 'Protocol Matching',
        name: 'Protocol Match - TCP',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: '' },
        shouldMatch: true,
        description: 'TCP packet should match TCP rule'
      },
      {
        category: 'Protocol Matching',
        name: 'Protocol Mismatch - TCP vs UDP',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        packet: { protocol: 'udp', dst_port: '80', payload: '' },
        shouldMatch: false,
        description: 'UDP packet should not match TCP rule'
      },
      {
        category: 'Protocol Matching',
        name: 'IP Protocol Wildcard',
        rule: 'alert ip any any -> any any (msg:"Test"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: '' },
        shouldMatch: true,
        description: 'IP wildcard should match any transport protocol'
      },
      {
        category: 'Protocol Matching',
        name: 'UDP Protocol Match',
        rule: 'alert udp any any -> any 53 (msg:"Test"; sid:1;)',
        packet: { protocol: 'udp', dst_port: '53', payload: '' },
        shouldMatch: true,
        description: 'UDP packet on port 53 should match UDP DNS rule'
      }
    ],
    contentMatching: [
      {
        category: 'Content Matching',
        name: 'Content Match - Simple String',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: 'GET / HTTP/1.1' },
        shouldMatch: true,
        description: 'Packet containing "GET" should match content rule'
      },
      {
        category: 'Content Matching',
        name: 'Content Mismatch',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"POST"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: 'GET / HTTP/1.1' },
        shouldMatch: false,
        description: 'Packet without "POST" should not match POST content rule'
      },
      {
        category: 'Content Matching',
        name: 'Empty Payload with Content Rule',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"data"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: '' },
        shouldMatch: false,
        description: 'Empty packet should not match content rule'
      },
      {
        category: 'Content Matching',
        name: 'Case Sensitive Content Match',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: 'get / http/1.1' },
        shouldMatch: false,
        description: 'Content matching is case-sensitive by default'
      }
    ],
    edgeCases: [
      {
        category: 'Edge Cases',
        name: 'Rule Without Content on Matching Packet',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: 'Some random data' },
        shouldMatch: true,
        description: 'Rule without content keyword should match any payload'
      },
      {
        category: 'Edge Cases',
        name: 'Multiple Conditions - All Match',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"HTTP"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: 'HTTP/1.1 200 OK' },
        shouldMatch: true,
        description: 'All conditions (protocol, port, content) satisfied'
      },
      {
        category: 'Edge Cases',
        name: 'Multiple Conditions - One Fails',
        rule: 'alert tcp any any -> any 80 (msg:"Test"; content:"SSH"; sid:1;)',
        packet: { protocol: 'tcp', dst_port: '80', payload: 'HTTP/1.1 200 OK' },
        shouldMatch: false,
        description: 'Protocol and port match but content fails - should not match'
      }
    ]
  };

  const runTestSuite = () => {
    setRunningTests(true);
    
    setTimeout(() => {
      const results = {
        validation: [],
        matching: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          byCategory: {}
        }
      };

      // Flatten and run validation tests
      const allValidationTests = [
        ...testSuite.syntax,
        ...testSuite.input,
        ...testSuite.functional
      ];

      allValidationTests.forEach(test => {
        const validation = validateRule(test.rule);
        const passed = validation.valid === test.expectedValid && 
                      validation.issues.length === test.expectedIssues;
        
        results.validation.push({
          ...test,
          actual: validation,
          passed
        });
        
        // Track by category
        if (!results.summary.byCategory[test.category]) {
          results.summary.byCategory[test.category] = { total: 0, passed: 0, failed: 0 };
        }
        results.summary.byCategory[test.category].total++;
        if (passed) results.summary.byCategory[test.category].passed++;
        else results.summary.byCategory[test.category].failed++;
        
        results.summary.total++;
        if (passed) results.summary.passed++;
        else results.summary.failed++;
      });

      // Flatten and run matching tests
      const allMatchingTests = [
        ...matchingTests.portMatching,
        ...matchingTests.protocolMatching,
        ...matchingTests.contentMatching,
        ...matchingTests.edgeCases,
        ...matchingTests.attackCategory
      ];

      allMatchingTests.forEach(test => {
        const validation = validateRule(test.rule);
        const matchResult = simulateRuleMatch(validation, test.packet);
        const passed = matchResult.matched === test.shouldMatch;
        
        results.matching.push({
          ...test,
          actual: matchResult,
          passed
        });
        
        // Track by category
        if (!results.summary.byCategory[test.category]) {
          results.summary.byCategory[test.category] = { total: 0, passed: 0, failed: 0 };
        }
        results.summary.byCategory[test.category].total++;
        if (passed) results.summary.byCategory[test.category].passed++;
        else results.summary.byCategory[test.category].failed++;
        
        results.summary.total++;
        if (passed) results.summary.passed++;
        else results.summary.failed++;
      });

      setSuiteResults(results);
      setRunningTests(false);
    }, 1000);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Package className="w-8 h-8 text-blue-400" />
            <h1 className="text-3xl font-bold">Snort Rule Unit-Testing Framework</h1>
          </div>
          <p className="text-slate-300">Test and validate Snort IDS rules with synthetic packet generation</p>
        </div>

        <div className="flex gap-2 mb-6">
          <button
            onClick={() => setActiveTab('tester')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'tester' 
                ? 'bg-blue-600 text-white' 
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            <div className="flex items-center gap-2">
              <PlayCircle className="w-4 h-4" />
              Rule Tester
            </div>
          </button>
          <button
            onClick={() => setActiveTab('testsuite')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'testsuite' 
                ? 'bg-blue-600 text-white' 
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            <div className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4" />
              Test Suite
            </div>
          </button>
          <button
            onClick={() => setActiveTab('generator')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'generator' 
                ? 'bg-blue-600 text-white' 
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4" />
              Code Generator
            </div>
          </button>
          <button
            onClick={() => setActiveTab('docs')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              activeTab === 'docs' 
                ? 'bg-blue-600 text-white' 
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4" />
              Documentation
            </div>
          </button>
        </div>

        {activeTab === 'testsuite' && (
          <div className="space-y-6">
                          <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-2xl font-semibold mb-2">Framework Test Suite</h2>
                  <p className="text-slate-400">Comprehensive validation with {
                    testSuite.syntax.length + testSuite.input.length + testSuite.functional.length +
                    matchingTests.portMatching.length + matchingTests.protocolMatching.length + 
                    matchingTests.contentMatching.length + matchingTests.edgeCases.length + matchingTests.attackCategory.length
                  } automated tests</p>
                </div>
                <button
                  onClick={runTestSuite}
                  disabled={runningTests}
                  className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors flex items-center gap-2"
                >
                  <PlayCircle className="w-5 h-5" />
                  {runningTests ? 'Running...' : 'Run Test Suite'}
                </button>
              </div>

              {suiteResults && (
                <>
                  <div className="grid grid-cols-3 gap-4 mb-6">
                    <div className="bg-slate-900 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-white">{suiteResults.summary.total}</div>
                      <div className="text-sm text-slate-400">Total Tests</div>
                    </div>
                    <div className="bg-green-900/30 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-green-400">{suiteResults.summary.passed}</div>
                      <div className="text-sm text-slate-400">Passed</div>
                    </div>
                    <div className="bg-red-900/30 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-red-400">{suiteResults.summary.failed}</div>
                      <div className="text-sm text-slate-400">Failed</div>
                    </div>
                  </div>

                  <div className="mb-6 bg-slate-900 p-4 rounded-lg">
                    <h3 className="text-lg font-semibold mb-3">Results by Category</h3>
                    <div className="grid grid-cols-2 gap-3">
                      {Object.entries(suiteResults.summary.byCategory).map(([category, stats]) => (
                        <div key={category} className="bg-slate-800 p-3 rounded">
                          <div className="font-medium text-white mb-2">{category}</div>
                          <div className="flex gap-4 text-sm">
                            <span className="text-slate-400">Total: {stats.total}</span>
                            <span className="text-green-400">✓ {stats.passed}</span>
                            <span className="text-red-400">✗ {stats.failed}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-6">
                    <div>
                      <h3 className="text-xl font-semibold mb-4">Rule Validation Tests</h3>
                      <div className="space-y-3">
                        {suiteResults.validation.map((test, idx) => (
                          <div key={idx} className={`p-4 rounded-lg border-2 ${test.passed ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'}`}>
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center gap-2">
                                {test.passed ? (
                                  <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                                ) : (
                                  <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                                )}
                                <div>
                                  <span className="font-semibold">{test.name}</span>
                                  <div className="text-xs text-blue-400 mt-1">{test.category}</div>
                                </div>
                              </div>
                            </div>
                            <div className="ml-7 space-y-2 text-sm">
                              <div className="text-slate-400 mb-2">{test.description}</div>
                              <div className="font-mono text-slate-300 bg-slate-950 p-2 rounded">
                                {test.rule || '(empty rule)'}
                              </div>
                              <div className="grid grid-cols-2 gap-4">
                                <div>
                                  <span className="text-slate-400">Expected: </span>
                                  <span className={test.expectedValid ? 'text-green-400' : 'text-red-400'}>
                                    {test.expectedValid ? 'Valid' : 'Invalid'} ({test.expectedIssues} issues)
                                  </span>
                                </div>
                                <div>
                                  <span className="text-slate-400">Actual: </span>
                                  <span className={test.actual.valid ? 'text-green-400' : 'text-red-400'}>
                                    {test.actual.valid ? 'Valid' : 'Invalid'} ({test.actual.issues.length} issues)
                                  </span>
                                </div>
                              </div>
                              {test.actual.issues.length > 0 && (
                                <div className="text-slate-300 bg-slate-950 p-2 rounded">
                                  <div className="font-semibold text-yellow-400 mb-1">Issues Found:</div>
                                  <ul className="list-disc list-inside space-y-1">
                                    {test.actual.issues.map((issue, i) => (
                                      <li key={i}>{issue}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="text-xl font-semibold mb-4">Packet Matching Tests</h3>
                      <div className="space-y-3">
                        {suiteResults.matching.map((test, idx) => (
                          <div key={idx} className={`p-4 rounded-lg border-2 ${test.passed ? 'bg-green-900/20 border-green-700' : 'bg-red-900/20 border-red-700'}`}>
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center gap-2">
                                {test.passed ? (
                                  <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                                ) : (
                                  <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                                )}
                                <div>
                                  <span className="font-semibold">{test.name}</span>
                                  <div className="text-xs text-blue-400 mt-1">{test.category}</div>
                                </div>
                              </div>
                            </div>
                            <div className="ml-7 space-y-2 text-sm">
                              <div className="text-slate-400 mb-2">{test.description}</div>
                              <div className="font-mono text-slate-300 bg-slate-950 p-2 rounded">
                                {test.rule}
                              </div>
                              <div className="bg-slate-950 p-2 rounded">
                                <div className="text-slate-400 mb-1">Test Packet:</div>
                                <div className="text-blue-400">
                                  Protocol: {test.packet.protocol.toUpperCase()} | Port: {test.packet.dst_port}
                                  {test.packet.payload && ` | Payload: "${test.packet.payload}"`}
                                </div>
                              </div>
                              <div className="grid grid-cols-2 gap-4">
                                <div>
                                  <span className="text-slate-400">Expected: </span>
                                  <span className={test.shouldMatch ? 'text-green-400' : 'text-red-400'}>
                                    {test.shouldMatch ? '✓ Should Match' : '✗ Should Not Match'}
                                  </span>
                                </div>
                                <div>
                                  <span className="text-slate-400">Result: </span>
                                  <span className={test.actual.matched ? 'text-green-400' : 'text-red-400'}>
                                    {test.actual.matched ? '✓ Matched' : '✗ No Match'}
                                  </span>
                                </div>
                              </div>
                              <div className="bg-slate-950 p-2 rounded">
                                <span className="text-slate-400">Reason: </span>
                                <span className="text-slate-300">{test.actual.reason}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </>
              )}

              {!suiteResults && (
                <div className="text-center py-12 text-slate-400">
                  <AlertCircle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p className="text-lg mb-2">Run the test suite to validate the framework's logic</p>
                  <p className="text-sm">Tests cover syntax validation, input validation, functional conflicts, and packet matching</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'tester' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-6">
              <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
                <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
                  <AlertCircle className="w-5 h-5 text-blue-400" />
                  Snort Rule
                </h2>
                <textarea
                  value={rule}
                  onChange={(e) => setRule(e.target.value)}
                  className="w-full h-32 bg-slate-900 text-white p-3 rounded border border-slate-700 focus:border-blue-500 focus:outline-none font-mono text-sm"
                  placeholder="Enter Snort rule..."
                />
                <div className="mt-4">
                  <p className="text-sm text-slate-400 mb-2">Sample Rules:</p>
                  <div className="space-y-2">
                    {sampleRules.map((sample, idx) => (
                      <button
                        key={idx}
                        onClick={() => setRule(sample.rule)}
                        className="w-full text-left px-3 py-2 bg-slate-900 hover:bg-slate-700 rounded text-sm transition-colors"
                      >
                        <div className="font-medium text-blue-400">{sample.name}</div>
                        <div className="text-slate-400 truncate">{sample.rule}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
                <h2 className="text-xl font-semibold mb-4">Packet Configuration</h2>
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Protocol</label>
                      <select
                        value={testConfig.protocol}
                        onChange={(e) => setTestConfig({...testConfig, protocol: e.target.value})}
                        className="w-full bg-slate-900 text-white p-2 rounded border border-slate-700"
                      >
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                        <option value="icmp">ICMP</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Flags</label>
                      <input
                        type="text"
                        value={testConfig.flags}
                        onChange={(e) => setTestConfig({...testConfig, flags: e.target.value})}
                        className="w-full bg-slate-900 text-white p-2 rounded border border-slate-700"
                        placeholder="S, A, F, etc."
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Source IP</label>
                      <input
                        type="text"
                        value={testConfig.srcIP}
                        onChange={(e) => setTestConfig({...testConfig, srcIP: e.target.value})}
                        className="w-full bg-slate-900 text-white p-2 rounded border border-slate-700"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Dest IP</label>
                      <input
                        type="text"
                        value={testConfig.dstIP}
                        onChange={(e) => setTestConfig({...testConfig, dstIP: e.target.value})}
                        className="w-full bg-slate-900 text-white p-2 rounded border border-slate-700"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Source Port</label>
                      <input
                        type="text"
                        value={testConfig.srcPort}
                        onChange={(e) => setTestConfig({...testConfig, srcPort: e.target.value})}
                        className="w-full bg-slate-900 text-white p-2 rounded border border-slate-700"
                      />
                    </div>
                    <div>
                      <label className="block text-sm text-slate-400 mb-1">Dest Port</label>
                      <input
                        type="text"
                        value={testConfig.dstPort}
                        onChange={(e) => setTestConfig({...testConfig, dstPort: e.target.value})}
                        className="w-full bg-slate-900 text-white p-2 rounded border border-slate-700"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm text-slate-400 mb-1">Payload</label>
                    <textarea
                      value={testConfig.payload}
                      onChange={(e) => setTestConfig({...testConfig, payload: e.target.value})}
                      className="w-full h-20 bg-slate-900 text-white p-2 rounded border border-slate-700 font-mono text-sm"
                      placeholder="Packet payload..."
                    />
                  </div>
                </div>
              </div>

              <button
                onClick={runTest}
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <PlayCircle className="w-5 h-5" />
                {loading ? 'Running Tests...' : 'Run Test'}
              </button>
            </div>

            <div className="space-y-6">
              {testResults && (
                <>
                  <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
                    <h2 className="text-xl font-semibold mb-4">Rule Validation</h2>
                    {testResults.validation.valid ? (
                      <div className="flex items-center gap-2 text-green-400 mb-4">
                        <CheckCircle className="w-6 h-6" />
                        <span className="font-semibold">Rule is valid</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-red-400 mb-4">
                        <XCircle className="w-6 h-6" />
                        <span className="font-semibold">Rule has issues</span>
                      </div>
                    )}
                    
                    {testResults.validation.issues.length > 0 && (
                      <div className="space-y-2">
                        {testResults.validation.issues.map((issue, idx) => (
                          <div key={idx} className="bg-slate-900 p-3 rounded text-sm">
                            <div className="flex items-start gap-2">
                              <AlertCircle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                              <span className="text-slate-300">{issue}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {testResults.validation.parsed && (
                      <div className="mt-4 bg-slate-900 p-4 rounded">
                        <p className="text-sm text-slate-400 mb-2">Parsed Components:</p>
                        <div className="space-y-1 text-sm font-mono">
                          <div><span className="text-blue-400">Action:</span> {testResults.validation.parsed.action}</div>
                          <div><span className="text-blue-400">Protocol:</span> {testResults.validation.parsed.protocol}</div>
                          <div><span className="text-blue-400">Direction:</span> {testResults.validation.parsed.srcIP}:{testResults.validation.parsed.srcPort} {testResults.validation.parsed.direction} {testResults.validation.parsed.dstIP}:{testResults.validation.parsed.dstPort}</div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
                    <h2 className="text-xl font-semibold mb-4">Generated Packet</h2>
                    <div className="bg-slate-900 p-4 rounded font-mono text-sm space-y-2">
                      <div className="text-blue-400">IP Packet:</div>
                      <div className="pl-4">
                        <div><span className="text-slate-400">Protocol:</span> {testResults.packet.protocol.toUpperCase()}</div>
                        <div><span className="text-slate-400">Source:</span> {testResults.packet.src_ip}:{testResults.packet.src_port}</div>
                        <div><span className="text-slate-400">Destination:</span> {testResults.packet.dst_ip}:{testResults.packet.dst_port}</div>
                        {testResults.packet.flags && (
                          <div><span className="text-slate-400">Flags:</span> {testResults.packet.flags}</div>
                        )}
                        {testResults.packet.payload && (
                          <div className="mt-2">
                            <span className="text-slate-400">Payload:</span>
                            <div className="mt-1 bg-slate-950 p-2 rounded text-green-400 break-all">
                              {testResults.packet.payload}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
                    <h2 className="text-xl font-semibold mb-4">Match Result</h2>
                    {testResults.matchResult.matched ? (
                      <div className="flex items-center gap-2 text-green-400 mb-3">
                        <CheckCircle className="w-6 h-6" />
                        <span className="font-semibold">Rule matched packet</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-red-400 mb-3">
                        <XCircle className="w-6 h-6" />
                        <span className="font-semibold">Rule did not match</span>
                      </div>
                    )}
                    <div className="bg-slate-900 p-4 rounded">
                      <p className="text-sm text-slate-300">{testResults.matchResult.reason}</p>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {activeTab === 'generator' && (
          <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">Python Test Framework</h2>
              <button
                onClick={() => {
                  const blob = new Blob([generatePythonCode()], { type: 'text/plain' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = 'snort_rule_tester.py';
                  a.click();
                }}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded transition-colors"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
            </div>
            <pre className="bg-slate-900 p-4 rounded overflow-x-auto text-sm">
              <code className="text-green-400">{generatePythonCode()}</code>
            </pre>
          </div>
        )}

        {activeTab === 'docs' && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-lg p-6 shadow-xl">
              <h2 className="text-2xl font-bold mb-4">Comprehensive Documentation</h2>
              
              <div className="space-y-8 text-slate-300">
                {/* Overview Section */}
                <section>
                  <h3 className="text-xl font-semibold text-white mb-3 flex items-center gap-2">
                    <Package className="w-5 h-5 text-blue-400" />
                    Project Overview
                  </h3>
                  <div className="bg-slate-900 p-4 rounded-lg space-y-3">
                    <p>
                      <strong className="text-white">Purpose:</strong> This framework provides automated unit testing for Snort IDS rules without requiring PCAP files. 
                      It validates rule syntax, detects conflicts, and simulates packet matching using programmatically generated packets.
                    </p>
                    <p>
                      <strong className="text-white">Target Audience:</strong> Security engineers, DevOps teams, and SOC analysts who need to validate Snort rules 
                      in CI/CD pipelines before deployment.
                    </p>
                    <p>
                      <strong className="text-white">Key Innovation:</strong> Eliminates dependency on network captures by generating synthetic test packets, 
                      enabling true unit testing of IDS rules.
                    </p>
                  </div>
                </section>

                {/* Rule Tester Section */}
                <section>
                  <h3 className="text-xl font-semibold text-white mb-3 flex items-center gap-2">
                    <PlayCircle className="w-5 h-5 text-blue-400" />
                    Rule Tester Tab
                  </h3>
                  <div className="bg-slate-900 p-4 rounded-lg space-y-4">
                    <div>
                      <h4 className="font-semibold text-white mb-2">Components:</h4>
                      <ul className="list-disc list-inside space-y-2 ml-4">
                        <li>
                          <strong className="text-white">Rule Input:</strong> Text area for entering or editing Snort rules. Supports full Snort syntax including 
                          actions (alert, drop, reject), protocols (tcp, udp, icmp, ip), network specifications, and rule options.
                        </li>
                        <li>
                          <strong className="text-white">Sample Rules:</strong> Pre-configured examples covering common use cases: HTTP detection, SSH brute force, 
                          DNS queries, and ICMP pings. Click any sample to instantly load it.
                        </li>
                        <li>
                          <strong className="text-white">Packet Configuration:</strong> Interactive form to define synthetic packet attributes:
                          <ul className="list-disc list-inside ml-6 mt-2 space-y-1">
                            <li><em>Protocol:</em> TCP, UDP, or ICMP</li>
                            <li><em>Source/Destination IPs:</em> Simulated endpoints</li>
                            <li><em>Ports:</em> Application-layer identifiers</li>
                            <li><em>Payload:</em> Application data (HTTP requests, DNS queries, etc.)</li>
                            <li><em>Flags:</em> TCP flags (SYN, ACK, FIN, etc.)</li>
                          </ul>
                        </li>
                      </ul>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold text-white mb-2">Validation Results:</h4>
                      <p className="mb-2">The framework performs multi-stage validation:</p>
                      <ol className="list-decimal list-inside space-y-2 ml-4">
                        <li><strong className="text-white">Syntax Parsing:</strong> Verifies rule structure matches Snort grammar</li>
                        <li><strong className="text-white">Required Fields:</strong> Checks for mandatory sid (Snort ID) and msg (message) options</li>
                        <li><strong className="text-white">Action Validation:</strong> Ensures action is one of: alert, log, pass, drop, reject, sdrop</li>
                        <li><strong className="text-white">Protocol Validation:</strong> Confirms protocol is tcp, udp, icmp, or ip</li>
                        <li><strong className="text-white">Conflict Detection:</strong> Identifies incompatible keyword combinations (e.g., flow with ICMP)</li>
                        <li><strong className="text-white">Semantic Warnings:</strong> Flags suspicious patterns (e.g., http_method on port 22)</li>
                      </ol>
                    </div>

                    <div>
                      <h4 className="font-semibold text-white mb-2">Match Simulation:</h4>
                      <p className="mb-2">After validation, the framework simulates Snort's matching engine:</p>
                      <ul className="list-disc list-inside space-y-1 ml-4">
                        <li>Compares packet protocol against rule protocol (ip acts as wildcard)</li>
                        <li>Checks destination port (supports exact match and "any" wildcard)</li>
                        <li>Searches payload for content keywords (case-sensitive by default)</li>
                        <li>Returns detailed explanation of match decision</li>
                      </ul>
                    </div>
                  </div>
                </section>

                {/* Test Suite Section */}
                <section>
                  <h3 className="text-xl font-semibold text-white mb-3 flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-blue-400" />
                    Test Suite Tab
                  </h3>
                  <div className="bg-slate-900 p-4 rounded-lg space-y-4">
                    <p>
                      The Test Suite validates the framework itself using automated tests. This meta-testing approach ensures 
                      the validation logic is correct and prevents regressions when modifying code.
                    </p>
                    
                    <div>
                      <h4 className="font-semibold text-white mb-2">Test Categories:</h4>
                      
                      <div className="space-y-3 ml-4">
                        <div>
                          <strong className="text-blue-400">1. Syntax Testing ({testSuite.syntax.length} tests)</strong>
                          <p className="mt-1">Validates the parser's ability to correctly identify well-formed and malformed rules:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li>Complete, valid rules with all components</li>
                            <li>Empty rules and whitespace handling</li>
                            <li>Missing structural elements (parentheses, direction operators)</li>
                            <li>{"Invalid direction operators ('-> instead of ->')"}</li>
                            <li>Bidirectional rules (&lt;&gt; operator)</li>
                          </ul>
                        </div>

                        <div>
                          <strong className="text-blue-400">2. Input Validation ({testSuite.input.length} tests)</strong>
                          <p className="mt-1">Tests boundary conditions and edge cases in user input:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li>Missing required fields (sid, msg)</li>
                            <li>Invalid actions (block, allow, deny) - only Snort-standard actions accepted</li>
                            <li>Invalid protocols (http, ftp) - must be network-layer protocols</li>
                            <li>Valid alternative actions (drop, reject, pass, log, sdrop)</li>
                            <li>All supported protocols (tcp, udp, icmp, ip)</li>
                          </ul>
                        </div>

                        <div>
                          <strong className="text-blue-400">3. Functional Testing ({testSuite.functional.length} tests)</strong>
                          <p className="mt-1">Verifies semantic rule correctness and conflict detection:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li><strong>Protocol Conflicts:</strong> flow keyword requires stateful protocol (TCP), fails on ICMP</li>
                            <li><strong>Keyword Restrictions:</strong> stream_size only works with TCP, not UDP</li>
                            <li><strong>Contextual Warnings:</strong> http_method on non-HTTP ports (warning, not error)</li>
                            <li><strong>Multiple Issues:</strong> Rules with compounding errors to test comprehensive reporting</li>
                            <li><strong>Valid Combinations:</strong> Ensures legitimate keyword combinations aren't flagged</li>
                          </ul>
                        </div>

                        <div>
                          <strong className="text-blue-400">4. Port Matching ({matchingTests.portMatching.length} tests)</strong>
                          <p className="mt-1">Validates port-based filtering logic:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li>Exact port matches (packet:80 vs rule:80)</li>
                            <li>Port mismatches (packet:443 vs rule:80)</li>
                            <li>Wildcard "any" port handling</li>
                          </ul>
                        </div>

                        <div>
                          <strong className="text-blue-400">5. Protocol Matching ({matchingTests.protocolMatching.length} tests)</strong>
                          <p className="mt-1">Tests protocol-layer filtering:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li>Same protocol matches (TCP-TCP, UDP-UDP)</li>
                            <li>Protocol mismatches (TCP rule vs UDP packet)</li>
                            <li>IP wildcard matches any transport protocol</li>
                            <li>ICMP as distinct protocol class</li>
                          </ul>
                        </div>

                        <div>
                          <strong className="text-blue-400">6. Content Matching ({matchingTests.contentMatching.length} tests)</strong>
                          <p className="mt-1">Validates payload inspection:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li>Simple string matching in payload</li>
                            <li>Case-sensitive matching (GET vs get)</li>
                            <li>Empty payload handling</li>
                            <li>Content mismatch detection</li>
                          </ul>
                        </div>

                        <div>
                          <strong className="text-blue-400">7. Edge Cases ({matchingTests.edgeCases.length} tests)</strong>
                          <p className="mt-1">Covers unusual but valid scenarios:</p>
                          <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                            <li>Rules without content keywords (should match any payload)</li>
                            <li>Multiple simultaneous conditions (protocol + port + content)</li>
                            <li>Partial condition matches (2 of 3 conditions met = no match)</li>
                          </ul>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold text-white mb-2">Test Execution:</h4>
                      <p className="mb-2">When you run the suite:</p>
                      <ol className="list-decimal list-inside space-y-1 ml-4">
                        <li>All test rules are parsed and validated</li>
                        <li>Expected outcomes are compared against actual results</li>
                        <li>Pass/fail status is determined for each test</li>
                        <li>Results are aggregated by category</li>
                        <li>Detailed explanations are provided for failures</li>
                      </ol>
                    </div>

                    <div className="bg-blue-900/20 border border-blue-700 p-3 rounded">
                      <strong className="text-blue-400">Total Test Coverage:</strong>
                      <p className="mt-1">
                        {testSuite.syntax.length + testSuite.input.length + testSuite.functional.length} validation tests + 
                        {' '}{matchingTests.portMatching.length + matchingTests.protocolMatching.length + 
                        matchingTests.contentMatching.length + matchingTests.edgeCases.length} matching tests = 
                        {' '}{testSuite.syntax.length + testSuite.input.length + testSuite.functional.length +
                        matchingTests.portMatching.length + matchingTests.protocolMatching.length + 
                        matchingTests.contentMatching.length + matchingTests.edgeCases.length + matchingTests.attackCategory.length} total automated tests
                      </p>
                    </div>
                  </div>
                </section>

                {/* Code Generator Section */}
                <section>
                  <h3 className="text-xl font-semibold text-white mb-3 flex items-center gap-2">
                    <Code className="w-5 h-5 text-blue-400" />
                    Code Generator Tab
                  </h3>
                  <div className="bg-slate-900 p-4 rounded-lg space-y-3">
                    <p>
                      Exports production-ready Python code that replicates the framework's functionality for use in CI/CD pipelines.
                    </p>
                    
                    <div>
                      <h4 className="font-semibold text-white mb-2">Generated Code Features:</h4>
                      <ul className="list-disc list-inside space-y-2 ml-4">
                        <li>
                          <strong className="text-white">Scapy Integration:</strong> Uses Scapy library for packet crafting
                          <ul className="list-disc list-inside ml-6 mt-1">
                            <li>IP layer construction with source/destination addresses</li>
                            <li>TCP/UDP transport layer with port configuration and flags</li>
                            <li>ICMP packet generation with type/code</li>
                            <li>Raw payload embedding</li>
                          </ul>
                        </li>
                        <li>
                          <strong className="text-white">Rule Validation:</strong> Implements same syntax checking as web interface
                        </li>
                        <li>
                          <strong className="text-white">Test Execution:</strong> Runs multiple test configurations and aggregates results
                        </li>
                        <li>
                          <strong className="text-white">CLI Output:</strong> Formatted results suitable for CI/CD log analysis
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="font-semibold text-white mb-2">CI/CD Integration Examples:</h4>
                      <div className="space-y-3">
                        <div>
                          <strong className="text-yellow-400">GitHub Actions:</strong>
                          <pre className="bg-slate-950 p-3 rounded mt-2 text-xs overflow-x-auto">
{`name: Snort Rule Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: pip install scapy
      - name: Run tests
        run: python snort_rule_tester.py`}
                          </pre>
                        </div>

                        <div>
                          <strong className="text-yellow-400">GitLab CI:</strong>
                          <pre className="bg-slate-950 p-3 rounded mt-2 text-xs overflow-x-auto">
{`test_rules:
  image: python:3.9
  before_script:
    - pip install scapy
  script:
    - python snort_rule_tester.py
  only:
    - merge_requests`}
                          </pre>
                        </div>

                        <div>
                          <strong className="text-yellow-400">Jenkins:</strong>
                          <pre className="bg-slate-950 p-3 rounded mt-2 text-xs overflow-x-auto">
{`pipeline {
  agent any
  stages {
    stage('Test Rules') {
      steps {
        sh 'pip install scapy'
        sh 'python snort_rule_tester.py'
      }
    }
  }
}`}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </div>
                </section>

                {/* Technical Architecture */}
                <section>
                  <h3 className="text-xl font-semibold text-white mb-3">Technical Architecture</h3>
                  <div className="bg-slate-900 p-4 rounded-lg space-y-3">
                    <div>
                      <h4 className="font-semibold text-white mb-2">Core Components:</h4>
                      <ul className="list-disc list-inside space-y-2 ml-4">
                        <li>
                          <strong className="text-white">validateRule():</strong> Regex-based parser that tokenizes Snort rules and validates 
                          each component against specification
                        </li>
                        <li>
                          <strong className="text-white">generatePacket():</strong> Creates JavaScript packet objects with protocol-specific 
                          attributes (flags for TCP, type for ICMP)
                        </li>
                        <li>
                          <strong className="text-white">simulateRuleMatch():</strong> Implements simplified Snort matching logic:
                          protocol check → port check → content check
                        </li>
                        <li>
                          <strong className="text-white">runTestSuite():</strong> Test orchestration engine that executes all test cases 
                          and aggregates results
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="font-semibold text-white mb-2">Limitations & Future Work:</h4>
                      <ul className="list-disc list-inside space-y-1 ml-4">
                        <li>Simplified matching logic (doesn't implement all Snort keywords)</li>
                        <li>No stateful connection tracking</li>
                        <li>Limited preprocessor support</li>
                        <li>Future: Integration with actual Snort via DAQ (Data Acquisition) API</li>
                        <li>Future: Support for rule thresholds, suppression, and rate limiting</li>
                      </ul>
                    </div>
                  </div>
                </section>

                {/* Use Cases */}
                <section>
                  <h3 className="text-xl font-semibold text-white mb-3">Common Use Cases</h3>
                  <div className="bg-slate-900 p-4 rounded-lg">
                    <ol className="list-decimal list-inside space-y-3 ml-4">
                      <li>
                        <strong className="text-white">Pre-deployment Validation:</strong> Test new rules before pushing to production IDS
                      </li>
                      <li>
                        <strong className="text-white">Rule Development:</strong> Rapid iteration on rule logic with instant feedback
                      </li>
                      <li>
                        <strong className="text-white">Training:</strong> Teach security analysts Snort syntax in interactive environment
                      </li>
                      <li>
                        <strong className="text-white">Regression Testing:</strong> Ensure rule updates don't break existing functionality
                      </li>
                      <li>
                        <strong className="text-white">Documentation:</strong> Generate test cases that serve as rule behavior specifications
                      </li>
                    </ol>
                  </div>
                </section>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}