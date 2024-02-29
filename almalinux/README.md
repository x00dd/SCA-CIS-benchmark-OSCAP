# Changes compared to Wazuh SCA ruleset

**32500:**

*Previous checks:*
```
condition: all  
rules:  
- "c:modprobe -n -v squashfs -> r:install /bin/false|Module  squashfs  not found"  
- "not  c:lsmod -> r:squashfs"  
- 'd:/etc/modprobe.d -> r:\.*.conf -> r:blacklist\t*\s*squashfs'
```
*Updated checks:*
```
condition: all  
rules:  
- "c:modprobe -n -v squashfs -> r:install /bin/false|install /bin/true|Module  squashfs  not found"  
- "not  c:lsmod -> r:squashfs"  
- 'd:/etc/modprobe.d -> r:\.*.conf -> r:install\t*\s*squashfs\t*\s*/bin/true'
```
*Explanation:*

Both “/bin/false” and “/bin/true” produce the  same  hardening  results. However, “/bin/false” returns a non-zero exit code and /bin/true a zero exit code. Both of the  rules in modprobe  will  result in disabled  squashfs.

**32501:**

*Previous checks:*
```
condition: all  
rules:  
- "c:modprobe -n -v udf -> r:install /bin/false|Module  udf  not found"  
- "not  c:lsmod -> r:udf"  
- 'd:/etc/modprobe.d -> r:\.*.conf -> r:blacklist\t*\s*udf'
```
*Updated checks:*
```
condition: all  
rules:  
- "c:modprobe -n -v udf -> r:install /bin/false|install /bin/true|Module  udf  not found"  
- "not  c:lsmod -> r:udf"  
- 'd:/etc/modprobe.d -> r:\.*.conf -> r:install\t*\s*udf\t*\s*/bin/true'
```
*Explanation:*

Both “/bin/false” and “/bin/true” produce the  same  hardening  results. However, “/bin/false” returns a non-zero exit code and /bin/true a zero exit code. Both of the  rules in modprobe  will  result in disabled  udf  filesystems.

**32531**

*Previous checks:*
```
condition: all
    rules:
      - "c:systemctl is-enabled aidecheck.service -> r:^enable"
      - "c:systemctl is-enabled aidecheck.timer -> r:^enable"
      - "c:systemctl status aidecheck.service -> r:active"

```
*Updated checks:*
```
condition: any
    rules:
      - "f:/etc/crontab -> r:/usr/sbin/aide --check"
```
*Explanation:*
There are different methods to implement this hardening rule. OpenSCAP uses crontab to look for the “/usr/sbin/aide –check” statement in /etc/crontab. SCA doesn’t look at this file. 

**32534:**

*Previous checks:*
```
condition: all  
rules:  
- 'c:stat -L /boot/grub2/grub.cfg -> r:Access:\s*\(0700/-r--------\)\s*Uid:\s*\(\s*\t*0/\s*\t*root\)\s*\t*Gid:\s*\(\s*\t*0/\s*\t*root\)'  
- 'c:stat -L /boot/grub2/grubenv -> r:Access:\s*\(0600/-r--------\)\s*Uid:\s*\(\s*\t*0/\s*\t*root\)\s*\t*Gid:\s*\(\s*\t*0/\s*\t*root\)'  
- 'c:stat -L /boot/grub2/user.cfg -> r:Access:\s*\(0600/-r--------\)\s*Uid:\s*\(\s*\t*0/\s*\t*root\)\s*\t*Gid:\s*\(\s*\t*0/\s*\t*root\)'  
```
*Updated checks:*
```
condition: all  
rules:  
- 'c:stat -Lc "%n %#a %u/%U %g/%G" /boot/grub2/grub.cfg -> r:/boot/grub2/grub.cfg 0600 0/root 0/root'  
- 'c:stat -Lc "%n %#a %u/%U %g/%G" /boot/grub2/grubenv -> r:/boot/grub2/grubenv 0600 0/root 0/root'  
- 'c:stat -Lc "%n %#a %u/%U %g/%G" /boot/grub2/user.cfg -> r:/boot/grub2/user.cfg 0600 0/root 0/root|No  such file or directory'  
```
*Explanation:*

The rights 0600 will  not match with “-r———” because  it is read/write, besides checks in CIS Benchmark don’t  give output in the form of “-r———”, because stat is used  with  other  flags.

Also  the  user.cfg is not  always present, so  it checks if  the file exists.

**32552:**

*Previous checks:*
```
condition: all  
rules:  
- "f:/etc/dconf/profile/gdm"  
- "f:/etc/dconf/profile/gdm -> r:user-db:user"  
- "f:/etc/dconf/profile/gdm -> r:system-db:gdm"  
- "f:/etc/dconf/profile/gdm -> r:file-db:/usr/share/gdm/greeter-dconf-defaults"  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-enable=true'  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-text='  
```
*Updated checks:*
```
condition: all  
rules:  
- "f:/etc/dconf/profile/gdm -> r:user-db:user"  
- "f:/etc/dconf/profile/gdm -> r:system-db:gdm"  
- "f:/etc/dconf/profile/gdm -> r:file-db:/usr/share/gdm/greeter-dconf-defaults"  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-enable=true'  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-text='  
```
*Explanation:*

This  would  always  result in a failed  condition  when GDM is not  installed. Removing  this line would  cause  it  to return a “not  applicable” as it  should.

**32553:**

*Previous checks:*
```
condition: all  
rules:  
- "f:/etc/dconf/profile/gdm"  
- "f:/etc/dconf/profile/gdm -> r:user-db:user"  
- "f:/etc/dconf/profile/gdm -> r:system-db:gdm"  
- "f:/etc/dconf/profile/gdm -> r:file-db:/usr/share/gdm/greeter-dconf-defaults"  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-enable=true'  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-text='  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:disable-user-list=true'
```
*Updated checks:*
```
condition: all  
rules:  
- "f:/etc/dconf/profile/gdm -> r:user-db:user"  
- "f:/etc/dconf/profile/gdm -> r:system-db:gdm"  
- "f:/etc/dconf/profile/gdm -> r:file-db:/usr/share/gdm/greeter-dconf-defaults"  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-enable=true'  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:banner-message-text='  
- 'd:/etc/dconf/db/gdm.d -> r:\.+ -> r:disable-user-list=true'  
```
*Explanation:*

This  would  always  result in a failed  condition  when GDM is not  installed. Removing  this line would  cause  it  to return a “not  applicable” as it  should.

**32554:**

*Previous checks:*
```
condition: all  
rules:  
- "f:/etc/dconf/profile/gdm"  
- "f:/etc/dconf/profile/gdm -> r:user-db:user"  
- "f:/etc/dconf/profile/gdm -> r:system-db:gdm"  
- 'd:/etc/dconf/db/local.d -> r:\.+ -> r:lock-delay=uint32'
```
*Updated checks:*
```
condition: all  
rules:  
- "f:/etc/dconf/profile/gdm -> r:user-db:user"  
- "f:/etc/dconf/profile/gdm -> r:system-db:gdm"  
- 'd:/etc/dconf/db/local.d -> r:\.+ -> r:lock-delay=uint32'
```
*Explanation:*

This  would  always  result in a failed  condition  when GDM is not  installed. Removing  this line would  cause  it  to return a “not  applicable” as it  should.

**32558:**

*Previous checks:*
```
condition: all  
rules:  
- 'f:/etc/crypto-policies/config -> r:^\s*LEGACY'
```
*Updated checks:*
```
condition: all  
rules:  
- 'f:/etc/crypto-policies/config -> !r:^\s*LEGACY'
```
*Explanation:*

Currently  it checks if  the  LEGACY string is present in the  configuration file. When  enforcing CIS Benchmark Level 2, it  states  that  the  LEGACY string  should NOT be present. It should  be  configured as DEFAULT, FUTURE or FIPS. LEGACY contains  to  many  weak  cryptographic  algorithms.

**32560:**

*Previous checks:*
```
- id: 32560
    title: "Ensure chrony is configured."
    description: "chrony is a daemon which implements the Network Time Protocol (NTP) and is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server."
    rationale: "If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
    remediation: 'Add or edit server or pool lines to /etc/chrony.conf as appropriate: server <remote-server> Add or edit the OPTIONS in /etc/sysconfig/chronyd to include ''-u chrony'': OPTIONS="-u chrony".'
    compliance:
      - cis: ["2.1.2"]
      - cis_csc_v8: ["8.4"]
      - cis_csc_v7: ["6.1"]
      - cmmc_v2.0: ["AU.L2-3.3.7"]
      - iso_27001-2013: ["A.12.4.4"]
      - mitre_mitigations: ["M1022"]
      - mitre_tactics: ["TA0002"]
      - mitre_techniques: ["T1070", "T1070.002"]
      - nist_sp_800-53: ["AU-7"]
      - pci_dss_v3.2.1: ["10.4"]
      - pci_dss_v4.0: ["10.6", "10.6.1", "10.6.2", "10.6.3"]
      - soc_2: ["CC4.1", "CC5.2"]
    condition: all
    rules:
      - "f:/etc/chrony.conf"
      - 'f:/etc/chrony.conf -> r:^\s*\t*server|^\s*\t*pool'
      - 'f:/etc/sysconfig/chronyd -> r:^\s*\t*OPTIONS\.*-u chrony'

```
*Updated checks:*
```
- id: 32560
    title: "A remote time server for Chrony is configured"
    description: "chrony is a daemon which implements the Network Time Protocol (NTP) and is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server."
    rationale: "If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
    remediation: 'Add or edit server or pool lines to /etc/chrony.conf as appropriate: server <remote-server>.'
    compliance:
      - cis: ["2.1.2"]
      - cis_csc_v8: ["8.4"]
      - cis_csc_v7: ["6.1"]
      - cmmc_v2.0: ["AU.L2-3.3.7"]
      - iso_27001-2013: ["A.12.4.4"]
      - mitre_mitigations: ["M1022"]
      - mitre_tactics: ["TA0002"]
      - mitre_techniques: ["T1070", "T1070.002"]
      - nist_sp_800-53: ["AU-7"]
      - pci_dss_v3.2.1: ["10.4"]
      - pci_dss_v4.0: ["10.6", "10.6.1", "10.6.2", "10.6.3"]
      - soc_2: ["CC4.1", "CC5.2"]
    condition: all
    rules:
      - 'f:/etc/chrony.conf -> r:^\s*\t*server|^\s*\t*pool'

  - id: 39999
    title: "Ensure that chronyd is running under chrony user account"
    description: "chrony is a daemon which implements the Network Time Protocol (NTP) and is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server."
    rationale: "If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
    remediation: 'Add or edit the OPTIONS in /etc/sysconfig/chronyd to include ''-u chrony'': OPTIONS="-u chrony".'
    compliance:
      - cis: ["2.1.2"]
      - cis_csc_v8: ["8.4"]
      - cis_csc_v7: ["6.1"]
      - cmmc_v2.0: ["AU.L2-3.3.7"]
      - iso_27001-2013: ["A.12.4.4"]
      - mitre_mitigations: ["M1022"]
      - mitre_tactics: ["TA0002"]
      - mitre_techniques: ["T1070", "T1070.002"]
      - nist_sp_800-53: ["AU-7"]
      - pci_dss_v3.2.1: ["10.4"]
      - pci_dss_v4.0: ["10.6", "10.6.1", "10.6.2", "10.6.3"]
      - soc_2: ["CC4.1", "CC5.2"]
    condition: any
    rules:
      - 'f:/etc/sysconfig/chronyd -> r:^\s*\t*OPTIONS\.*-u chrony'
      - 'f:/etc/sysconfig/chronyd -> !r:-u'

```
*Explanation:*
OpenSCAP doesn’t add the ‘-u chrony’ flag, instead it makes sure it isn’t present which automatically means chrony will use the chrony user by default. Because we couldn’t get it to work In one SCA rule we decided to split it into two separate rules, which is also what OpenSCAP has done. 

**32585:**

*Previous checks:*
```
condition: any
    rules:
      - "c:rpm -q firewalld -> r:^package firewalld is not installed"
      - "not c:firewall-cmd --state -> r:^running"
      - "c:systemctl is-enabled firewalld -> r:^masked"
```

*Updated checks:*
```
condition: any
    rules:
      - "c:rpm -q nftables -> r:^package nftables is not installed"
      - "c:systemctl is-enabled nftables -> r:^masked"
```

*Explanation:*
According to the CIS Benchmark a single firewall utility should be used, oscap chooses firewalld. Hence, the check is changed accordingly.

**32588:**

*Previous checks:*
```
 - id: 32588
    title: "Ensure nftables default deny firewall policy."
    description: "Base chain policy is the default verdict that will be applied to packets reaching the end of the chain."
    rationale: "There are two policies: accept (Default) and drop. If the policy is set to accept, the firewall will accept any packet that is not configured to be denied and the packet will continue traversing the network stack. It is easier to explicitly permit acceptable usage than to deny unacceptable usage. Note: Changing firewall settings while connected over the network can result in being locked out of the system."
    impact: "If configuring nftables over ssh, creating a base chain with a policy of drop will cause loss of connectivity. Ensure that a rule allowing ssh has been added to the base chain prior to setting the base chain's policy to drop."
    remediation: "If NFTables utility is in use on your system: Run the following command for the base chains with the input, forward, and output hooks to implement a default DROP policy: # nft chain <table family> <table name> <chain name> { policy drop \\; } Example: # nft chain inet filter input { policy drop \\; } # nft chain inet filter forward { policy drop \\; }."
    compliance:
      - cis: ["3.4.2.7"]
      - cis_csc_v8: ["4.4"]
      - cis_csc_v7: ["9.4"]
      - cmmc_v2.0: ["AC.L1-3.1.20", "CM.L2-3.4.7", "SC.L1-3.13.1", "SC.L2-3.13.6"]
      - iso_27001-2013: ["A.13.1.1"]
      - nist_sp_800-53: ["CA-9"]
      - pci_dss_v3.2.1: ["1.1.4", "1.3.1"]
      - pci_dss_v4.0: ["1.2.1", "1.4.1"]
      - soc_2: ["CC6.6"]
    condition: all
    rules:
      - "c:nft list ruleset -> r:hook input && r:policy drop"
      - "c:nft list ruleset -> r:hook forward && r:policy drop"
      - "c:nft list ruleset -> r:hook output && r:policy drop"
```
*Updated checks:*
```
 - id: 32588
    title: "Ensure firewalld default zone is set."
    description: "A firewall zone defines the trust level for a connection, interface or source address
binding. This is a one to many relation, which means that a connection, interface or
source can only be part of one zone, but a zone can be used for many network
connections, interfaces and sources.
•
•
•
The default zone is the zone that is used for everything that is not explicitly
bound/assigned to another zone.
If no zone assigned to a connection, interface or source, only the default zone is
used.
The default zone is not always listed as being used for an interface or source as
it will be used for it either way. This depends on the manager of the interfaces."
    rationale: "Because the default zone is the zone that is used for everything that is not explicitly
bound/assigned to another zone, if FirewallD is being used, it is important for the default
zone to set"
    remediation: "Set DefaultZone=drop in /etc/firewalld/firewalld.conf."
    compliance:
      - cis: ["3.4.2.1"]
    condition: all
    rules:
      - "f:/etc/firewalld/firewalld.conf -> r:^DefaultZone=drop"
```

*Explanation:*
 Oscap choses to work with firewalld instead of nftables, so the rule must be check if firewalld’s defaultzone is set to drop. 

**32596:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sudoers && r:-p wa && r:-k scope|key=\\s*\t*scope'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sudoers.d && r:-p wa && r:-k scope|key=\\s*\t*scope'
      - 'c:auditctl -l -> r:^-w && r:/etc/sudoers && r:-p wa && r:-k scope|key=\\s*\t*scope'
      - 'c:auditctl -l -> r:^-w && r:/etc/sudoers.d && r:-p wa && r:-k scope|key=\\s*\t*scope'

```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sudoers && r:-p wa && r:-k actions|key=\\s*\t*actions'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sudoers.d && r:-p wa && r:-k actions|key=\\s*\t*actions'
      - 'c:auditctl -l -> r:^-w && r:/etc/sudoers && r:-p wa && r:-k actions|key=\\s*\t*actions'
      - 'c:auditctl -l -> r:^-w && r:/etc/sudoers.d && r:-p wa && r:-k actions|key=\\s*\t*actions'

```

*Explanation:*
The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses actions as key instead of scope. 

**32597:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-C euid!=uid|-C uid!=euid  && r:-F auid!=unset|-F auid!=1|-F auid!=4294967295 && r:-S execve && r:-k user_emulation|key=user_emulation'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-C euid!=uid|-C uid!=euid  && r:-F auid!=unset|-F auid!=1|-F auid!=4294967295 && r:-S execve && r:-k user_emulation|key=user_emulation'
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-C euid!=uid|-C uid!=euid && r:-F auid!=unset|-F auid!=1|-F auid!=4294967295 && r:-S execve && r:-k user_emulation|key=user_emulation"
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-C euid!=uid|-C uid!=euid && r:-F auid!=unset|-F auid!=1|-F auid!=4294967295 && r:-S execve && r:-k user_emulation|key=user_emulation"

```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-S execve && r:-C euid!=uid|-C uid!=euid  && r:-F auid!=unset|-F auid!=1|-F auid!=-1|-F auid!=4294967295 && r:-k user_emulation|key=user_emulation'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-S execve && r:-C euid!=uid|-C uid!=euid  && r:-F auid!=unset|-F auid!=1|-F auid!=-1|-F auid!=4294967295 && r:-k user_emulation|key=user_emulation'
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-S execve && r:-C euid!=uid|-C uid!=euid && r:-F auid!=unset|-F auid!=1|-F auid!=-1|-F auid!=4294967295 && r:-k user_emulation|key=user_emulation"
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-S execve && r:-C euid!=uid|-C uid!=euid && r:-F auid!=unset|-F auid!=1|-F auid!=-1|-F auid!=4294967295 && r:-k user_emulation|key=user_emulation"

```

*Explanation:*
CIS Benchmark checks for ‘-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation’ and oscap for ‘-a always,exit -F arch=b32 -S execve -C euid!=uid -F auid!=unset -k user_emulation’ which is a slightly different order but the result is the same. 

**32598:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S && r:adjtimex && r:settimeofday && r:clock_settime && r:-k time-change|key=time-change'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S && r:adjtimex && r:settimeofday && r:clock_settime && r:-k time-change|key=time-change'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/localtime && r:-p wa && r:-k time-change|key=time-change'
      - "c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S && r:adjtimex && r:settimeofday && r:clock_settime && r:-k time-change|key=time-change"
      - "c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S && r:adjtimex && r:settimeofday && r:clock_settime && r:-k time-change|key=time-change"
      - "c:auditctl -l -> r:^-w && r:/etc/localtime && r:-p wa && r:-k time-change|key=time-change"
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S && r:stime && r:adjtimex && r:settimeofday && r:-k audit_time_rules|key=audit_time_rules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S && r:clock_settime && r:-k time-change|key=time-change'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S && r:clock_settime && r:-k time-change|key=time-change'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S && r:adjtimex && r:settimeofday && r:-k audit_time_rules|key=audit_time_rules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/localtime && r:-p wa && r:-k audit_time_rules|key=audit_time_rules'
      - "c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:stime && r:-S && r:adjtimex && r:settimeofday && r:-k audit_time_rules|key=audit_time_rules"
      - "c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S && r:clock_settime && r:-k time-change|key=time-change"
      - "c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S && r:clock_settime && r:-k time-change|key=time-change"
      - "c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S && r:adjtimex && r:settimeofday && r:-k audit_time_rules|key=audit_time_rules"
      - "c:auditctl -l -> r:^-w && r:/etc/localtime && r:-p wa && r:-k audit_time_rules|key=audit_time_rules"
```

*Explanation:*
The CIS Benchmark uses bigger rules to perform the hardening, oscap uses more individual rules. Also the –k options is different in oscap (time-change, audit_time_rules). 

**32599:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-S && r:sethostname && r:setdomainname && r:-k system-locale|key=system-locale'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-S && r:sethostname && r:setdomainname && r:-k system-locale|key=system-locale'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/issue && r:-p wa && r:-k system-locale|key=system-locale'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/issue.net && r:-p wa && r:-k system-locale|key=system-locale'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/hosts && r:-p wa && r:-k system-locale|key=system-locale'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sysconfig/network && r:-p wa && r:-k system-locale|key=system-locale'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sysconfig/network-scripts && r:-p wa && r:-k system-locale|key=system-locale'
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-S && r:sethostname && r:setdomainname && r:-k system-locale|-F key=system-locale"
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-S && r:sethostname && r:setdomainname && r:-k system-locale|-F key=system-locale"
      - "c:auditctl -l -> r:^-w && r:/etc/issue && r:-p wa && r:-k system-locale|key=system-locale"
      - "c:auditctl -l -> r:^-w && r:/etc/issue.net && r:-p wa && r:-k system-locale|key=system-locale"
      - "c:auditctl -l -> r:^-w && r:/etc/hosts && r:-p wa && r:-k system-locale|key=system-locale"
      - "c:auditctl -l -> r:^-w && r:/etc/sysconfig/network && r:-p wa && r:-k system-locale|key=system-locale"
      - "c:auditctl -l -> r:^-w && r:/etc/sysconfig/network-scripts && r:-p wa && r:-k system-locale|key=system-locale"
```
*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-S && r:sethostname && r:setdomainname && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-S && r:sethostname && r:setdomainname && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/issue && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/issue.net && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/hosts && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sysconfig/network && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/sysconfig/network-scripts && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification'
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b64 && r:-S && r:sethostname && r:setdomainname && r:-k audit_rules_networkconfig_modification|-F key=audit_rules_networkconfig_modification"
      - "c:auditctl -l -> r:^-a && r:exit,always|always,exit && r:-F arch=b32 && r:-S && r:sethostname && r:setdomainname && r:-k audit_rules_networkconfig_modification|-F key=audit_rules_networkconfig_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/issue && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/issue.net && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/hosts && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/sysconfig/network && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/sysconfig/network-scripts && r:-p wa && r:-k audit_rules_networkconfig_modification|key=audit_rules_networkconfig_modification"
```

*Explanation:*
The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses audit_rules_networkconfig_modification as key instead of system-locale. 

**32600:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/group && r:-p wa && r:-k identity|key=identity'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/passwd && r:-p wa && r:-k identity|key=identity'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/gshadow && r:-p wa && r:-k identity|key=identity'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/shadow && r:-p wa && r:-k identity|key=identity'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/security/opasswd && r:-p wa && r:-k identity|key=identity'
      - "c:auditctl -l -> r:^-w && r:/etc/group && r:-p wa && r:-k identity|key=identity"
      - "c:auditctl -l -> r:^-w && r:/etc/passwd && r:-p wa && r:-k identity|key=identity"
      - "c:auditctl -l -> r:^-w && r:/etc/gshadow && r:-p wa && r:-k identity|key=identity"
      - "c:auditctl -l -> r:^-w && r:/etc/shadow && r:-p wa && r:-k identity|key=identity"
      - "c:auditctl -l -> r:^-w && r:/etc/security/opasswd && r:-p wa && r:-k identity|key=identity"
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/group && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/passwd && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/gshadow && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/shadow && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/etc/security/opasswd && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification'
      - "c:auditctl -l -> r:^-w && r:/etc/group && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/passwd && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/gshadow && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/shadow && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification"
      - "c:auditctl -l -> r:^-w && r:/etc/security/opasswd && r:-p wa && r:-k audit_rules_usergroup_modification|key=audit_rules_usergroup_modification"
```

*Explanation:*
The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses audit_rules_usergroup_modification as key instead of identity.

**32601:**

*Previous checks:*
```
 condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k mounts|key=mounts'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k mounts|key=mounts'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k mounts|key=mounts'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k mounts|key=mounts'
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_mod|key=perm_mod'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_mod|key=perm_mod'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_mod|key=perm_mod'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S mount && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_mod|key=perm_mod'
```

*Explanation:*
The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses perm_mod as key instead of mounts. 

**32603:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/var/log/lastlog && r:-p wa && r:-k logins|key=logins'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/var/run/faillock && r:-p wa && r:-k logins|key=logins'
      - "c:auditctl -l -> r:^-w && r:/var/log/lastlog && r:-p wa && r:-k logins|key=logins"
      - "c:auditctl -l -> r:^-w && r:/var/run/faillock && r:-p wa && r:-k logins|key=logins"
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/var/log/lastlog && r:-p wa && r:-k logins|key=logins'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-w && r:/var/log/faillock && r:-p wa && r:-k logins|key=logins'
      - "c:auditctl -l -> r:^-w && r:/var/log/lastlog && r:-p wa && r:-k logins|key=logins"
      - "c:auditctl -l -> r:^-w && r:/var/log/faillock && r:-p wa && r:-k logins|key=logins"
```

*Explanation:*
The file locations where set to /var/run but the files where not existing, instead /var/log is being used. 


**32606:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chcon && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_chng|key=perm_chng'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chcon && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_chng|key=perm_chng'
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chcon && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|key=privileged'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chcon && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|key=privileged'
```

*Explanation:*
OSCAP does not check whether 'perm=x' is present in the rule. Nevertheless, the rule may be considered as passed because, by default, all actions (rwxa) are logged when 'perm' is not specified. However, there is a concern that the logs may become overwhelming. Auditctl, however, indicates the following in its manual: 'The read & write syscalls are omitted from this set since they would overwhelm the logs. 

The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses privileged as key. 

**32607:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/setfacl && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_chng|-F key=perm_chng'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/setfacl && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k perm_chng|-F key=perm_chng'
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/setfacl && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/setfacl && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
```

*Explanation:*
OSCAP does not check whether 'perm=x' is present in the rule. Nevertheless, the rule may be considered as passed because, by default, all actions (rwxa) are logged when 'perm' is not specified. However, there is a concern that the logs may become overwhelming. Auditctl, however, indicates the following in its manual: 'The read & write syscalls are omitted from this set since they would overwhelm the logs. 

The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses privileged as key. 


**32608:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chacl && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k priv_cmd|-F key=priv_cmd'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chacl && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k priv_cmd|-F key=priv_cmd'
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chacl && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/chacl && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
```

*Explanation:*
OSCAP does not check whether 'perm=x' is present in the rule. Nevertheless, the rule may be considered as passed because, by default, all actions (rwxa) are logged when 'perm' is not specified. However, there is a concern that the logs may become overwhelming. Auditctl, however, indicates the following in its manual: 'The read & write syscalls are omitted from this set since they would overwhelm the logs. 

The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses privileged as key. 


**32609:**

*Previous checks:*
```
 condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/sbin/usermod && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k usermod|-F key=usermod'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/sbin/usermod && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k usermod|-F key=usermod'
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/sbin/usermod && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/sbin/usermod && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
```

*Explanation:*
OSCAP does not check whether 'perm=x' is present in the rule. Nevertheless, the rule may be considered as passed because, by default, all actions (rwxa) are logged when 'perm' is not specified. However, there is a concern that the logs may become overwhelming. Auditctl, however, indicates the following in its manual: 'The read & write syscalls are omitted from this set since they would overwhelm the logs. 

The –k option sets the key for the audit event. The key is a way to categorize or label events for easier analysis. This key can be set to any value, osap uses privileged as key. 

**32610:**

*Previous checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64|-F arch=b32 && r:-S && r:init_module && r:finit_module && r:delete_module && r:create_module && r:query_module && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k kernel_modules|-F key=kernel_modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/kmod && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k kernel_modules|-F key=kernel_modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64|-F arch=b32 && r:-S && r:init_module && r:finit_module && r:delete_module && r:create_module && r:query_module && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k kernel_modules|-F key=kernel_modules'
      - 'c:auditctl -l-> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/kmod && r:-F perm=x && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k kernel_modules|-F key=kernel_modules'
      - "c:ls -l /usr/sbin/lsmod -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/rmmod -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/insmod -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/modinfo -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/modprobe -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/depmod -> r:/bin/kmod"
```

*Updated checks:*
```
condition: all
    rules:
      - "c:ls -l /usr/sbin/lsmod -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/rmmod -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/insmod -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/modinfo -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/modprobe -> r:/bin/kmod"
      - "c:ls -l /usr/sbin/depmod -> r:/bin/kmod"
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S query_module && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k modules|-F key=modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S query_module && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k modules|-F key=modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S init_module,finit_module|-S finit_module -S init_module && r:-k modules|-F key=modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S init_module,finit_module|-S finit_module -S init_module && r:-k modules|-F key=modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S delete_module && r:-k modules|-F key=modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S delete_module && r:-k modules|-F key=modules'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S create_module && r:-k module-change|-F key=module-change'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S create_module && r:-k module-change|-F key=module-change'
      - 'c:auditctl -l -> r:^-a && r:always,exit|exit,always && r:-S all && r:-F path=/usr/bin/kmod && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S query_module && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k modules|-F key=modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S query_module && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k modules|-F key=modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S init_module,finit_module|-S finit_module -S init_module && r:-k modules|-F key=modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S init_module,finit_module|-S finit_module -S init_module && r:-k modules|-F key=modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S delete_module && r:-k modules|-F key=modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S delete_module && r:-k modules|-F key=modules'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b32 && r:-S create_module && r:-k module-change|-F key=module-change'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F arch=b64 && r:-S create_module && r:-k module-change|-F key=module-change'
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:^-a && r:always,exit|exit,always && r:-F path=/usr/bin/kmod && r:-F auid>=\d+ && r:-F auid!=-1|-F auid!=4294967295|-F auid!=unset && r:-k privileged|-F key=privileged'
```

*Explanation:*
 OSCAP uses different rules for various kernel modules; additionally, OSCAP also utilizes other keys, such as 'privileged,' 'modules,' and 'module-change.' However, the impact of these rules remains the same. 

OSCAP does not check whether 'perm=x' is present in the rule. Nevertheless, the rule may be considered as passed because, by default, all actions (rwxa) are logged when 'perm' is not specified. However, there is a concern that the logs may become overwhelming. Auditctl, however, indicates the following in its manual: 'The read & write syscalls are omitted from this set since they would overwhelm the logs. 


**32611:**

*Previous checks:*
```
condition: all
    rules:
      - 'not d:/etc/audit/rules.d -> r:\.+.rules$ -> !r:\s*\t*-e 2$'
```

*Updated checks:*
```
condition: all
    rules:
      - 'd:/etc/audit/rules.d -> r:\.+.rules$ -> r:\s*\t*-e 2$'
```

*Explanation:*
The check was negatively formulated; it has now been rephrased to verify if -e 2 appears in a .rules file in the /etc/audit/rules.d directory.

**32618:**

*Previous checks:*
```
rules:
      - 'c:stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules -> !r:root|\\s*'
```

*Updated checks:*
```
condition: all
    rules:
      - 'c:stat -c "%U" /sbin/auditctl -> r:root'
      - 'c:stat -c "%U" /sbin/aureport -> r:root'
      - 'c:stat -c "%U" /sbin/ausearch -> r:root'
      - 'c:stat -c "%U" /sbin/autrace -> r:root'
      - 'c:stat -c "%U" /sbin/auditd -> r:root'
      - 'c:stat -c "%U"  /sbin/augenrules -> r:root'
```

*Explanation:*
Parsing in the original SCA ruleset is not working correctly. Also change condition to ALL. 


**32662:**

*Previous checks:*
```
condition: all  
rules:  
- 'f:/etc/sudoers -> r:^\s*\t*Defaults\s*\t*logfile='  
- 'd:/etc/sudoers.d -> r:\.* -> r:^\s*\t*Defaults\s*\t*logfile='
```
*Updated checks:*
```
condition: any  
rules:  
- 'f:/etc/sudoers -> r:^\s*\t*Defaults\s*\t*logfile='  
- 'd:/etc/sudoers.d -> r:\.* -> r:^\s*\t*Defaults\s*\t*logfile='
```
*Explanation:*

There  were checks at two  locations, but the CIS Benchmarks state that  one of the  two is sufficient. Hence, the  use of "any" instead of "all."

**32669:**

*Previous checks:*
```
condition: all
    rules:
      - 'f:/etc/pam.d/password-auth -> !r:^\s*\t*# && r:auth\s*\t*required\s*\t*pam_faillock.so\s*preauth'
      - 'f:/etc/pam.d/password-auth -> !r:^\s*\t*# && r:auth && r:required && r:\s*\t*pam_faillock.so && r:\s*\t*authfail'
      - 'f:/etc/pam.d/system-auth -> !r:^\s*\t*# && r:auth\s*\t*required\s*\t*pam_faillock.so\s*preauth'
      - 'f:/etc/pam.d/system-auth -> !r:^\s*\t*# && r:auth\s*\t*required\s*\t*pam_faillock.so'
      - 'f:/etc/security/faillock.conf -> !r:^\s*\t*# && n:deny\s*\t*=\s*\t*(\d+) compare <= 5'
      - 'f:/etc/security/faillock.conf -> !r:^\s*\t*# && n:fail_interval\s*\t*=\s*\t*(\d+) compare <= 900'
```

*Updated checks:*
```
condition: all
    rules:
      - 'f:/etc/pam.d/password-auth -> !r:^\s*\t*# && r:auth\s*\t*required\s*\t*pam_faillock.so\s*preauth'
      - 'f:/etc/pam.d/password-auth -> !r:^\s*\t*# && r:auth && r:required && r:\s*\t*pam_faillock.so && r:\s*\t*authfail'
      - 'f:/etc/pam.d/system-auth -> !r:^\s*\t*# && r:auth\s*\t*required\s*\t*pam_faillock.so\s*preauth'
      - 'f:/etc/pam.d/system-auth -> !r:^\s*\t*# && r:auth\s*\t*required\s*\t*pam_faillock.so'
      - 'f:/etc/security/faillock.conf -> !r:^\s*\t*# && n:deny\s*\t*=\s*\t*(\d+) compare <= 5'
      - 'f:/etc/security/faillock.conf -> !r:^\s*\t*# && n:unlock_time\s*\t*=\s*\t*(\d+) compare <= 900'
```

*Explanation:*
The CIS Benchmark stated that the unlock_time in etc/security/faillock.conf must be set a certain value. However, the almalinux9 SCA checks for the value of fail_interval which is not present. 

**32673:**

*Previous checks:*
```
condition: all  
rules:  
- 'f:/etc/login.defs -> n:^\s*\t*PASS_MIN_DAYS\s*\t*(\d+) compare >= 7'  
- 'not f:/etc/shadow -> n:^\w+:\$\.*:\d+:(\d+): compare < 7'
```
*Updated checks:*
```
condition: all  
rules:  
- 'f:/etc/login.defs -> n:^\s*\t*PASS_MIN_DAYS\s*\t*(\d+) compare >= 1'  
- 'not f:/etc/shadow -> n:^\w+:\$\.*:\d+:(\d+): compare < 1'
```
*Explanation:*

The CIS Benchmark stated  that  it is recommended  that PASS_MIN_DAYS parameter be set to 1 or more days. However, the almalinux9 SCA checks  for a value of 7.

## Removed rules
The rules with ID **32625**, **32626**, **32627** and **32631** are commented out because OpenSCAP used the rsyslog method to save the logs. These rules contradicts with that approach directly. Both ways are valid ways to harden the system, however only one can be chosen. 
