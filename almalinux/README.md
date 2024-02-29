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
