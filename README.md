# SCA CIS Benchmark OSCAP compatible

Within our situation, hardening was performed using the oscap tool and monitoring is done using Wazuh. However, oscap executes some hardening steps slightly differently than those checked by the Wazuh Security Content Automation (SCA) file. When Wazuh is utilized as a monitoring solution, the hardening percentages will deviate from what oscap indicates. 

To align them as closely as possible, various checks have been adjusted to match the hardening steps outlined by oscap. Throughout this process, the CIS Benchmark for the specific OS has been consistently referenced to ensure compliance with the CIS Benchmark.

## Current status and collaboration

For now, only an AlmaLinux 9 SCA file is available. To make an SCA file for another OS compatible with the hardening tool oscap, feel free to collaborate and create a pull request with the corresponding SCA file.
