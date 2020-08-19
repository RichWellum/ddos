# DDOS detection

`sta_ddos.py` is a tool to perform rate of change inspections on protocols -
to warn on potential DDOS attacks. It is yaml driven and easy for the end user
to make changes and apply.

## Setup

### Create a python3 virtual environment

```bash
    virtualenv ddos_python
```

### Activate virtual env

```bash
    source ddos_python/bin/activate
```

### Install requirements

```bash
    pip3 install -r requirements.txt
```

### Edit config.yaml - add your SMC details and also edit your ddos settings

CANA Application ID's are found here: <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>

Stealthwatch Protocol ID's are found here:
<https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/management_console/default_applications_definitions/SW_7_0_Default_Applications_Definitions_DV_1_0.pdf>

Typical example of a common protocol profile:

ICMP
SSH
Telnet
NetBIOS

This would be represented by:

```bash
dos_attack:
    verbose: false # Set me to true to see lots of output
    enabled: true
    dos_flow_time: 360 # Look at 5m sliding window (enough time to gather from FCs)
    dos_flow_repeat_time: 5 # Query each 60s
    dos_threshold: 15 # % spike causes a table entry and warning
    dos_spike: 5 # int consequtive dos_thresholds is an alert
    protocol: [] # Change protocols here (1 = ICMP) etc
    applications: { includes: [37, 44, 48, 27], excludes: [] }
```

Note that is aggregating the total bytes of all these applications.

### Run tool

```bash
    ./sta_ddos.py config.yaml
```

### Run tool in verbose mode for more info

```bash
    ./sta_ddos.py config.yaml -v
```
