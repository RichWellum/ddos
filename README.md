# DDOS detection

``sta_ddos.py`` is a tool to perform rate of change inspections on protocols -
to warn on potential DDOS attacks. It is yaml driven and easy for the end user
to make changes and apply.

## Setup

Create a python3 virtual environment:

```bash
    virtualenv ddos_python
```

Activate virtual env:

```bash
    source ddos_python/bin/activate
```

Install requirements:

```bash
    pip3 install -r requirements.txt
```

Edit config.yaml - add your SMC details and also edit your ddos settings

Run tool:

```bash
    ./sta_ddos.py config.yaml
```
