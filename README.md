# Active Directory Web Services (ADWS) for Samba

## Installation

To avoid installing packages as root and polluting namespaces, we can use a
virtualenv.

```bash
git clone https://github.com/GSam/samba-adws.git
git clone https://github.com/GSam/python-wcfbin.git

virtualenv env
./env/bin/pip install -r samba-adws/requirements.txt
```

Currently this repository requires a patched Samba installation. Patches can be
found at `https://github.com/GSam/samba`. The **PYTHONPATH** environment
variable needs to refer to the patched Python modules.

## Running

Requires sudo / root in order to access sam.ldb directly.

### Expose on network interface 10.0.0.1:9389

```bash
cd samba-adws
PYTHONPATH=/path/to/samba/bin/python:/path/to/python-wcfbin sudo --preserve-env=PYTHONPATH ../env/bin/python main.py --bind 10.0.0.1
```
