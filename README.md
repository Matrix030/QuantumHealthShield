# QuantumHealthShield

### Let liboqs-python install liboqs automatically

If liboqs is not detected at runtime by liboqs-python, it will be downloaded,
configured and installed automatically (as a shared library). This process will
be performed only once, at runtime, i.e., when loading the liboqs-python
wrapper. The liboqs source directory will be automatically removed at the end
of the process.

This is convenient in case you want to avoid installing liboqs manually, as
described in the subsection above.

### Install and activate a Python virtual environment

Execute in a Terminal/Console/Administrator Command Prompt

```shell
python3 -m venv venv
. venv/bin/activate
python3 -m ensurepip --upgrade
```

On Windows, replace the line

```shell
. venv/bin/activate
```

by

```shell
venv\Scripts\activate.bat
```

### Configure and install the wrapper

Execute in a Terminal/Console/Administrator Command Prompt

```shell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```

### Run the examples

Execute

```shell
python3 liboqs-python/examples/kem.py
python3 liboqs-python/examples/sig.py
python3 liboqs-python/examples/rand.py
```

### Run the unit test

Execute

```shell
nose2 --verbose liboqs-python
```
### Install Cryptography Package:
```shell
pip install cryptography
```

### How to run QuantumHealthShield main.py:
```shell
cd QuantumHealthShield
python3 main.py
```