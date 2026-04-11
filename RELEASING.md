# Releasing beav3r-sdk

This document is for package maintainers.

## Pre-release checks

```bash
python3 -m pip install -U build twine
python3 -m build
python3 -m twine check dist/*
python3 -m unittest discover -s tests -v
```

## Publish

```bash
python3 -m twine upload dist/*
```

## Post-publish smoke test

```bash
python3 -m venv /tmp/beav3r-sdk-smoke
source /tmp/beav3r-sdk-smoke/bin/activate
python -m pip install -U pip
python -m pip install beav3r-sdk
python -c "import beav3r_sdk; print('ok')"
```
