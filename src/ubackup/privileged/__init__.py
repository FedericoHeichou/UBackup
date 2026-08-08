"""Installed, narrowly scoped privileged helper implementations.

The modules in this package are invoked by fixed root-owned entrypoints.  They
must not grow into a generic command runner: every entrypoint owns a fixed
operation and uses the protocol validation in :mod:`ubackup.privileged.protocol`.
"""
