import sys

# The application promises not to leave Python bytecode caches around the
# inspected filesystem. Set this as early as package import allows, including
# when invoked through the installed console-script entry point.
sys.dont_write_bytecode = True

__version__ = "0.1.0"
APP_NAME = "UBackup"
