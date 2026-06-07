"""drifty — Terraform Drift Intelligence."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("drifty")
except PackageNotFoundError:
    __version__ = "unknown"
    
__author__ = "Satyajit Dey"
__email__ = "satyajit.dey@umbc.edu"
