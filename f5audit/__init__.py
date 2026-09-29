"""f5audit: read-only audit tool for F5 BIG-IP LTM configurations.

Collects configuration and statistics via iControl REST (GET only),
correlates object references, and reports orphaned / inactive objects
as input for a human-driven, change-controlled cleanup.
"""

__version__ = "0.4.0"
