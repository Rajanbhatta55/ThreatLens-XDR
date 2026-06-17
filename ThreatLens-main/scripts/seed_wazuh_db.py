"""Compatibility wrapper for the package seed-db implementation."""

from threatlens.seed_wazuh_db import main


if __name__ == "__main__":
    raise SystemExit(main())