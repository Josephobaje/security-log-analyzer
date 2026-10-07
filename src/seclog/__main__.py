"""Allow ``python -m seclog``."""

from seclog.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
