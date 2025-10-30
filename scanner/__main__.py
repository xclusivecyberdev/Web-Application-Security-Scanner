"""Module entrypoint for ``python -m scanner``."""

from .cli import main


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
