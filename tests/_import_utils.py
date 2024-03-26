import sys
from pathlib import Path

_CURRENT_DIR = (
    Path(sys.argv[0] if __name__ == "__main__" else __file__).resolve().parent
)


def allow_imports() -> None:
    path = (_CURRENT_DIR / "..." / ".." / ".." / "src").absolute().resolve()
    assert path.exists()
    sys.path.append(f"{path}")
