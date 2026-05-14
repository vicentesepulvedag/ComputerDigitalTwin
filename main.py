import os
import site
import sys


def _asegurar_venv_en_path():
    venv_site = os.path.join(
        os.path.dirname(__file__), ".venv", "lib", "python3.14", "site-packages"
    )
    venv_site = os.path.normpath(venv_site)
    if os.path.isdir(venv_site) and venv_site not in sys.path:
        sys.path.insert(0, venv_site)
        site.addsitedir(venv_site)


_asegurar_venv_en_path()

from cli.menu import menu_interactivo

if __name__ == "__main__":
    menu_interactivo()
