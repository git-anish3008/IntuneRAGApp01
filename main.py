import sys
import ctypes
from ui.desktop_app import IntuneRAGDesktopApp

def enable_windows_high_dpi():
    """Ensures crisp Segoe UI font rendering on Windows 10/11 laptops."""
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

if __name__ == "__main__":
    enable_windows_high_dpi()
    app = IntuneRAGDesktopApp()
    app.mainloop()