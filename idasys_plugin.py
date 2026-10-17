"""IDASys plugin entry point.

Copy this file AND the ``idasys`` folder into ``%APPDATA%\\Hex-Rays\\IDA Pro\\plugins``
(or ``<IDA>\\plugins``).

Headless usage (prints the report and exits)::

    idat -A -S"idasys_plugin.py --headless" driver.sys
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import ida_idaapi  # noqa: E402
import ida_kernwin  # noqa: E402


class IDASysPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Windows kernel driver analysis helper"
    help = "Recovers DriverEntry, dispatch routines, IOCTLs and device names"
    wanted_name = "IDASys: Analyze driver"
    wanted_hotkey = ""

    def init(self):
        import ida_ida
        import ida_idp
        if ida_idp.ph_get_id() != ida_idp.PLFM_386:
            return ida_idaapi.PLUGIN_SKIP
        from idasys import ui
        self._ui = ui
        ui.register_actions()
        self._hooks = ui.PopupHooks()
        self._hooks.hook()
        ida_kernwin.msg("IDASys loaded: Edit > IDASys (Ctrl+Alt+D analyze, Ctrl+Alt+I decode IOCTL)\n")
        _ = ida_ida
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self._ui.run_full(True)

    def term(self):
        try:
            self._hooks.unhook()
            self._ui.unregister_actions()
        except Exception:
            pass


def PLUGIN_ENTRY():
    return IDASysPlugin()


def _headless_main():
    import ida_auto
    import ida_pro
    from idasys import core
    ida_auto.auto_wait()
    apply_changes = "--readonly" not in sys.argv
    out = None
    for a in sys.argv:
        if a.startswith("--out="):
            out = a[len("--out="):]
    rep = core.analyze(apply_changes=apply_changes, verbose=out is None)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(core.render_text(rep))
    ida_pro.qexit(0)


if __name__ == "__main__" and "--headless" in sys.argv:
    _headless_main()
