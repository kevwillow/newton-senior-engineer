"""The fixtures of the Active Directory tests.

The tests that run the generated Windows write setup need the printed
script and the stub write helpers of the build.  The two fixtures are
in ``windows_run.py``, and they are here so that every test module of
this directory may ask for them.
"""

from windows_run import helpers, windows_script  # noqa: F401
