"""The Active Directory audit, and the guarded writes under ``write/``.

The package holds the pieces between one collector document and one
model-bound report:

- ``queries.json`` / ``queryset.py``  the pinned query set and its validator
- ``forbidden.py``   the attributes that are never requested and never returned
- ``wire.py``        the collector document contract (SPEC-1.3 section 5)
- ``values.py``      SID, GUID, FILETIME and GeneralizedTime decoding
- ``secdesc.py``     self-relative security descriptors (MS-DTYP 2.4.6)
- ``members.py``     recursive, cycle-safe membership
- ``model.py``       the results model (section 6)
- ``catalogue.py``   the check catalogue (the checks are in ``checks/``)
- ``runner.py``      the runner and the identity guard (section 8)
- ``render.py``      the model-bound report (envelope and redaction)

Every module listed above is standard library only.  None of them opens
a socket, runs a command or reads a device: ``transport.py`` fetches the
collector document, ``tools.py`` holds the two audit tools, ``setupgen.py``
prints the owner's setup script, and the collectors live in
``collector/``.  The audit never writes to a directory; the guarded writes
of ``write/`` are a separate path with their own approval.
"""

from __future__ import annotations
