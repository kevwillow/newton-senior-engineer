"""The AD write helper of one DC, in memory (the fake of the helper).

The fake implements the modes of SPEC-1.4-REQUEST against an in-memory
directory: the token check, the expiry check, the exclusive transaction
record, the PDC-only apply, the conflict on a before-image that does not
match, the version rule of the undo and the ``read`` mode with its facts.

The helpers of one domain share one directory (the objects), so a write
on the PDC is visible on the other DCs: that is instant replication.  A
helper that gets its own copy of the directory never sees the write and
is the lagging DC of the tests.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from newton_mcp.ad.write import request


class NotFound(Exception):
    """The object of the target is not there."""


class FakeHelper:
    """One write helper, in memory.

    ``configured`` is the name the setup wrote into ``device.txt`` of
    this DC: the name of the device that stands for the domain, the
    same on every DC of the domain.  The helper refuses a request whose
    ``device`` differs from it with ``schema``, the way the real helper
    reads its own ``device.txt`` and compares.
    """

    def __init__(
        self,
        device: str,
        *,
        configured: str = "lab-win",
        pdc: bool = False,
        key_hex: str | None = None,
        objects: dict[str, dict[str, Any]] | None = None,
        now: int = 1800000000,
    ) -> None:
        self.device = device
        self.configured = configured
        self.pdc = pdc
        self.key_hex = "11" * 32 if key_hex is None else key_hex
        self.now = now
        self.objects: dict[str, dict[str, Any]] = {} if objects is None else objects
        self.records: dict[str, dict[str, Any]] = {}
        self.armed: set[str] = set()

    # -- the directory ----------------------------------------------------

    def _lower_sam(self, value: Any) -> Any:
        """The name of an account, lowercased (SPEC section 6).

        The directory holds the name as it was written (``Administrator``),
        but the request schema accepts only a lowercase name and the
        contract compares the names without their case: the ids of an
        answer therefore carry the name in lowercase.
        """
        if isinstance(value, str):
            return value.lower()
        return value

    def add(
        self,
        guid: str,
        sid: str,
        sam: str,
        **fields: Any,
    ) -> dict[str, Any]:
        """Add one object to the directory and return it."""
        obj: dict[str, Any] = {
            "guid": guid,
            "sid": sid,
            "sam": sam,
            "uac": 512,
            "etypes": 0,
            "lockout": 0,
            "maq": None,
            "admin_count": 0,
            "dc_account": False,
            "privileged": False,
            "object_class": ["user"],
            "members": [],
            "parent": None,
            "version": 1,
            "kind": "user",
        }
        obj.update(fields)
        self.objects[guid] = obj
        return obj

    def touch(self, guid: str) -> None:
        """Change an object behind the back of the write (a concurrent edit)."""
        self.objects[guid]["version"] += 1

    # -- the modes --------------------------------------------------------

    def handle(self, raw: bytes) -> dict[str, Any]:
        """Answer one request."""
        try:
            req = request.parse_request(raw)
        except request.RequestRefused as exc:
            return {"v": 1, "code": exc.code}
        if req["device"] != self.configured:
            return {"v": 1, "code": "schema"}
        mode = req["mode"]
        if mode == "read":
            return self._read(req)
        if mode == "apply":
            return self._apply(req)
        if mode == "confirm":
            return self._confirm(req)
        if mode == "abort":
            return self._abort(req)
        return self._status(req)

    # -- the read mode ----------------------------------------------------

    def _by_sam(self, sam: str) -> list[dict[str, Any]]:
        lowered = sam.lower()
        return [
            obj
            for obj in self.objects.values()
            if str(obj["sam"]).lower() == lowered
        ]

    def _by_guid(self, guid: str) -> dict[str, Any]:
        obj = self.objects.get(guid)
        if obj is None:
            raise NotFound(guid)
        return obj

    def _one(
        self,
        target: dict[str, Any],
        prefix: str,
    ) -> dict[str, Any]:
        """Find the object of a target: by guid when it has one, else by sam."""
        guid = target.get(prefix + "guid")
        if isinstance(guid, str):
            obj = self._by_guid(guid)
            sid = target.get(prefix + "sid")
            sam = target.get(prefix + "sam")
            if isinstance(sid, str) and str(obj["sid"]).lower() != sid.lower():
                raise NotFound(guid)
            if isinstance(sam, str) and str(obj["sam"]).lower() != sam.lower():
                raise NotFound(guid)
            return obj
        sam = target.get(prefix + "sam")
        if not isinstance(sam, str):
            raise NotFound("no name")
        found = self._by_sam(sam)
        if len(found) != 1:
            raise NotFound(sam)
        return found[0]

    def _live_of(self, verb: str, obj: dict[str, Any]) -> dict[str, Any]:
        """The live values of one object, in the shape of the verb."""
        if verb in ("uac-clear", "disable", "enable"):
            return {"uac": obj["uac"]}
        if verb == "enc-types":
            etypes = obj["etypes"]
            return {"etypes": "absent" if etypes is None else etypes}
        if verb == "unlock":
            return {"lockout": obj["lockout"]}
        if verb == "move":
            return {"parent": obj["parent"]}
        raise NotFound(verb)

    def _facts_of(self, obj: dict[str, Any]) -> dict[str, Any]:
        """The facts of one object."""
        return {
            "admin_count": obj["admin_count"],
            "dc_account": obj["dc_account"],
            "privileged": obj["privileged"],
            "object_class": list(obj["object_class"]),
            "pdc": self.pdc,
        }

    def _risk_of(self, verb: str, facts: dict[str, Any]) -> str:
        """The risk level the helper derives itself (SPEC section 4).

        HIGH when any object of the target is privileged, has an
        adminCount of 1 or is a DC account; otherwise LOW for an unlock,
        otherwise MED.
        """
        for one in facts.values():
            if not isinstance(one, dict):
                continue
            if one.get("privileged") is True:
                return "HIGH"
            if one.get("admin_count") == 1:
                return "HIGH"
            if one.get("dc_account") is True:
                return "HIGH"
        if verb == "unlock":
            return "LOW"
        return "MED"

    def _resolve(
        self,
        verb: str,
        target: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """The ids, the live values and the facts of the target."""
        if verb in ("member-add", "member-remove"):
            group = self._one(target, "group_")
            member = self._one(target, "member_")
            ids = {
                "group_guid": group["guid"],
                "group_sid": group["sid"],
                "group_sam": self._lower_sam(group["sam"]),
                "member_guid": member["guid"],
                "member_sid": member["sid"],
                "member_sam": self._lower_sam(member["sam"]),
            }
            live = {
                "member": "present"
                if member["guid"] in group["members"]
                else "absent"
            }
            facts = {
                "group": self._facts_of(group),
                "member": self._facts_of(member),
            }
            return ids, live, facts
        if verb == "user-create":
            parent = self._by_guid(str(target["parent_guid"]))
            sam = str(target["sam"])
            live = {
                "object": "present" if self._by_sam(sam) else "absent"
            }
            ids = {"parent_guid": parent["guid"], "sam": self._lower_sam(sam)}
            facts = {"target": self._facts_of(parent)}
            return ids, live, facts
        if verb == "maq":
            obj = self._one(target, "")
            ids = {"guid": obj["guid"]}
            live = {"maq": obj["maq"]}
            facts = {"target": self._facts_of(obj)}
            return ids, live, facts
        obj = self._one(target, "")
        ids = {
            "guid": obj["guid"],
            "sid": obj["sid"],
            "sam": self._lower_sam(obj["sam"]),
        }
        facts = {"target": self._facts_of(obj)}
        return ids, self._live_of(verb, obj), facts

    def _read(self, req: dict[str, Any]) -> dict[str, Any]:
        try:
            ids, live, facts = self._resolve(req["verb"], req["target"])
        except NotFound:
            return {"v": 1, "code": "not_found"}
        return {"v": 1, "code": "ok", "live": live, "ids": ids, "facts": facts}

    # -- the apply mode ---------------------------------------------------

    def _apply(self, req: dict[str, Any]) -> dict[str, Any]:
        expected = request.token(
            self.key_hex, request.digest(req), req["nbf"], req["exp"]
        )
        if not hmac.compare_digest(expected, str(req["token"])):
            return {"v": 1, "code": "bad_token"}
        if not req["nbf"] - 60 <= self.now <= req["exp"]:
            return {"v": 1, "code": "expired"}
        txid = str(req["txid"])
        if txid in self.records:
            return {"v": 1, "code": "replay"}
        if not self.pdc:
            return {"v": 1, "code": "not_pdc"}
        record: dict[str, Any] = {
            "txid": txid,
            "request": {
                key: value
                for key, value in req.items()
                if key not in ("secret", "token")
            },
            "state": "armed",
            "undo_at": self.now + int(req["window"]),
            "restored": False,
            "conflicts": [],
            "version": None,
            "created": None,
        }
        self.records[txid] = record
        try:
            ids, live, facts = self._resolve(req["verb"], req["target"])
        except NotFound:
            record["state"] = "refused"
            return {"v": 1, "code": "not_found"}
        derived = self._risk_of(req["verb"], facts)
        if derived != req["risk"]:
            record["state"] = "refused"
            return {"v": 1, "code": "risk_mismatch"}
        if live != req["before"]:
            record["state"] = "refused"
            return {"v": 1, "code": "conflict", "live": live}
        created = self._write(req, record)
        if created is not None:
            record["created"] = created
        after = self._live_now(req, record)
        answer: dict[str, Any] = {
            "v": 1,
            "code": "ok",
            "live": after,
            "undo_at": record["undo_at"],
        }
        if created is not None:
            answer["created"] = created
        return answer

    def _object_of(self, req: dict[str, Any]) -> dict[str, Any]:
        """The object an apply writes to."""
        verb = req["verb"]
        target = req["target"]
        if verb in ("member-add", "member-remove"):
            return self._one(target, "group_")
        if verb == "user-create":
            return self._by_guid(str(target["parent_guid"]))
        return self._one(target, "")

    def _write(
        self,
        req: dict[str, Any],
        record: dict[str, Any],
    ) -> str | None:
        """Write the after-image and arm the undo."""
        verb = req["verb"]
        after = req["after"]
        obj = self._object_of(req)
        if verb in ("uac-clear", "disable", "enable"):
            obj["uac"] = after["uac"]
        elif verb == "enc-types":
            obj["etypes"] = None if after["etypes"] == "absent" else after["etypes"]
        elif verb == "unlock":
            obj["lockout"] = after["lockout"]
        elif verb == "member-add":
            member = str(req["target"]["member_guid"])
            if member not in obj["members"]:
                obj["members"].append(member)
        elif verb == "member-remove":
            member = str(req["target"]["member_guid"])
            if member in obj["members"]:
                obj["members"].remove(member)
        elif verb == "maq":
            obj["maq"] = after["maq"]
        elif verb == "move":
            obj["parent"] = after["parent"]
        elif verb == "user-create":
            sam = str(req["target"]["sam"])
            digest = hashlib.sha256(sam.encode("utf-8")).hexdigest()
            guid = "-".join(
                (
                    digest[:8],
                    digest[8:12],
                    digest[12:16],
                    digest[16:20],
                    digest[20:32],
                )
            )
            self.add(
                guid,
                "S-1-5-21-1-2-3-9999",
                sam,
                uac=514,
                object_class=["user", "organizationalPerson"],
                parent=obj["guid"],
            )
            return guid
        obj["version"] += 1
        # the version the write leaves behind is the one the undo checks
        record["version"] = obj["version"]
        return None

    def _live_now(
        self,
        req: dict[str, Any],
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """The live values of the target of a record, after the write."""
        verb = req["verb"]
        if verb == "user-create":
            sam = str(req["target"]["sam"])
            return {"object": "present" if self._by_sam(sam) else "absent"}
        if verb in ("member-add", "member-remove"):
            group = self._one(req["target"], "group_")
            member = str(req["target"]["member_guid"])
            return {
                "member": "present" if member in group["members"] else "absent"
            }
        obj = self._object_of(req)
        return self._live_of(verb, obj)

    # -- the confirm, abort and status modes ------------------------------

    def _confirm(self, req: dict[str, Any]) -> dict[str, Any]:
        txid = str(req["txid"])
        record = self.records.get(txid)
        if record is None:
            return {"v": 1, "code": "not_found"}
        if record["state"] in ("undone", "undo_failed"):
            return {"v": 1, "code": "conflict"}
        live = self._live_now(record["request"], record)
        if live != record["request"]["after"]:
            return {"v": 1, "code": "conflict"}
        record["state"] = "confirmed"
        return {"v": 1, "code": "ok"}

    def _undo(self, record: dict[str, Any]) -> tuple[bool, list[str]]:
        """The undo: only when the version still equals the recorded one."""
        req = record["request"]
        verb = req["verb"]
        obj = self._object_of(req)
        if obj["version"] != record["version"]:
            record["conflicts"].append(obj["guid"])
            return False, list(record["conflicts"])
        before = req["before"]
        if verb in ("uac-clear", "disable", "enable"):
            obj["uac"] = before["uac"]
        elif verb == "enc-types":
            obj["etypes"] = None if before["etypes"] == "absent" else before["etypes"]
        elif verb == "unlock":
            obj["lockout"] = before["lockout"]
        elif verb == "member-add":
            member = str(req["target"]["member_guid"])
            if member in obj["members"]:
                obj["members"].remove(member)
        elif verb == "member-remove":
            member = str(req["target"]["member_guid"])
            if member not in obj["members"]:
                obj["members"].append(member)
        elif verb == "maq":
            obj["maq"] = before["maq"]
        elif verb == "move":
            obj["parent"] = before["parent"]
        elif verb == "user-create":
            created = record.get("created")
            if isinstance(created, str):
                self.objects.pop(created, None)
        obj["version"] += 1
        return True, []

    def _abort(self, req: dict[str, Any]) -> dict[str, Any]:
        txid = str(req["txid"])
        record = self.records.get(txid)
        if record is None:
            return {"v": 1, "code": "not_found"}
        # Both real helpers abort only an armed record: a confirmed one is a
        # conflict and nothing is restored (measured live on 2026-11-13).
        if record["state"] != "armed":
            return {"v": 1, "code": "conflict"}
        restored, conflicts = self._undo(record)
        record["restored"] = restored
        record["conflicts"] = conflicts
        record["state"] = "undo_failed" if conflicts else "undone"
        return {
            "v": 1,
            "code": "ok",
            "restored": restored,
            "conflicts": conflicts,
        }

    def _status(self, req: dict[str, Any]) -> dict[str, Any]:
        txid = str(req["txid"])
        record = self.records.get(txid)
        if record is None:
            return {"v": 1, "code": "not_found"}
        return {
            "v": 1,
            "code": "ok",
            "state": record["state"],
            "undo_at": record["undo_at"],
            "restored": record["restored"],
            "conflicts": list(record["conflicts"]),
        }
