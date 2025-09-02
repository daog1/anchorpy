"""This module deals with (de)serializing Anchor events."""
from hashlib import sha256
from typing import Any, Dict, Optional, Tuple
#,evaluate_forward_ref
#from typing_extensions import evaluate_forward_ref

from anchorpy_idl import (
    Idl,
    IdlEvent,
)
from construct import Adapter, Bytes, Construct, Sequence, Switch
from pyheck import snake

from anchorpy.coder.idl import _typedef_layout, find_type_by_name
from anchorpy.program.common import Event


def _event_discriminator(name: str) -> bytes:
    """Get 8-byte discriminator from event name.

    Args:
        name: The event name.

    Returns:
        Discriminator
    """
    return sha256(f"event:{name}".encode()).digest()[:8]


def _event_layout(event: IdlEvent, idl: Idl) -> Construct:
    """Build the layout for an event by reusing its typedef directly.

    This avoids relying on newer anchorpy_idl symbols.
    """
    ev_type_def = find_type_by_name(event.name, idl.types)
    return _typedef_layout(ev_type_def, idl.types, event.name)


class EventCoder(Adapter):
    """Encodes and decodes Anchor events."""

    def __init__(self, idl: Idl):
        """Initialize the EventCoder.

        Args:
            idl: The parsed Idl object.
        """
        self.idl = idl
        idl_events = idl.events
        layouts: Dict[str, Construct]
        if idl_events:
            layouts = {event.name: _event_layout(event, idl) for event in idl_events}
        else:
            layouts = {}
        self.layouts = layouts
        self.discriminators: Dict[bytes, str] = (
            {}
            if idl_events is None
            else {_event_discriminator(event.name): event.name for event in idl_events}
        )
        self.discriminator_to_layout = {
            disc: self.layouts[event_name]
            for disc, event_name in self.discriminators.items()
        }
        subcon = Sequence(
            "discriminator" / Bytes(8),  # not base64-encoded here
            Switch(lambda this: this.discriminator, self.discriminator_to_layout),
        )
        super().__init__(subcon)  # type: ignore

    def _decode(self, obj: Tuple[bytes, Any], context, path) -> Optional[Event]:
        disc = obj[0]
        try:
            event_name = self.discriminators[disc]
        except KeyError:
            return None
        return Event(data=obj[1], name=event_name)
