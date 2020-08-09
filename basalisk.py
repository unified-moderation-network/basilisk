from __future__ import annotations

"""
A really small bit of python glue, wrapping hyperscan as a service

Currently only ships with a single test pattern.

This needs:
  - a way to update the db on demand
    - This needs to notify downstream to invalidate any caching
  - serialization of the last db state
  - resume load from serialized state
"""

import msgpack
import hyperscan
import zmq


MULTICAST_SUBSCRIBE_ADDR = "tcp://127.0.0.1:5555"
PULL_REMOTE_ADDR = "tcp://127.0.0.1:5556"

MATCH_FOUND_TOPIC = "basalisk.gaze"
LOOK_FOR_MATCH = "basalisk.offer"

#: This is just here for a default pattern to test with
INVITE_PATTERN = r"(?i)(discord\.(?:gg|io|me|li)|discord(?:app)?\.com\/invite)\/(\S+)"


def match_handler(pattern_id, start, end, flags, context):

    socket, rts = context

    payload = msgpack.packb((MATCH_FOUND_TOPIC, rts))
    socket.send(payload)

    return True


def check_match(db, rts, to_check, socket):
    if __debug__:
        import logging
        logging.info("Scanning: %s", to_check)
    db.scan(to_check, match_event_handler=match_handler, context=(socket, rts))


def main():

    ctx = zmq.Context()
    sub_socket = ctx.socket(zmq.SUB)
    push_socket = ctx.socket(zmq.PUSH)
    sub_socket.setsockopt(zmq.SUBSCRIBE, b"")
    sub_socket.connect(MULTICAST_SUBSCRIBE_ADDR)
    push_socket.connect(PULL_REMOTE_ADDR)

    db = hyperscan.Database()
    DEFAULT_EXPRESSIONS = (INVITE_PATTERN,)
    db.compile(expressions=DEFAULT_EXPRESSIONS)

    while True:
        try:
            msg = sub_socket.recv()

            topic, (rts, to_check) = msgpack.unpackb(
                msg, use_list=False, strict_map_key=False
            )

            if topic == LOOK_FOR_MATCH:
                check_match(db, rts, to_check, push_socket)

        except Exception as exc:
            if __debug__:
                # This is a really lazy way of letting me peek at this for now
                # is something goes wrong.
                import logging

                logging.exception(f"???: {msg}", exc_info=exc)
