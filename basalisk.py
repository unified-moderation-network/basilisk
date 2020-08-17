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

import logging
import sys
from logging.handlers import RotatingFileHandler

import hyperscan
import msgpack
import zmq

log = logging.getLogger("basalisk")

MULTICAST_SUBSCRIBE_ADDR = "tcp://127.0.0.1:5555"
PULL_REMOTE_ADDR = "tcp://127.0.0.1:5556"

MATCH_FOUND_TOPIC = "basalisk.gaze"
LOOK_FOR_MATCH = "basalisk.offer"

#: This is just here for a default pattern to test with
INVITE_PATTERN = r"(?i)(discord\.(?:gg|io|me|li)|discord(?:app)?\.com\/invite)\/(\S+)"


def only_once(f):
    has_called = False

    def wrapped(*args, **kwargs):
        nonlocal has_called

        if not has_called:
            has_called = True
            f(*args, **kwargs)

    return wrapped


def match_handler(pattern_id, start, end, flags, context):
    socket, rts = context
    payload = msgpack.packb((MATCH_FOUND_TOPIC, rts))
    socket.send(payload)


def check_match(db, rts, to_check, socket):
    logging.info("Scanning: %s", to_check)
    db.scan(
        to_check, match_event_handler=only_once(match_handler), context=(socket, rts)
    )


def main():

    raw_topics = (b"\x92\xaebasalisk.offer",)

    ctx = zmq.Context()
    sub_socket = ctx.socket(zmq.SUB)
    push_socket = ctx.socket(zmq.PUSH)
    for raw_topic in raw_topics:
        sub_socket.setsockopt(zmq.SUBSCRIBE, raw_topic)
    sub_socket.connect(MULTICAST_SUBSCRIBE_ADDR)
    push_socket.connect(PULL_REMOTE_ADDR)

    db = hyperscan.Database()
    DEFAULT_EXPRESSIONS = (INVITE_PATTERN.encode(),)
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
            log.exception(
                "Error when scanning %s from payload %s", to_check, msg, exc_info=exc
            )


if __name__ == "__main__":
    rotating_file_handler = RotatingFileHandler(
        "basalisk.log", maxBytes=10000000, backupCount=5
    )
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        style="%",
    )
    rotating_file_handler.setFormatter(formatter)
    log.addHandler(rotating_file_handler)
    main()
