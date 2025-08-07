#!/usr/bin/env python3
"""
Postfix Mail Injector

This script provides a reusable Python class `PostfixInjector` that allows injection of emails
into a Postfix maildrop directory via the cleanup and pickup sockets.

Inspired by the Perl modules:
- Mail::Postfix::Postdrop
- Qpsmtpd::Postfix

It provides an object-oriented interface that mimics the behavior of Python's `smtplib.SMTP`.

Example usage:
    injector = PostfixInjector()
    injector.set_sender("sender@example.com")
    injector.add_recipient("recipient@example.com")
    injector.set_message(raw_email_string)
    queue_id = injector.submit()
    print("Injected with queue ID:", queue_id)

You can also run the script standalone to inject a test message:
    $ ./postfix_injector.py --from sender@example.com --to recipient@example.com --file ./test.eml

Requires:
    - Python 3.6+
    - Postfix with accessible UNIX sockets at /var/spool/postfix/public/{cleanup,pickup}

"""

import time
import socket
import logging


class PostfixQueueError(Exception):
    """Raised when a message cannot be queued via the Postfix cleanup socket."""

    def __init__(self, message_id=None, reason=None):
        self.message_id = message_id
        self.reason = reason
        msg = f"Failed to queue message"
        if message_id:
            msg += f" {message_id}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class PostfixInjector:
    def __init__(
        self,
        cleanup_socket="/var/spool/postfix/public/cleanup",
        pickup_socket="/var/spool/postfix/public/pickup",
        timeout=1,
        maxwait=1,
    ):
        self.logger = logging.getLogger("PostfixInjector")
        self.logger.addHandler(logging.NullHandler())

        self.cleanup_socket = cleanup_socket
        self.pickup_socket = pickup_socket
        self.timeout = timeout
        self.maxwait = max(timeout, maxwait)
        self.timestamp = int(time.time())

        self.records = {
            "REC_TYPE_SIZE": "C",  # first record, created by cleanup
            "REC_TYPE_TIME": "T",  # time stamp, required
            "REC_TYPE_FULL": "F",  # full name, optional
            "REC_TYPE_INSP": "I",  # inspector transport
            "REC_TYPE_FILT": "L",  # loop filter transport
            "REC_TYPE_FROM": "S",  # sender, required
            "REC_TYPE_DONE": "D",  # delivered recipient, optional
            "REC_TYPE_RCPT": "R",  # todo recipient, optional
            "REC_TYPE_ORCP": "O",  # original recipient, optional
            "REC_TYPE_WARN": "W",  # warning message time
            "REC_TYPE_ATTR": "A",  # named attribute for extensions
            "REC_TYPE_MESG": "M",  # start message records
            "REC_TYPE_CONT": "L",  # long data record
            "REC_TYPE_NORM": "N",  # normal data record
            "REC_TYPE_XTRA": "X",  # start extracted records
            "REC_TYPE_RRTO": "r",  # return-receipt, from headers
            "REC_TYPE_ERTO": "e",  # errors-to, from headers
            "REC_TYPE_PRIO": "P",  # priority
            "REC_TYPE_VERP": "V",  # VERP delimiters
            "REC_TYPE_END": "E",  # terminator, required
        }

        self.flags = {
            "CLEANUP_FLAG_NONE": 0,  # /* No special features */
            "CLEANUP_FLAG_BOUNCE": (1 << 0),  # /* Bounce bad messages */
            "CLEANUP_FLAG_FILTER": (1 << 1),  # /* Enable header/body checks */
            "CLEANUP_FLAG_HOLD": (1 << 2),  # /* Place message on hold */
            "CLEANUP_FLAG_DISCARD": (1 << 3),  # /* Discard message silently */
            "CLEANUP_FLAG_BCC_OK": (1 << 4),  # /* Ok to add auto-BCC addresses */
            "CLEANUP_FLAG_MAP_OK": (1 << 5),  # /* Ok to map addresses */
            "CLEANUP_FLAG_MILTER": (1 << 6),  # /* Enable Milter applications */
        }
        self.flags.update(
            {
                "CLEANUP_FLAG_FILTER_ALL": (
                    self.flags["CLEANUP_FLAG_FILTER"]
                    | self.flags["CLEANUP_FLAG_MILTER"]
                )
            }
        )
        self.flags.update(
            {
                "CLEANUP_FLAG_MASK_EXTERNAL": (
                    self.flags["CLEANUP_FLAG_FILTER_ALL"]
                    | self.flags["CLEANUP_FLAG_BCC_OK"]
                    | self.flags["CLEANUP_FLAG_MAP_OK"]
                ),
                "CLEANUP_FLAG_MASK_INTERNAL": (self.flags["CLEANUP_FLAG_MAP_OK"]),
                "CLEANUP_FLAG_MASK_EXTRA": (
                    self.flags["CLEANUP_FLAG_HOLD"] | self.flags["CLEANUP_FLAG_DISCARD"]
                ),
            }
        )

        self._reset()

    def enable_debug(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s:%(name)s:%(filename)s:%(lineno)d: %(message)s",
        )
        self.logger.setLevel(logging.DEBUG)

    def _reset(self):
        self.sender = None
        self.recipients = []
        self.message = None
        self.attrs = {}
        self.msg_flags = self.flags["CLEANUP_FLAG_NONE"]
        self.content = bytearray()

    def set_sender(self, address):
        self.sender = address
        self.logger.debug(f"Set sender: {address}")

    def add_recipient(self, address):
        self.recipients.append(address)
        self.logger.debug(f"Added recipient: {address}")

    def set_message(self, msg_str):
        self.message = msg_str
        self.logger.debug("Message set.")

    def set_attribute(self, key, value):
        self.attrs[key] = value
        self.logger.debug(f"Set attribute: {key} = {value}")

    def set_flag(self, flag):
        self.msg_flags = self.msg_flags | flag
        self.logger.debug(f"Added flag: {flag}")

    def _connect(self):
        self.logger.debug(f"Connecting to cleanup socket: {self.cleanup_socket}")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.cleanup_socket)

    def _recv_line(self):
        line = bytearray()
        wait = 0
        while True:
            try:
                c = self.sock.recv(1)
            except socket.timeout:
                if wait >= (self.maxwait / self.timeout):
                    raise
                if len(line) == 0:
                    wait += 1
                    continue
            if not c:
                break
            line.extend(c)
            if line[-2:] == b"\x00\x00":
                line.append(ord("\n"))
                break
        self.logger.debug(f"Received line: {line}")
        return bytes(line[:-1])

    def _parse_attr_line(self, line):
        parts = line.strip(b"\n").split(b"\x00")
        self.logger.debug(f"Parsed parts: {parts}")
        it = iter(parts)
        return {k.decode(): v.decode() for k, v in zip(it, it) if k}

    def _get_attr(self):
        attrs = {}
        raw_data = self._recv_line()
        for line in raw_data.split():
            for k, v in self._parse_attr_line(line).items():
                attrs[k] = v
        self.logger.debug(f"Parsed attributes: {attrs}")
        return attrs

    def _encode_attr(self, attrs):
        ret = bytearray()
        for k, v in attrs.items():
            ret += k.encode() + b"\x00" + str(v).encode() + b"\x00"
        ret += b"\x00"
        self.logger.debug(f"Encoded attributes: {ret}")
        return ret

    def _build_rec(self, rec_type, data):
        try:
            content = bytearray()
            content.append(ord(self.records[rec_type]))
            ln = len(data)
            while ln >= 0x80:
                content.append((ln & 0x7F) | 0x80)
                ln >>= 7
            content.append(ln)
            if isinstance(data, str):
                data = data.encode("utf-8")
            content += data
            self.content += content
            self.logger.debug(
                f"Built record {rec_type} with length {len(data)}: {content}"
            )
        except KeyError:
            raise ValueError(f"Unknown record type: {rec_type}")

    def _build_msg_line(self, line):
        while len(line) > 1024:
            self._build_rec("REC_TYPE_CONT", line[:1024])
            line = line[1024:]
        self._build_rec("REC_TYPE_NORM", line)

    def submit(self):
        if not (self.sender and self.recipients and self.message):
            raise ValueError(
                "Sender, recipients, and message must be set before submitting"
            )

        self._connect()
        queue_id = self._get_attr()["queue_id"]
        self.logger.debug(f"Got queue_id: {queue_id}")

        attrs = {"flags": self.msg_flags}
        self.sock.sendall(self._encode_attr(attrs))
        self.logger.debug("Sent flags")

        self.set_attribute("rewrite_context", "local")
        self.set_attribute("log_ident", queue_id)
        for attr, val in self.attrs.items():
            self._build_rec("REC_TYPE_ATTR", f"{attr}={val}")

        self._build_rec("REC_TYPE_TIME", str(self.timestamp))
        self._build_rec("REC_TYPE_FROM", self.sender)

        for rcpt in self.recipients:
            self._build_rec("REC_TYPE_RCPT", rcpt)

        self._build_rec("REC_TYPE_MESG", "")

        for line in self.message.split(b"\n"):
            self._build_msg_line(line)

        self._build_rec("REC_TYPE_XTRA", "")
        self._build_rec("REC_TYPE_END", "")

        self.sock.sendall(self.content)
        self.logger.debug(f"Sent message content of length {len(self.content)}")
        res = self._get_attr()
        self.logger.debug(f"Got final response: {res}")
        self.sock.close()

        if res.get("status", None) == "0":
            self.logger.debug("Message queued successfully")
            if self.msg_flags & self.flags["CLEANUP_FLAG_HOLD"]:
                self.logger.debug("Skipping pickup call, message has HELD flag set")
            else:
                self._notify_pickup()
        else:
            raise (
                PostfixQueueError(message_id=queue_id, reason=res.get("reason", None))
            )

        return queue_id

    def _notify_pickup(self):
        self.logger.debug(f"Notifying pickup via socket: {self.pickup_socket}")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(self.pickup_socket)
        s.send(b"W")
        s.close()
