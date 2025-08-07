import argparse
from textwrap import wrap
from email.parser import BytesParser
from email.policy import SMTP
from email.utils import formatdate
from .injector import PostfixInjector


def ensure_received_header(msg_bytes, hostname="localhost"):
    parser = BytesParser(policy=SMTP)
    msg = parser.parsebytes(msg_bytes)

    if any(h.lower() == "received" for h in msg.keys()):
        return msg_bytes

    now = formatdate(localtime=True)
    received_header = "\n".join(
        wrap(
            f"Received: from cli-injector by {hostname} with local (PostfixInjector); {now}",
            width=78,
            subsequent_indent="\t",
            break_long_words=False,
            break_on_hyphens=False,
        )
    )
    return received_header.encode() + b"\n" + msg.as_bytes()


def main():
    parser = argparse.ArgumentParser(
        description="Inject mail into Postfix via cleanup socket"
    )
    parser.add_argument("--from", dest="sender", required=True, help="Sender email")
    parser.add_argument(
        "--to", dest="recipient", action="append", required=True, help="Recipient email"
    )
    parser.add_argument(
        "--file", dest="msgfile", required=True, help="Path to raw RFC822 message file"
    )
    parser.add_argument(
        "--hold",
        dest="hold_flag",
        required=False,
        action="store_true",
        help="Inject message as HOLD",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        required=False,
        action="store_true",
        help="Debug output",
    )
    args = parser.parse_args()

    injector = PostfixInjector()
    if args.debug:
        injector.enable_debug()

    with open(args.msgfile, "rb") as f:
        raw_msg = f.read()
    raw_msg = ensure_received_header(raw_msg)
    injector.logger.debug(f"Got message: {raw_msg}")

    injector.set_flag(injector.flags["CLEANUP_FLAG_MASK_INTERNAL"])

    if args.hold_flag:
        injector.set_flag(injector.flags["CLEANUP_FLAG_HOLD"])

    injector.set_sender(args.sender)

    for rcpt in args.recipient:
        injector.add_recipient(rcpt)

    injector.set_message(raw_msg)

    qid = injector.submit()

    print("Successfully injected with queue ID:", qid)


if __name__ == "__main__":
    main()
