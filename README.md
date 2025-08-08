# pypostdrop
Python class to inject rfc822 mail messages straight into the Postfix queue

A Python-based tool to inject raw email messages directly into Postfix via the `cleanup` service socket.

Designed for developers, testers, and advanced users who want to programmatically submit email messages to Postfix without using SMTP.

## Features

- Inject raw RFC822 messages into Postfix
- Automatically adds a `Received:` header if missing
- Support for the `HOLD` queue flag
- CLI interface for scripting and automation
- Fully usable as a Python module

## Requirements

- Python 3.6+
- A running Postfix installation.
- Oermission to write to Postfix `cleanup` service socket.
- Permissions to write to Postfix’s `pickup` socket.
- This usually requires root or postfix group membership, suid might be an option as well.

## Installation

```bash
pip install postdrop
```

Or clone and install manually:

```bash
git clone https://github.com/ixs/postdrop.git
cd postdrop
pip install .
```
