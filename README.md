# smtp2signalcli
This project creates an SMTP server that serves as a bridge to
[signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api/).
It receives incoming emails over SMTP and sends them to the specified
recipient phone number.

To use, copy the provided `config.yaml.template` to `config.yaml` and update
its contents to match your setup.

For now, the recipient phone number is specified in `config.yaml`, but we
could instead have the phone number be specified by the sending device in
the destination email address (which we currently ignore).
