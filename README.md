# smtp2signalcli
This script creates an SMTP server that receives incoming emails over SMTP
and forwards them to a
[Signal CLI REST API](https://github.com/bbernhard/signal-cli-rest-api/).
Recipients are extracted from the destination email addresses: The domain
part of the email address is ignored, and the local part is checked for
either a phone number, group ID, or an alias specified in the `RECIPIENT_MAP`
in the `config.yaml`.

To use the script, rename the provided `config.yaml.template` to `config.yaml`
and update its contents to match your configuration.
