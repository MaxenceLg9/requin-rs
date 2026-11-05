# Capture regression corpus

Put each user-provided `.pcap`, `.pcapng`, or `.cap` file in this directory and
add a same-basename `.expect` file. The sidecar is UTF-8 `key=value`, with
`frames=<count>` required and optional `protocol.<summary-name>=<count>` rows.
Blank lines and `#` comments are ignored. Example:

```text
frames=42
protocol.IPv4=30
protocol.TCP=8
protocol.DNS=4
```

The corpus test runs the real streaming parser and checks every frame. Keep
captures anonymized and limited to test traffic before adding them to a commit.
