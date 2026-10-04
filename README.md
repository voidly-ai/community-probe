# Voidly Community Probe

Run a volunteer measurement client from your own network and contribute observations to [Voidly's censorship research](https://voidly.ai/probes). The probe makes outbound DNS, TLS, and HTTP checks to a target list. It is not a VPN, proxy, relay, or anonymity tool.

**Read the [setup and consent guide](https://voidly.ai/probes/join) before starting.** Installing the package does not register a node or start measurements. Starting with `--consent` does both.

## Start the Python client

```bash
python -m pip install voidly-probe
voidly-probe --consent
```

Other commands:

```bash
voidly-probe --once          # one measurement cycle, then exit
voidly-probe --status        # read your node status
voidly-probe --interval 600  # change the cycle interval
voidly-probe --unregister    # remove the local identity file
```

The client saves a node identity and token in `~/.voidly/node.json` by default. Keep that file private. Registration, a running process, and accepted measurements are separate events; check your node status and logs before assuming results were contributed. `--unregister` removes local configuration; it does not erase already submitted observations or revoke a remote token.

The [Docker option and its persistent-volume behavior](https://voidly.ai/probes/join) are documented separately. The Docker launch command starts measurement immediately with consent.

## What leaves your machine

- The checked-in client rotates through a built-in target list. An installed package can be a different revision, so inspect its target list before running. Your ISP and the tested services can observe the requests.
- Submitted records can include the target, result, latency, blocking method, location, and time. A single node is one network vantage point, not a country-wide finding.
- By default, registration contacts `ipinfo.io` to estimate country and city. Set `VOIDLY_COUNTRY` and, optionally, `VOIDLY_CITY` before registration to skip that lookup.
- A location and measurement timeline may identify a node. Participation does not provide anonymity or a payment promise.

Read the [current data and consent details](https://voidly.ai/probes/join) and [methodology](https://voidly.ai/methodology). Voidly-original data and upstream measurements can have different license terms.

## Source and support

The checked-in Python client is [`voidly_probe.py`](voidly_probe.py). Compare the source revision with the release you install from [PyPI](https://pypi.org/project/voidly-probe/) when reviewing client behavior; package and repository revisions can differ. Report bugs through [GitHub issues](https://github.com/voidly-ai/community-probe/issues). Report security issues using [SECURITY.md](SECURITY.md).

Code license: [MIT](LICENSE).
