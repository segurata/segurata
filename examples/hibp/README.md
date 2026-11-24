# securizame-hibp

An external securizame connector in Python 3 (standard library only) that asks
[Have I Been Pwned](https://haveibeenpwned.com/API/v3) which breaches include your email
addresses. It is also the reference example of the external protocol
([docs/connectors.md](../../docs/connectors.md)).

## Install

```bash
ln -s "$PWD/examples/hibp/securizame-hibp" ~/.local/bin/securizame-hibp   # any directory on PATH
securizame connectors | grep hibp                                         # describe loaded
```

The HIBP breach search needs a paid API key (<https://haveibeenpwned.com/API/Key>). Keep it in the
Keychain, never in the config:

```bash
security add-generic-password -s securizame-hibp -a "$USER" -w
```

and reference it in `~/.config/securizame/config.json`:

```json
"hibp": {
  "config": {"emails": ["you@example.com", "work@example.org"]},
  "secrets": {"HIBP_API_KEY": "keychain:securizame-hibp"}
}
```

Then `securizame inventory hibp`. Without the key it reports a `missing_credentials` status with
these steps.

| Config key | Default | Meaning |
|---|---|---|
| `emails` | required | Addresses to check |
| `request_delay_seconds` | 6 | Pause between addresses; 6 s keeps within 10 requests a minute. Lower it if your key allows more (`GET /subscription/status`, field `Rpm`) |
| `include_unverified` | true | `false` leaves out breaches HIBP has not verified |
| `base_url` | `https://haveibeenpwned.com/api/v3` | For tests only; anything other than https, or http on localhost, is refused so the key never goes elsewhere |

## What it reports

One `exposure` finding per breach and address, from
`GET /breachedaccount/{email}?truncateResponse=false` with the `hibp-api-key` header and the user
agent `securizame-hibp`. The resource id is the breach's `Name`, which HIBP never changes, so ids
stay stable across runs. Evidence: domain, breach and publication dates, data classes, size, and
HIBP's flags (verified, sensitive, spam list, malware, stealer log).

| Severity | When |
|---|---|
| `high` | Passwords or password hints exposed, however old: the password may be reused elsewhere |
| `medium` | Card, bank, ID, security-question, auth-token or private-message data, no password |
| `low` | Anything else (addresses, names, usernames) |
| one level up | Breached or published within the last year (passwords then become `critical`) |
| one level down | Over five years old and no password |
| `low` at most / `info` | Spam lists / breaches HIBP considers fabricated |

Remediation (manual): change the password at the breached site and anywhere it was reused, and turn
on two-factor authentication.

Statuses: `ok` per address (`not in any breach HIBP can disclose` on a 404, or the breach count);
`missing_credentials` without a key or when HIBP rejects it (401, which stops the run); `error` on
403 (stops), 400 (that address), repeated 429 after honouring `retry-after` three times, 503, or no
network. The key is sent only in the header and never printed.

Checking passwords against Pwned Passwords is out of scope.

## Test

```bash
cd examples/hibp && python3 -m unittest
```

The tests run a fake HIBP server on 127.0.0.1; nothing reaches the real API.
