# FuzzHTTPBypass

An existing Wfuzz wrapper for comparing HTTP path, method, header, and authentication variations in a CTF or an explicitly authorized test environment. A changed status or response body is an observation, not proof of an authentication bypass.

## Setup and offline checks

Python 3.10 or later:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python fuzzhttpbypass.py --help
python -m unittest discover -s tests -v
```

Wfuzz and Requests are loaded only when execution needs them; help and the mocked test suite work with the standard library alone. Wfuzz may require PycURL and platform build dependencies. Live Wfuzz installation/execution is not covered by this update's verification.

## Local-lab example

```bash
python fuzzhttpbypass.py -u http://127.0.0.1:8000/index.html -f notcontains,403
```

This executes the existing variation routines against the specified endpoint; it is not a single read-only GET and may use state-changing HTTP methods. Use only a disposable authorized lab. No targets were contacted while verifying this update.

Filter syntax is `contains,VALUE` or `notcontains,VALUE`. Numeric values from 100 through 599 select response codes; other values are text filters. Quote the whole filter when it contains spaces, such as `-f 'notcontains,Invalid Access'`. Wfuzz's text-filter interpretation remains its own behavior; quoting prevents arguments from being split but does not promise literal-regex matching.

## Reliability improvements

- Argument parsing honors an explicit argument list, enabling isolated tests.
- URL parsing handles ports and IPv6 literals and rejects invalid schemes, embedded credentials, fragments, and whitespace.
- IP detection uses ipaddress rather than counting dots; DNS resolution uses getaddrinfo.
- The baseline GET has a 30-second timeout and does not follow redirects.
- User-agent lists use unique temporary files, removed on normal completion and exceptions.
- Baseline cookie values are redacted from console output.
- Normal completion returns an exit code instead of terminating the process with SIGTERM.
- Imports and help perform no requests or DNS resolution.

The previously implemented variation lists are retained. This revision does not add new techniques or a broader scan mode.

## Limitations

Mocked tests verify parsing and orchestration, not successful bypasses or all Wfuzz/PycURL combinations. Existing known limitations with some HTTP methods, proxies, and Wfuzz filter semantics remain; verify them in a local lab. The wrapper does not establish authentication state, correlate outcomes with authorization rules, bound the full combinatorial run, or impose a whole-run deadline. Review the existing generated requests before use. Baseline cookie values are redacted, but response bodies and Wfuzz result output may still contain application data. Ctrl+C interrupts execution; hard process termination may leave a temporary file.

This is a security-tool maintenance example, not an ML or statistical-modeling project.
