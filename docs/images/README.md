# About the images

`usage-log.png` and `usage-log-dark.png` show **the window's page**
(`elasticdms::window::page()`) with the sample data from `--demo`, rendered in a browser.

**They are not captures of the running window.** Screen recording is not permitted to the processes
that built this repository (`screencapture` fails without the “Screen Recording” right). What was
rendered is the same HTML output the window loads — so the content is right, the window decoration
is missing.

That the real window runs is shown differently: started with
`EDMS_LOG=debug ./target/debug/elasticdms --demo --window` the page reports back over
`window.ipc.postMessage`, and Rust logs

```
DEBUG elasticdms::window: window opened. x=… y=… width=840 height=672 scale=1
DEBUG elasticdms::event_loop: the user interface is ready. language=… time_zone=…
```

The second line is the proof for the whole chain: the policy (CSP with a nonce) admits the embedded
script, the script runs, and its message arrives in Rust.

Producing them yourself (writes the page with demo data as an HTML file, the same route the window
takes):

```sh
cargo test -p elasticdms -- --ignored write_preview --nocapture
```

The page carries keys, not sentences (ADR-D10): the test renders the language of its own run and
puts it into the file name, so `EDMS_LANG=de` writes the German page and `EDMS_LANG=en` the English
one — one picture per language, out of one tool. The two files here show the German view, the one
the first customers see.
