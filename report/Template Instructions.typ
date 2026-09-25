#import "lib.typ": *
#show: pwneers.with(
  title: [Pwneers Typst Template],
  subtitle: [Cybersecurity Study Group 2],
  author: [Pwneers Group 2],
  date: [Template guide],
)

#callout[
  This file is both documentation and a working example. Compile it with Typst
  to see the template features rendered in a real document.
]

= Getting started

Create a new `.typ` file in the `pwneers` folder, or place the template file
next to your document and import it at the top:

```typst
#import "lib.typ": *
```

The `#show: pwneers` line applies the page layout, typography, colors, heading
styles, footer and code-block styling. The reusable helpers are available by
name.

The template automatically creates a cover page, a table of contents and then
starts the document content on a new page. Customize the cover with:

```typst
#show: pwneers.with(
  title: [Network Security Lab Report],
  subtitle: [Web Application Assessment],
  author: [Your Name],
  date: [18 September 2026],
)
```

= Headings and document structure

Use normal Typst headings. They are numbered automatically and styled by level:

```typst
= Main section
== Subsection
=== Technical detail
==== Small detail
```

The first-level heading uses a dark blue/viola banner. Lower levels use the
accent purple and progressively smaller text.

== Suggested report structure

A typical Pwneers report can follow this structure:

1. Scope and objective
2. Environment and assumptions
3. Methodology
4. Findings and evidence
5. Exploitation or validation steps
6. Mitigations and conclusion

= Tables

Use `simple-table` when the table has custom headers or more than two columns:

#simple-table(
  ([*ID*], [*Severity*], [*Finding*]),
  (
    ([PW-01], [High], [Weak SSH password]),
    ([PW-02], [Medium], [Verbose error message]),
  ),
  columns: (auto, auto, 1fr),
)

For key/value information, use the shorter `info-table` helper:

#info-table((
  ([Target], [10.0.0.12]),
  ([OS], [Ubuntu 24.04]),
  ([Tools], [Nmap, Burp Suite, Wireshark]),
))

Table rows are arrays of cells. Cells can contain normal Typst markup, such as
`[*bold text*]`, links or lists.

= Screenshots and evidence

Use `screenshot` for screenshots, command output captures and other visual
evidence. The path is relative to the importing `.typ` file:

```typst
#screenshot(
  "screenshots/login-page.png",
  caption: [Login page observed during reconnaissance.],
  width: 90%,
)
```

The same helper can display an image already stored elsewhere in this
repository. The example below uses an existing project screenshot:

#screenshot(
  "img/example.png",
  caption: [Example screenshot included in the repository.],
  width: 88%,
)

For a clean project layout, keep evidence files in a folder such as
`screenshots/` next to the report and use descriptive names.

= Code blocks

Fenced raw blocks are styled automatically. Add a language after the opening
backticks when syntax highlighting is useful. Use `bash` for shell commands;
the template maps it to Typst's shell lexer:

```bash
nmap -sV -p- 10.0.0.12
```

For generated or variable-based source code, use `code-block`:

#code-block(
  "curl -i https://target.example/api/users\n\n# Inspect the response headers",
  lang: "bash",
)

`code-block` expects a string. Use `\\n` inside the string for line breaks.
The font is JetBrains Mono and the light background keeps syntax colors readable.

= Notes and warnings

Use `callout` for context that should stand out without interrupting the flow:

#callout[
  Record the exact command, target and timestamp for every reproducible test.
]

Use `warning` for security-sensitive or potentially destructive steps:

#warning[
  Do not run exploit payloads against systems without explicit authorization.
]

Both helpers accept normal Typst content, including emphasis, links and lists.

= Available colors

The main palette is exposed as reusable variables:

#simple-table(
  ([*Variable*], [*Use*]),
  (
    ([pwneers-ink], [Dark text and code blocks]),
    ([pwneers-primary], [Main blue/purple]),
    ([pwneers-accent], [Secondary accent]),
    ([pwneers-surface], [Alternating table rows]),
    ([pwneers-muted], [Secondary text]),
    ([pwneers-danger], [Warnings]),
  ),
  columns: (1.5fr, 2fr),
)

Prefer the predefined colors so that future palette changes can be made in one
place, inside `lib.typ`.
