// Usage in a document:
// #import "lib.typ": *
// #show: pwneers

// --- PALETTE ----------------------------------------------------------------
#let pwneers-ink = rgb("#17152D")
#let pwneers-primary = rgb("#302B63")
#let pwneers-accent = rgb("#6857C7")
#let pwneers-table-header = rgb("#5A4F9F")
#let pwneers-accent-light = rgb("#EAE7FF")
#let pwneers-surface = rgb("#F6F5FC")
#let pwneers-code-surface = rgb("#F0EEFA")
#let pwneers-border = rgb("#D8D5EA")
#let pwneers-muted = rgb("#66627A")
#let pwneers-danger = rgb("#B42318")

#let pwneers-code-lang(lang) = if lang == "bash" { "sh" } else { lang }

// --- TEMPLATE ---------------------------------------------------------------
// Set/show rules must live in a template function to affect the importing file.
#let pwneers(
  body,
  title: "Pwneers report",
  subtitle: none,
  author: none,
  date: none,
  logo: "img/logo.png",
) = {
  set page(
    paper: "a4",
    margin: (top: 24mm, bottom: 22mm, left: 25mm, right: 25mm),
    header: none,
    footer: context [
      #set text(size: 8pt, fill: pwneers-muted)
      #line(length: 100%, stroke: 0.5pt + pwneers-border)
      #v(0.35em)
      pwneers - page #counter(page).display()
    ],
  )

  set text(font: "Calibre", size: 11pt, fill: pwneers-ink, lang: "en")
  set par(justify: true, leading: 0.65em)
  set block(breakable: true)
  set list(indent: 1.2em)
  set enum(indent: 1.2em)
  set heading(numbering: "1.1")

  show heading.where(level: 1): it => {
    v(0.9em)
    block(
      width: 100%,
      inset: (left: 0.8em, top: 0.45em, bottom: 0.45em),
      fill: pwneers-primary,
      radius: 3pt,
    )[
      #text(size: 15pt, weight: "bold", fill: white)[
        #if it.numbering != none {
          counter(heading).display(it.numbering)
          h(0.55em)
        }
        #it.body
      ]
    ]
    v(0.45em)
  }

  show heading.where(level: 2): it => {
    v(0.65em)
    text(size: 12.5pt, weight: "bold", fill: pwneers-primary)[
      #if it.numbering != none {
        counter(heading).display(it.numbering)
        h(0.45em)
      }
      #it.body
    ]
    line(length: 100%, stroke: 0.8pt + pwneers-accent-light)
    v(0.25em)
  }

  show heading.where(level: 3): it => {
    v(0.5em)
    text(size: 11pt, weight: "bold", fill: pwneers-accent)[
      #if it.numbering != none {
        counter(heading).display(it.numbering)
        h(0.4em)
      }
      #it.body
    ]
    v(0.15em)
  }

  show heading.where(level: 4): it => {
    v(0.35em)
    text(size: 10.5pt, weight: "bold", fill: pwneers-muted)[#it.body]
    v(0.1em)
  }

  // Light background keeps syntax colors readable.
  show raw.where(block: true): it => block(
    width: 100%,
    fill: pwneers-code-surface,
    stroke: 0.5pt + pwneers-border,
    radius: 5pt,
    inset: 0.8em,
    above: 0.5em,
    below: 0.5em,
  )[
    #set text(font: "JetBrainsMono NF", size: 8.8pt, fill: pwneers-ink)
    #it
  ]

  // Cover page: no header/footer, only title and document information.
  page(header: none, footer: none)[
    #align(center)[
      #v(2cm)
      #image(logo, width: 40%)
      #v(2.2cm)
      #text(size: 34pt, weight: "bold", fill: pwneers-primary)[#title]
      #if subtitle != none {
        v(0.8em)
        text(size: 14pt, fill: pwneers-accent)[#subtitle]
      }
      #v(1fr)
      #line(length: 100%, stroke: 0.8pt + pwneers-accent)
      #v(0.55em)
      #if author != none {
        text(size: 11pt)[#author]
      }
      #if date != none {
        linebreak()
        text(size: 10pt, fill: pwneers-muted)[#date]
      }
    ]
  ]

  // The outline can span multiple pages. Content starts on a fresh page after it.
  pagebreak()
  outline(title: [Contents], depth: 3)
  pagebreak()
  body
}

// --- TABLES -----------------------------------------------------------------
#let simple-table(headers, rows, columns: auto, align: left) = {
  block(
    width: 100%,
    clip: true,
    radius: 5pt,
    stroke: 0.5pt + pwneers-border,
  )[
    #table(
      columns: columns,
      align: align,
      inset: 0.65em,
      stroke: (x, y) => if y == 0 {
        1pt + pwneers-table-header
      } else {
        0.5pt + pwneers-border
      },
      fill: (x, y) => if y == 0 {
        pwneers-table-header
      } else if calc.odd(y) {
        pwneers-surface
      } else {
        none
      },
      ..headers.map(header => [
        #text(font: "Calibre", size: 9.5pt, weight: "medium", fill: white)[#header]
      ]),
      ..rows.flatten(),
    )
  ]
}

#let info-table(rows) = simple-table(
  ([*Item*], [*Details*]),
  rows,
  columns: (auto, 1fr),
)

// --- SCREENSHOTS ------------------------------------------------------------
#let screenshot(path, caption: none, width: 100%) = figure(
  image(path, width: width),
  caption: caption,
)

// --- CODE -------------------------------------------------------------------
#let code-block(source, lang: none) = block(
  width: 100%,
  fill: pwneers-code-surface,
  stroke: 0.5pt + pwneers-border,
  radius: 5pt,
  inset: 0.8em,
  above: 0.5em,
  below: 0.5em,
)[
  #set text(font: "JetBrainsMono NF", size: 8.8pt, fill: pwneers-ink)
  #raw(source, lang: pwneers-code-lang(lang), block: true)
]

// --- NOTES ------------------------------------------------------------------
#let callout(body, title: "Note", color: pwneers-accent) = block(
  width: 100%,
  radius: 5pt,
  fill: color.lighten(88%),
  stroke: (left: 3pt + color),
  inset: (left: 0.8em, right: 0.8em, top: 0.55em, bottom: 0.55em),
)[
  #text(weight: "bold", fill: color)[#title]
  #linebreak()
  #body
]

#let warning(body) = callout(body, title: "Warning", color: pwneers-danger)
