Brand specification for VEYRON. Every application surface, README, docs page,
and GitHub social preview uses this palette so the product reads as one
deliberate identity.

## 1. Mark

The mark is a geometric shield constructed from a stylised letter V. Four
inner chevrons point inward toward a centre point — evoking scanning focus,
convergence of evidence, and a protected boundary. The negative space forms
the V at the heart of VEYRON without relying on letters alone.

Variants:

- `veyron-icon.svg` — standalone mark (small-size recognisable; works at 16 px)
- `veyron-sidebar.svg` — square-safe mark for dashboard sidebar (24 × 24 px safe area)
- `veyron-favicon.svg` — simplified mark for browser tabs (16 × 16 px)
- `veyron-logo.svg` — full lockup: mark + wordmark "VEYRON"
- `veyron-mono.svg` — monochrome (single ink colour) for print/stamps
- `veyron-light.svg` — same geometry, colours chosen for light backgrounds
- `veyron-social.svg` — wide layout for GitHub social preview

All SVGs are self-contained: no `<script>`, no external references.

## 2. Colour palette

| Role | Use | Hex |
|---|---|---|
| Charcoal base | App/page backgrounds | `#0f172a` |
| Panel | Cards, surfaces | `#1e293b` |
| Border | Dividers | `#334155` |
| Ink | Primary text | `#f1f5f9` |
| Muted | Secondary text | `#94a3b8` |
| Accent | Primary brand, interactive | `#38bdf8` |
| Critical | Critical / high findings | `#ef4444` |
| Warn | Medium findings | `#f59e0b` |
| Safe | Validated, low, info | `#22c55e` |

All foreground colours meet WCAG AA contrast against the charcoal base.
Check monochrome legibility before producing print material.

## 3. Typography

- Headings: system-ui (`Segoe UI`, `Roboto`, sans-serif), bold, uppercase,
  letter-spacing 0.12–0.16 em, tracking tight.
- Body: system-ui, 13 px minimum, line-height 1.5, colour `#f1f5f9`.
- Code/data: Consolas, Menlo, monospace, 12 px.

## 4. Usage rules

- Do not stretch the mark; preserve aspect ratio.
- Do not recolour outside this palette.
- Do not add glow, drop shadow, or gradients not specified here.
- Keep ≥ 1/4 mark-height of clear space around the lockup.
- Never place another product's logo adjacent without explicit separation.

## 5. Accessibility

- All colours AA or better on charcoal backgrounds.
- Interactive states use both colour change and an underline/icon change.
- Dashboard renders without JavaScript dependency for data tables.
- Alt text on every image: "VEYRON logo" / "VEYRON mark".

## 6. Asset locations

`assets/logo/*.svg` — sources
`assets/veyron-social-preview.png` — GitHub social preview raster
