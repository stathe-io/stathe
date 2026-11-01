# Brand assets

The wordmark as vectors, and the LinkedIn images rendered from them. Keeping the
source here means the next size is a window-size argument rather than a redraw.

| File | What it is |
|---|---|
| `wordmark.svg` | "stathe" and the square, as paths. Use this anywhere the name appears as a logo |
| `mark.svg` | The "s" and the square, for small sizes where the full name does not survive |
| `stathe-linkedin-company-1128x191.png` | Company page cover, from `company.html` |
| `stathe-linkedin-company-2256x382.png` | The same at 2x, sharper on high-density screens; upload this one |
| `stathe-logo-600.png` | Company page logo, from `logo.html` |

The name is right of centre: LinkedIn drops the page logo over the left of the
cover, and the company card in search and the feed shows only its middle.

## Palette

Sampled from `docs/banner.png` rather than guessed.

| | |
|---|---|
| Ink (background) | `#0a1420` |
| Glow (radial, top) | `#0b2a32` |
| Wordmark | `#e8eef4` |
| Accent (the square) | `#19c7b2` |
| Muted text | `#8ba3ad` |

## Type

The wordmark is **Archivo Black**, the face `docs/banner.png` was drawn in,
outlined to paths so nothing depends on the font being installed. Running text
is **IBM Plex Sans**, as in the banner's tagline.

`fonts/` holds both, unmodified, with their licences (SIL OFL 1.1): the Archivo
Black TTF from `google/fonts`, and IBM's own Latin-1 cut of Plex Sans Variable
from `@ibm/plex-sans-variable` 0.2.0. Plex has a reserved font name, so use
IBM's files rather than a subset made elsewhere.

`wordmark.py` regenerates the SVGs from the Archivo Black TTF; how to run it is
at the top of the file.

## Rendering

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --hide-scrollbars --allow-file-access-from-files \
  --window-size=1128,191 \
  --screenshot=docs/brand/stathe-linkedin-company-1128x191.png \
  "file://$PWD/docs/brand/company.html"
```

The window size is the image size, so a new format needs no new artwork.
