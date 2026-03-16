# Example — Hack The Box (template)

Write-ups should be created in **markdown** (.md) and can include images in the `images/` folder in this same directory.

## Structure

- Put each write-up in a `.md` file under `writeups/hackthebox/` (or `vulnlab/`, `offsec/`).
- Images: use the `images/` folder within the same platform, e.g.:
  - `writeups/hackthebox/images/screenshot1.png`
  - In markdown: `![Caption](images/screenshot1.png)` or `![Caption](./images/screenshot1.png)`.

## Image example

Add images in `writeups/hackthebox/images/` and use in markdown:  
`![Caption](images/your-image.png)`.

## Code example

```bash
nmap -sC -sV -oA scan 10.10.10.x
```

## How to add a new write-up

1. Create `writeups/hackthebox/machine-name.md`.
2. Add images in `writeups/hackthebox/images/`.
3. On the write-ups page, add a link:  
   `writeup.html?platform=htb&slug=machine-name`  
   (use `vulnlab` or `offsec` and the matching slug for the other platforms).

---

*This file is a template. Replace it with your write-up content or remove it and create new .md files for your labs.*
