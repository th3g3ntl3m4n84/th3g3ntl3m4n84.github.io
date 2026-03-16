# Portfolio — Joao Paulo Figueiredo Guedes

Personal site with a hacker/cybersecurity style, ready for **GitHub Pages**.

## Structure

```
.
├── index.html          # Main page (about, education, experience, certifications, projects, presentations)
├── writeups.html       # Write-ups listing (HTB, VulnLab, OffSec)
├── writeup.html        # Write-up viewer (renders .md with images)
├── css/
│   └── styles.css
├── writeups/
│   ├── hackthebox/     # Hack The Box write-ups
│   │   ├── exemplo.md  # Template
│   │   └── images/
│   ├── vulnlab/
│   │   └── images/
│   └── offsec/
│       └── images/
└── README.md
```

## Deploy to GitHub Pages

1. Create a repository on GitHub (e.g., `username/website`).
2. Push this project's files to the repository.
3. Go to **Settings → Pages**, choose **Deploy from a branch**.
4. Branch: **main** (or **master**), folder **/ (root)**.
5. The site will be at `https://username.github.io/website/`.

## Adding write-ups

- **Hack The Box:** Create `writeups/hackthebox/machine-name.md` and put images in `writeups/hackthebox/images/`. In markdown use `![Caption](images/file.png)`.
- **VulnLab:** Same layout in `writeups/vulnlab/` and `writeups/vulnlab/images/`.
- **OffSec:** Same layout in `writeups/offsec/` and `writeups/offsec/images/`.

Then add a card on the `writeups.html` page with the link:

- `writeup.html?platform=htb&slug=machine-name`
- `writeup.html?platform=vulnlab&slug=filename`
- `writeup.html?platform=offsec&slug=filename`

The `slug` parameter is the filename **without** the `.md` extension.
