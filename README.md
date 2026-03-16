# Portfolio — Joao Paulo Figueiredo Guedes

Site pessoal em estilo hacker/cybersecurity, preparado para **GitHub Pages**.

## Estrutura

```
.
├── index.html          # Página principal (sobre, formação, experiência, certificações, projetos, apresentações)
├── writeups.html       # Listagem de write-ups (HTB, VulnLab, OffSec)
├── writeup.html        # Visualizador de write-up (renderiza .md com imagens)
├── css/
│   └── styles.css
├── writeups/
│   ├── hackthebox/     # Write-ups Hack The Box
│   │   ├── exemplo.md  # Template
│   │   └── images/
│   ├── vulnlab/
│   │   └── images/
│   └── offsec/
│       └── images/
└── README.md
```

## Publicar no GitHub Pages

1. Crie um repositório no GitHub (ex.: `username/website`).
2. Envie os arquivos deste projeto para o repositório.
3. Em **Settings → Pages**, escolha **Deploy from a branch**.
4. Branch: **main** (ou **master**), pasta **/ (root)**.
5. O site ficará em `https://username.github.io/website/`.

## Adicionar write-ups

- **Hack The Box:** crie `writeups/hackthebox/nome-da-maquina.md` e coloque imagens em `writeups/hackthebox/images/`. No markdown use `![Legenda](images/arquivo.png)`.
- **VulnLab:** mesmo esquema em `writeups/vulnlab/` e `writeups/vulnlab/images/`.
- **OffSec:** mesmo esquema em `writeups/offsec/` e `writeups/offsec/images/`.

Depois adicione um card na página `writeups.html` com o link:

- `writeup.html?platform=htb&slug=nome-da-maquina`
- `writeup.html?platform=vulnlab&slug=nome-do-arquivo`
- `writeup.html?platform=offsec&slug=nome-do-arquivo`

O parâmetro `slug` é o nome do arquivo **sem** a extensão `.md`.
# th3g3ntl3m4n84.github.io
