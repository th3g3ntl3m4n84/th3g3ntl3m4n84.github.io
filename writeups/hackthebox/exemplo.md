# Exemplo — Hack The Box (template)

Write-ups devem ser criados em **markdown** (.md) e podem incluir imagens na pasta `images/` desta mesma pasta.

## Estrutura

- Coloque cada write-up em um arquivo `.md` em `writeups/hackthebox/` (ou `vulnlab/`, `offsec/`).
- Imagens: use a pasta `images/` dentro da mesma plataforma, por exemplo:
  - `writeups/hackthebox/images/screenshot1.png`
  - No markdown: `![Descrição](images/screenshot1.png)` ou `![Descrição](./images/screenshot1.png)`.

## Exemplo de imagem

Adicione imagens em `writeups/hackthebox/images/` e use no markdown:  
`![Legenda](images/sua-imagem.png)`.

## Exemplo de código

```bash
nmap -sC -sV -oA scan 10.10.10.x
```

## Como adicionar um novo write-up

1. Crie `writeups/hackthebox/nome-da-maquina.md`.
2. Adicione imagens em `writeups/hackthebox/images/`.
3. Na página de write-ups, adicione um link:  
   `writeup.html?platform=htb&slug=nome-da-maquina`  
   (use `vulnlab` ou `offsec` e o slug correspondente para as outras plataformas).

---

*Este arquivo é um template. Substitua pelo conteúdo do seu write-up ou apague e crie novos .md com seus labs.*
