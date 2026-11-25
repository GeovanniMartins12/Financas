# Finanças

Controle financeiro pessoal (app web instalável no iPhone).

## Segurança
- Os dados ficam no aparelho. A cópia na nuvem é **cifrada no próprio iPhone** (AES-256-GCM) com uma chave derivada da sua senha (PBKDF2-SHA256, 600 mil rodadas). A senha nunca sai do aparelho.
- O servidor (`worker/`, Cloudflare Workers + KV) guarda só blocos ilegíveis, nomes opacos e a agenda de avisos (datas + textos cifrados). Ele não consegue ler nomes, valores nem lançamentos.
- As notificações são cifradas duas vezes: com a sua chave e com a criptografia padrão do Web Push. Só o iPhone decifra o texto.
- O acesso ao servidor usa um token derivado da senha (o servidor guarda só o SHA-256 dele) e é bloqueado por 1 hora após 10 tentativas erradas.
- Este repositório contém apenas código, nunca dados.

## Publicação
- App: GitHub Pages (branch `main`, raiz).
- Servidor: `.github/workflows/deploy-worker.yml` publica na Cloudflare usando os segredos `CLOUDFLARE_API_TOKEN` e `CLOUDFLARE_ACCOUNT_ID`, e grava o endereço em `config.js`.
