# Sentinela

Antivírus e limpador de arquivos para Windows, escrito em Rust (linha de comando). Varre arquivos com assinaturas de hash (SHA-256), regras YARA e heurísticas de executáveis PE, além de limpar lixo do sistema e encontrar arquivos grandes e duplicados. Distribuído como um único `sentinela.exe`, sem dependências externas.

> **Aviso importante:** o Sentinela é um projeto complementar e **não substitui** um antivírus completo. **Mantenha o Windows Defender (Segurança do Windows) sempre ativo.**

> **Falsos positivos:** regras YARA da comunidade e heurísticas de PE podem marcar arquivos legítimos como suspeitos. Um achado `[SUSPEITO]` é um alerta para você investigar, não uma sentença: confira o arquivo (por exemplo no VirusTotal) antes de apagá-lo. O Sentinela **nunca apaga nem move** arquivos encontrados pela varredura.

## Download

Baixe o `sentinela.exe` mais recente na página de [releases](https://github.com/Luz-Lucas/sentinela/releases).

## Comandos

```
sentinela scan <caminho>... [--json] [--max-size <MB>] [--exclude <glob>]...
sentinela update
sentinela clean [--category <nome>]... [--apply] [--yes] [--json]
sentinela find-large <caminho> [--top <N>] [--min-size <MB>] [--json]
sentinela find-dupes <caminho> [--min-size <KB>] [--json]
sentinela info
```

### Códigos de saída

| Código | Significado |
| --- | --- |
| `0` | Sucesso / nada encontrado |
| `1` | Achados de malware (`scan` encontrou algo suspeito ou malicioso) |
| `2` | Erro global (caminho inexistente, categoria inválida, falha de rede no `update`, uso incorreto) |

Erros em arquivos individuais (acesso negado, arquivo em uso) **não** interrompem a execução: aparecem em "Não verificados" no texto ou em `errors` no JSON.

### `scan`: verificar arquivos e pastas

```
> sentinela scan C:\Users\eu\Downloads
Verificados: 1342 | Maliciosos: 1 | Suspeitos: 1 | Erros: 2
[MALICIOSO] C:\Users\eu\Downloads\crack.exe — sha256:3f9a…
[SUSPEITO] C:\Users\eu\Downloads\setup.exe — pe-heuristics

Não verificados:
  C:\Users\eu\Downloads\bloqueado.tmp — acesso negado
```

- `--json`: saída estável em JSON, um objeto com `version` (1), `summary`, `items` e `errors`.
- `--max-size <MB>` (padrão `256`): arquivos maiores que isso só têm o hash calculado (em streaming), sem análise de conteúdo.
- `--exclude <glob>` (repetível): ignora caminhos que casam com o glob, por exemplo `--exclude "**/node_modules/**" --exclude "**/*.iso"`.
- Links simbólicos e junctions nunca são seguidos.
- `Ctrl+C` interrompe a varredura e imprime o relatório parcial.

```
sentinela scan C:\Users\eu\Downloads D:\Projetos --max-size 100 --exclude "**/*.iso" --json
```

### `update`: baixar assinaturas

```
> sentinela update
Banco atualizado em C:\Users\eu\AppData\Local\Sentinela\db
  Hashes: 48213
  Regras YARA: 112 arquivo(s) aceito(s), 3 rejeitado(s), 640 regra(s) no total
```

O banco fica em `%LOCALAPPDATA%\Sentinela\db` (altere com a variável `SENTINELA_DB_DIR`; o `update` recusa substituir uma pasta existente, não vazia, que não pareça um banco do Sentinela — sem `manifest.json`, `hashes.txt` ou `rules/` — então aponte para uma pasta vazia ou inexistente). Se o banco ainda não foi inicializado, o `scan` avisa no stderr. Sem rodar `update`, o `scan` ainda funciona com a assinatura embutida do arquivo de teste EICAR.

Os hashes vêm do MalwareBazaar (abuse.ch), que exige uma chave de autenticação **gratuita**: crie uma conta em <https://auth.abuse.ch/> e defina a variável de ambiente `ABUSE_CH_AUTH_KEY`:

```
> set ABUSE_CH_AUTH_KEY=sua-chave
> sentinela update
```

No PowerShell: `$env:ABUSE_CH_AUTH_KEY = "sua-chave"`. Sem a chave, apenas as regras YARA são atualizadas e um aviso é exibido. A chave nunca é impressa.

### `clean`: limpeza de arquivos temporários

**Sem `--apply`, o `clean` é apenas uma simulação: nada é apagado.** Ele lista o que seria removido e o espaço que seria liberado:

```
> sentinela clean
user-temp      812 arquivo(s), 1.4 GB
windows-temp   pulada (requer administrador)
crash-dumps    3 arquivo(s), 96.0 MB
browser-cache  4210 arquivo(s), 2.1 GB
    aviso: Chrome está em execução; cache ignorado
recycle-bin    57 arquivo(s), 340.2 MB
windows-update pulada (requer administrador)

Total que seria liberado: 5082 arquivo(s), 3.9 GB. Simulação: nada foi apagado; use --apply para limpar.
```

Para apagar de verdade, use `--apply`. O Sentinela lista (no stderr) cada categoria com arquivos e tamanho, avisa quando a Lixeira será esvaziada permanentemente, lista as categorias ignoradas (ex.: requer administrador) e pergunta `[s/N]` (qualquer resposta diferente de `s`, `S` ou `sim` cancela). Use `--yes` para pular a pergunta (útil em scripts):

```
> sentinela clean --category user-temp --category crash-dumps --apply
Apagar 815 arquivo(s), 1.5 GB no total? [s/N] s
```

Antes de cada exclusão o caminho é revalidado: precisa estar dentro de uma pasta permitida da categoria e não pode ser link. Arquivos em uso ou sem permissão são pulados e contabilizados. Categorias que exigem administrador são puladas com aviso quando o programa não está elevado (execute o terminal como administrador para incluí-las).

Categorias e o que cada uma apaga (use `--category <nome>`, repetível; sem ela, todas):

| Categoria | O que apaga | Admin |
| --- | --- | --- |
| `user-temp` | Arquivos de `%TEMP%` com mais de 24 horas | não |
| `windows-temp` | Arquivos de `%SystemRoot%\Temp` com mais de 24 horas | sim |
| `crash-dumps` | `%LOCALAPPDATA%\CrashDumps`; também `%SystemRoot%\Minidump` e os relatórios `ReportArchive` e `ReportQueue` do WER em `%ProgramData%\Microsoft\Windows\WER` | parcial (Minidump e WER) |
| `browser-cache` | Somente as pastas `Cache`, `Code Cache` e `GPUCache` dos perfis de Chrome, Edge e Brave, e `cache2` do Firefox. **Nunca** toca em cookies, histórico, senhas ou dados de perfil. Com o navegador aberto, a categoria é pulada com aviso | não |
| `recycle-bin` | Esvazia a Lixeira (sem janelas de confirmação do Windows) | não |
| `windows-update` | `%SystemRoot%\SoftwareDistribution\Download`. Ao aplicar, para o serviço `wuauserv`, apaga e reinicia o serviço, mesmo que a exclusão falhe | sim |

Com `--json`, o resultado segue o mesmo envelope: `summary` com `files`, `bytes`, `deleted` e `freed`; `items` com uma entrada por categoria (`id`, `plan`, `applied`, `skipped_reason`); e `errors` com os arquivos pulados.

### `find-large`: maiores arquivos

```
> sentinela find-large D:\ --top 3 --min-size 500
   4.2 GB  D:\VMs\win11.vhdx
   1.8 GB  D:\Videos\viagem.mkv
 612.0 MB  D:\Instaladores\jogo.iso
```

Padrões: `--top 20`, `--min-size 0` (em MB). Somente lista; nunca apaga.

### `find-dupes`: arquivos duplicados

```
> sentinela find-dupes D:\Fotos --min-size 100
2 x 9f2c1a7b03de (3.1 MB cada)
    D:\Fotos\2024\img_001.jpg
    D:\Fotos\backup\img_001.jpg

Espaço desperdiçado: 3.1 MB
```

Agrupa por tamanho, depois pelo hash dos primeiros 64 KB e por fim pelo SHA-256 completo. Padrão `--min-size 1` (em KB). Somente relata grupos; **nunca apaga**.

### `info`

```
> sentinela info
sentinela 0.1.0
Banco de assinaturas: C:\Users\eu\AppData\Local\Sentinela\db
  malwarebazaar-recent — atualizado em 2026-10-22T12:00:00Z (48213 itens)
  yara-forge-core — atualizado em 2026-10-22T12:00:00Z (640 itens)
Executando como administrador: não
```

Sem banco local: `banco não inicializado — rode `sentinela update``.

## Como compilar

Requer o [Rust](https://rustup.rs) estável.

```bash
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

O binário fica em `target/release/sentinela` (`sentinela.exe` no Windows). Ao publicar uma tag `v*`, o GitHub Actions compila no Windows e cria a release automaticamente com o `sentinela.exe`.

## Licença

MIT, veja [LICENSE](LICENSE).

## Links e arquivos somente na nuvem

O `scan` e o `find` não seguem links simbólicos nem junções; cada um é listado como erro (`link simbólico/junção ignorado`), inclusive quando a pasta raiz é um link. Arquivos do OneDrive (Files On-Demand) que ainda não foram baixados não são lidos, para não disparar o download: aparecem como erro `arquivo somente na nuvem (não baixado); não verificado`. Já a limpeza (`clean`) é mais estrita e recusa qualquer ponto de reanálise. A idade mínima de 24 h dos temporários considera a mais recente entre a data de modificação e a de criação.
