# Sentinela

Antivírus e limpador de arquivos para Windows, escrito em Rust (CLI). Varre arquivos com assinaturas de hash, regras YARA e heurísticas de executáveis PE, além de limpar lixo do sistema e encontrar arquivos grandes e duplicados.

> **Aviso:** o Sentinela é um projeto complementar e **não substitui** um antivírus completo. Mantenha o Windows Defender (Segurança do Windows) sempre ativo.

## Comandos

```
sentinela scan <caminho>... [--json] [--max-size <MB>] [--exclude <glob>]...
sentinela update
sentinela clean [--category <nome>]... [--apply] [--yes] [--json]
sentinela find-large <caminho> [--top <N>] [--min-size <MB>] [--json]
sentinela find-dupes <caminho> [--min-size <KB>] [--json]
sentinela info
```

Códigos de saída: `0` = nada encontrado / sucesso; `1` = achados (malware suspeito); `2` = erro global.

Categorias de `clean`: `user-temp`, `windows-temp`, `crash-dumps`, `browser-cache`, `recycle-bin`, `windows-update`. Sem `--category`, todas são consideradas.

## Como compilar

Requer o [Rust](https://rustup.rs) estável.

```bash
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

O binário fica em `target/release/sentinela` (`sentinela.exe` no Windows).

## Licença

MIT, veja [LICENSE](LICENSE).
