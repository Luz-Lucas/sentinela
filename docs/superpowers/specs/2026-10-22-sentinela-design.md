# Sentinela — Design

Data: 2026-10-22
Status: aguardando revisão

## 1. Objetivo

Ferramenta de linha de comando para Windows, de uso pessoal real, que:

1. **Varre sob demanda** arquivos e pastas em busca de malware (segunda opinião ao Microsoft Defender, que deve continuar ativo).
2. **Limpa arquivos desnecessários** (temporários, cache de navegadores, Lixeira, cache do Windows Update).
3. **Encontra arquivos grandes e duplicados** para o usuário decidir o que fazer.

Critérios de sucesso:
- Detecta o arquivo de teste EICAR e qualquer hash presente no banco local.
- Varre uma pasta com milhares de arquivos sem travar por causa de um arquivo bloqueado ou corrompido.
- Nunca apaga nada fora das pastas permitidas de cada categoria de limpeza, nem sem `--apply`.
- Distribuído como um único `sentinela.exe`, sem dependências externas.

### Fora do escopo (v1)

Proteção em tempo real, quarentena ou remoção de malware, interface gráfica, limpeza de registro, otimização de serviços ou inicialização. A varredura **só relata**.

## 2. Decisões

| Decisão | Escolha | Motivo |
|---|---|---|
| Linguagem | Rust (edição 2021, toolchain estável) | `.exe` único, rápido e com memória segura ao analisar arquivos hostis. |
| Motor YARA | crate `yara-x` | Implementação nativa em Rust mantida pela VirusTotal; dispensa libyara em C. |
| Parser de PE | crate `goblin` | Parser puro em Rust, sem dependências nativas. |
| CLI | crate `clap` (derive) | Padrão do ecossistema. |
| Paralelismo | crate `rayon` | Pool de threads simples para a varredura. |
| Hash | crate `sha2` | SHA-256. |
| HTTP | crate `ureq` com `rustls` | Cliente síncrono pequeno, TLS sem OpenSSL. |
| Saída JSON | `serde` + `serde_json` | — |
| Nome do binário | `sentinela` | — |
| Repositório | `github.com/Luz-Lucas/sentinela`, público | Escolha do usuário. |

## 3. Comandos

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

## 4. Arquitetura

Um crate binário, com módulos de responsabilidade única:

```
src/
  main.rs              # só chama cli::run()
  cli.rs               # definição clap e despacho
  walker.rs            # percurso seguro de diretórios
  scan/
    mod.rs             # orquestra a varredura e o veredito
    detector.rs        # trait Detector + tipos Finding/Severity
    hash.rs            # detector por SHA-256
    yara.rs            # detector YARA (yara-x)
    pe.rs              # heurísticas de PE
  signatures.rs        # localização, carga e troca atômica do banco
  updater.rs           # download e validação de feeds
  clean/
    mod.rs             # orquestra simulação e aplicação
    category.rs        # trait Category + resolução de caminhos
    categories.rs      # as seis categorias concretas
    platform.rs        # chamadas Windows (admin, serviço wuauserv, Lixeira)
  finder.rs            # arquivos grandes e duplicados
  report.rs            # saída texto e JSON
```

### 4.1 `walker`

- Entrada: raízes, exclusões (globs) e opção de limite de tamanho.
- Saída: iterador de `Entry { path, size }` ou `WalkError { path, reason }`.
- Não segue links simbólicos nem *junctions/reparse points*.
- Erros por arquivo não interrompem o percurso.
- Compartilhado por `scan`, `clean` e `finder`.

### 4.2 Detectores

```rust
trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn inspect(&self, file: &FileData) -> Vec<Finding>;
}
struct FileData<'a> { path: &'a Path, bytes: &'a [u8], sha256: [u8; 32] }
struct Finding { detector: &'static str, rule: String, severity: Severity, detail: String }
enum Severity { Info, Suspicious, Malicious }
```

- **hash**: `HashSet<[u8; 32]>` carregado do banco. Casou → `Malicious`.
- **yara**: regras compiladas uma vez. A severidade vem da metadata `severity` da regra (`malicious` / `suspicious`); sem metadata, vale `Suspicious`.
- **pe**: só atua em arquivos com cabeçalho `MZ`/PE válido. Sinais: entropia de seção > 7.2, seção ao mesmo tempo gravável e executável, ponto de entrada fora da seção de código, nomes de seção típicos de empacotadores (UPX etc.), ausência de assinatura Authenticode (apenas a presença do diretório de segurança na v1; a validação criptográfica fica para depois). Cada sinal soma pontos; score ≥ limiar → `Suspicious`. **Nunca** gera `Malicious`.

Veredito do arquivo = maior severidade entre os achados.

Arquivos maiores que `--max-size` (padrão 256 MB) recebem apenas o detector de hash, calculado em *streaming*.

### 4.3 Banco de assinaturas (`signatures`)

- Local: `%LOCALAPPDATA%\Sentinela\db\` (em outros sistemas, o diretório de dados do usuário, para testes).
- Conteúdo: `hashes.txt` (um SHA-256 hexadecimal por linha, `#` para comentários), `rules/*.yar` e `manifest.json` (fontes, datas e contagens).
- O hash e a regra do EICAR vêm embutidos no binário, então a ferramenta é útil mesmo sem `update`.

### 4.4 `updater`

- Fontes fixas no código (sem URLs vindas de configuração na v1):
  - Hashes: exportação SHA-256 recente do MalwareBazaar (abuse.ch).
  - Regras: pacote "core" do YARA Forge.
- As URLs exatas são verificadas na fase de implementação.
- Fluxo: baixa para `db.new\` → valida (as regras compilam com `yara-x`; cada linha de hash é hex de 64 caracteres) → renomeia `db\` para `db.old\` e `db.new\` para `db\` → apaga `db.old\`. Qualquer falha mantém o `db\` atual.
- Regras que não compilam são descartadas individualmente com aviso, sem invalidar o pacote inteiro.

### 4.5 `clean`

```rust
trait Category {
    fn id(&self) -> &'static str;
    fn needs_admin(&self) -> bool;
    fn roots(&self, env: &Env) -> Vec<PathBuf>;           // pastas permitidas
    fn plan(&self, env: &Env) -> Result<Vec<Candidate>>;  // simulação
    fn apply(&self, env: &Env, plan: &[Candidate]) -> ApplyReport;
}
```

- `Env` contém as variáveis (`TEMP`, `LOCALAPPDATA`, `APPDATA`, `SystemRoot`) e uma **raiz substituível** para testes.
- Antes de cada exclusão, o caminho canônico do candidato é revalidado: precisa estar dentro de algum `roots()` e não pode ser link.
- Arquivos em uso ou sem permissão são pulados e contabilizados.
- Categorias:
  - `user-temp`: `%TEMP%`. Só arquivos com mais de 24 h.
  - `windows-temp`: `%SystemRoot%\Temp` (admin). Só arquivos com mais de 24 h.
  - `crash-dumps`: `%LOCALAPPDATA%\CrashDumps`, `%SystemRoot%\Minidump` (admin), `%ProgramData%\Microsoft\Windows\WER\ReportArchive` e `ReportQueue` (admin).
  - `browser-cache`: somente as pastas `Cache`, `Code Cache` e `GPUCache` dos perfis de Chrome, Edge e Brave, e `cache2` do Firefox. Nunca toca em `Cookies`, `History`, `Login Data` ou equivalentes. Navegador aberto → a categoria é pulada com aviso.
  - `recycle-bin`: `SHQueryRecycleBinW` para a simulação e `SHEmptyRecycleBinW` (sem UI) para aplicar.
  - `windows-update`: `%SystemRoot%\SoftwareDistribution\Download` (admin). Ao aplicar: para `wuauserv`, apaga e reinicia o serviço, inclusive se a exclusão falhar.
- Sem admin, as categorias que o exigem são puladas com aviso.
- `--apply` sem `--yes` pede confirmação interativa mostrando o total.

### 4.6 `finder`

- `find-large`: os N maiores arquivos (padrão 20) acima de `--min-size`.
- `find-dupes`: agrupa por tamanho → hash dos primeiros 64 KB → SHA-256 completo. Só relata grupos; **nunca apaga**.

### 4.7 `report`

Texto legível por padrão (resumo + lista de achados + arquivos não verificados com motivo). `--json` produz um objeto estável com `version`, `summary`, `items` e `errors`.

## 5. Tratamento de erros

- Erros por arquivo viram entradas em `errors` e não interrompem nada.
- Erros globais (caminho inexistente, banco corrompido sem fallback embutido, falha de rede no `update`) → mensagem clara e código 2.
- Ctrl+C: interrompe novos trabalhos, aguarda os em andamento e imprime relatório parcial.
- Uso de `anyhow` nas bordas e `thiserror` para os erros de domínio.

## 6. Testes

- TDD em todos os módulos.
- Nenhum malware real: EICAR, arquivos gerados nos testes e regras YARA de teste.
- `clean` é testado só sobre uma raiz falsa em diretório temporário. Os testes obrigatórios garantem que:
  - sem `--apply` nada é apagado;
  - nada fora de `roots()` é apagado, inclusive por meio de links;
  - arquivos recentes (< 24 h) em temp são preservados;
  - pastas de cookies/histórico de navegador são preservadas.
- Testes que dependem de APIs Windows usam `#[cfg(windows)]`; o restante roda em qualquer sistema.
- CI no GitHub Actions: `cargo fmt --check`, `cargo clippy -D warnings` e `cargo test` em `windows-latest` e `ubuntu-latest`. Em tags `v*`, compila `sentinela.exe` em release e publica como GitHub Release.

## 7. Riscos

- **Falsos positivos** das heurísticas de PE e de regras da comunidade: mitigados porque a PE nunca dá `Malicious` e porque a ferramenta só relata.
- **Exclusão indevida na limpeza**: mitigada por simulação padrão, lista fixa de pastas, revalidação canônica antes de cada exclusão e testes dedicados.
- **O próprio `sentinela.exe` ser marcado por outros antivírus** (binário novo e não assinado): aceito na v1; assinatura de código fica para o futuro.
- **Desenvolvimento em Linux para alvo Windows**: o código específico de Windows é validado pelo CI em `windows-latest`.
