# Sentinela Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construir `sentinela.exe`, uma CLI para Windows que varre arquivos em busca de malware (hash + YARA + heurísticas de PE), limpa arquivos desnecessários com segurança e encontra arquivos grandes/duplicados.

**Architecture:** Um crate Rust com `src/lib.rs` (toda a lógica, testável) e `src/main.rs` (só chama `sentinela::cli::run()`). Cada módulo tem uma responsabilidade e expõe uma função/struct de biblioteca; o `cli.rs` é ligado por último. Código específico de Windows fica atrás de `#[cfg(windows)]` em `clean/platform.rs`.

**Tech Stack:** Rust estável (edição 2021), `clap`, `walkdir`, `globset`, `sha2`, `hex`, `yara-x`, `goblin`, `rayon`, `ureq` (rustls), `zip`, `serde`/`serde_json`, `anyhow`, `thiserror`, `dirs`, `ctrlc`, `sysinfo`, `windows-sys` (só Windows); dev: `tempfile`, `assert_cmd`, `predicates`.

**Spec:** `docs/superpowers/specs/2026-10-22-sentinela-design.md`

## Global Constraints

- Binário: `sentinela`. Repositório: `github.com/Luz-Lucas/sentinela`, **público**. Licença: MIT.
- Códigos de saída: `0` sucesso/nada encontrado, `1` achados de malware, `2` erro global.
- Erros por arquivo nunca interrompem a execução; viram entradas em `errors`.
- Nunca seguir links simbólicos nem junctions/reparse points (atributo `FILE_ATTRIBUTE_REPARSE_POINT = 0x400` no Windows).
- Heurística de PE nunca produz `Malicious`.
- `clean` sem `--apply` nunca apaga nada; `find-large`/`find-dupes` nunca apagam nada.
- Banco local: `dirs::data_local_dir()/Sentinela/db` (`%LOCALAPPDATA%\Sentinela\db`).
- Limite padrão de tamanho para varredura completa: 256 MB; acima disso, só hash (streaming).
- Temporários (`user-temp`, `windows-temp`): só arquivos com mais de 24 h.
- Saída JSON: objeto com `version` (1), `summary`, `items`, `errors`.
- Dependências: usar `cargo add <crate>` (versão estável mais recente); não fixar versões à mão.
- Todo código passa em `cargo fmt --check` e `cargo clippy --all-targets -- -D warnings`.
- Testes não usam malware real: só EICAR, arquivos gerados e regras de teste. Testes de `clean` nunca tocam pastas reais do sistema.

## Review Focus

1. **Nomes com Unicode/acentos** (`C:\Users\João\Downloads\relatório.exe`): varredura, limpeza e JSON funcionam e mostram o caminho corretamente. → teste em Task 7.
2. **Arquivo vazio (0 bytes)**: sem pânico em hash, entropia, YARA ou PE; resultado limpo. → teste em Task 3 e Task 5.
3. **Arquivo some ou fica bloqueado durante a varredura**: vira entrada em `errors`, sem pânico. → teste em Task 7.
4. **PE truncado/malformado** (começa com `MZ` mas o resto é lixo): sem achados e sem pânico. → teste em Task 5.
5. **Variável de ambiente perigosa** (`TEMP` vazio, ausente ou apontando para a raiz de um drive `C:\` ou para a pasta do usuário): `clean` recusa essa categoria em vez de apagar. → teste em Task 9.

## Ordem de execução (ondas)

As tarefas de uma mesma onda tocam arquivos disjuntos e podem rodar em paralelo, cada uma em sua própria git worktree, com merge ao fim da onda.

- **Onda 0:** Task 1
- **Onda 1:** Tasks 2, 3, 4, 5, 6
- **Onda 2:** Tasks 7, 8, 9, 12
- **Onda 3:** Tasks 10, 11
- **Onda 4:** Task 13

---

### Task 1: Bootstrap — toolchain, crate, módulos, CI e repositório no GitHub

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/scan/detector.rs`, arquivos vazios para todos os outros módulos da árvore abaixo, `.gitignore`, `LICENSE`, `README.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: árvore de módulos (todas as tarefas seguintes só preenchem seus arquivos):
  ```
  src/lib.rs: pub mod cli; pub mod walker; pub mod scan; pub mod signatures;
              pub mod updater; pub mod clean; pub mod finder; pub mod report;
  src/scan/mod.rs: pub mod detector; pub mod hash; pub mod yara; pub mod pe;
  src/clean/mod.rs: pub mod category; pub mod categories; pub mod browser; pub mod platform;
  ```
- Produces (`src/scan/detector.rs`), completo nesta tarefa:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
  #[serde(rename_all = "lowercase")]
  pub enum Severity { Info, Suspicious, Malicious }
  #[derive(Debug, Clone, Serialize)]
  pub struct Finding { pub detector: &'static str, pub rule: String, pub severity: Severity, pub detail: String }
  pub struct FileData<'a> { pub path: &'a Path, pub bytes: Option<&'a [u8]>, pub sha256: [u8; 32] }
  pub trait Detector: Send + Sync { fn name(&self) -> &'static str; fn inspect(&self, file: &FileData) -> Vec<Finding>; }
  ```
  `bytes` é `None` para arquivos acima do limite de tamanho.

- [ ] **Step 1: Instalar o Rust** com rustup no modo usuário (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal -c rustfmt,clippy`) e confirmar com `~/.cargo/bin/cargo --version`.
- [ ] **Step 2: Criar o crate** com `cargo init --name sentinela` e adicionar as dependências do Tech Stack via `cargo add` (`ureq` com rustls; `windows-sys` em `[target.'cfg(windows)'.dependencies]` com as features `Win32_Foundation`, `Win32_UI_Shell`, `Win32_Storage_FileSystem`; `serde` com `derive`; `clap` com `derive`). Dev-deps: `tempfile`, `assert_cmd`, `predicates`.
- [ ] **Step 3: Criar a árvore de módulos** acima, `detector.rs` completo e `main.rs` chamando `sentinela::cli::run()` com `std::process::exit` no código retornado. Nesta tarefa, `cli::run() -> i32` só define o `clap` com o subcomando `info`, que imprime `sentinela <versão>`.
- [ ] **Step 4: Teste de integração** `tests/cli.rs::info_prints_version`: `Command::cargo_bin("sentinela").arg("info")` sai com 0 e stdout contém `env!("CARGO_PKG_VERSION")`.
- [ ] **Step 5: Rodar** `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings`. Esperado: tudo passa.
- [ ] **Step 6: CI** em `.github/workflows/ci.yml`: em `push` e `pull_request`, matriz `windows-latest` e `ubuntu-latest`, `dtolnay/rust-toolchain@stable` com rustfmt e clippy, `Swatinem/rust-cache@v2`, depois fmt, clippy e test.
- [ ] **Step 7: README** (português): o que é, aviso para manter o Defender ativo, comandos do spec, como compilar. `LICENSE` MIT com "Lucas Luz". `.gitignore` com `/target`.
- [ ] **Step 8: Commit e criar o repositório**:
  ```bash
  git add -A && git commit -m "chore: bootstrap crate, module tree and CI"
  gh repo create Luz-Lucas/sentinela --public --source . --remote origin --push \
    --description "Antivírus e limpador de arquivos para Windows, em Rust (CLI)"
  ```
  Verificar com `gh run list --limit 1` que o CI disparou.

---

### Task 2: `walker` — percurso seguro de diretórios

**Files:**
- Modify: `src/walker.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone)] pub struct Entry { pub path: PathBuf, pub size: u64, pub modified: SystemTime }
  #[derive(Debug, Clone, Serialize)] pub struct WalkError { pub path: PathBuf, pub reason: String }
  pub enum WalkItem { File(Entry), Error(WalkError) }
  #[derive(Default)] pub struct WalkOptions { pub excludes: Option<globset::GlobSet> }
  pub fn walk<'a>(roots: &'a [PathBuf], opts: &'a WalkOptions) -> impl Iterator<Item = WalkItem> + 'a;
  pub fn is_link_like(meta: &std::fs::Metadata) -> bool; // symlink OU reparse point (Windows)
  ```
  Uma raiz que é arquivo produz um único `Entry`. Raiz inexistente produz `WalkItem::Error`.

- [ ] **Step 1: Testes que falham** (no módulo `#[cfg(test)]`, com `tempfile::tempdir`):
  - `walks_nested_files`: 3 arquivos em subpastas → 3 `File` com tamanhos corretos.
  - `file_root_yields_single_entry`.
  - `missing_root_yields_error`.
  - `excludes_glob`: glob `**/*.log` exclui `a.log` e mantém `a.txt`.
  - `does_not_follow_symlinked_dir` (`#[cfg(unix)]`): link para pasta fora da raiz → nenhum arquivo de fora aparece.
  - `symlink_loop_terminates` (`#[cfg(unix)]`): link `sub/loop -> ..` → o percurso termina.
- [ ] **Step 2: Rodar** `cargo test walker` → FAIL (funções inexistentes).
- [ ] **Step 3: Implementar** com `walkdir::WalkDir::new(root).follow_links(false)`, filtrando entradas onde `is_link_like` é verdadeiro (inclusive diretórios, para não descer neles). No Windows, `is_link_like` testa `MetadataExt::file_attributes() & 0x400`. Erros do walkdir viram `WalkItem::Error`.
- [ ] **Step 4: Rodar** `cargo test walker` → PASS.
- [ ] **Step 5: Commit** `feat(walker): safe directory traversal`.

---

### Task 3: Detector de hash

**Files:**
- Modify: `src/scan/hash.rs`

**Interfaces:**
- Consumes: `Detector`, `FileData`, `Finding`, `Severity` (Task 1).
- Produces:
  ```rust
  pub fn sha256_bytes(data: &[u8]) -> [u8; 32];
  pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]>; // streaming, buffer de 64 KB
  pub struct HashDetector { set: HashSet<[u8; 32]> }
  impl HashDetector { pub fn new(set: HashSet<[u8; 32]>) -> Self; }
  ```
  Finding: `detector = "hash"`, `rule = "sha256:<hex>"`, `severity = Malicious`, `detail = "hash conhecido de malware"`.

- [ ] **Step 1: Testes que falham**:
  - `sha256_of_empty` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
  - `file_and_bytes_hash_match` para um arquivo de 200 KB gerado.
  - `known_hash_is_malicious`: set contendo o hash de `b"abc"` → um finding `Malicious`.
  - `unknown_hash_is_clean` → vazio.
  - `works_without_bytes`: `FileData { bytes: None, .. }` com hash conhecido → ainda detecta.
- [ ] **Step 2: Rodar** `cargo test scan::hash` → FAIL.
- [ ] **Step 3: Implementar** com `sha2::Sha256`.
- [ ] **Step 4: Rodar** `cargo test scan::hash` → PASS.
- [ ] **Step 5: Commit** `feat(scan): sha256 hash detector`.

---

### Task 4: Detector YARA

**Files:**
- Modify: `src/scan/yara.rs`

**Interfaces:**
- Consumes: tipos da Task 1.
- Produces:
  ```rust
  pub struct CompileOutcome { pub rules: Option<yara_x::Rules>, pub rejected: Vec<(String, String)> } // (nome, erro)
  pub fn compile_rules(sources: &[(String, String)]) -> CompileOutcome; // (nome, código-fonte)
  pub struct YaraDetector { rules: yara_x::Rules }
  impl YaraDetector { pub fn new(rules: yara_x::Rules) -> Self; }
  ```
  Finding: `detector = "yara"`, `rule = "<namespace>:<identificador>"`, `severity` vinda da metadata `severity` (`"malicious"` → `Malicious`, `"suspicious"` → `Suspicious`, ausente/outra → `Suspicious`), `detail` = metadata `description` ou string vazia.

- [ ] **Step 1: Testes que falham**:
  - `matching_rule_reports_finding`: regra `rule t { strings: $a = "XYZZY" condition: $a }`, bytes `b"..XYZZY.."` → 1 finding `Suspicious`.
  - `severity_from_metadata`: `meta: severity = "malicious"` → `Malicious`.
  - `bad_source_is_rejected_others_kept`: uma fonte válida e uma inválida → `rules` é `Some`, `rejected.len() == 1` e a válida continua detectando.
  - `no_bytes_no_findings`: `bytes: None` → vazio.
  - `empty_file_is_clean`: `bytes: Some(&[])` → vazio.
- [ ] **Step 2: Rodar** `cargo test scan::yara` → FAIL.
- [ ] **Step 3: Implementar**: valida cada fonte isoladamente com um `yara_x::Compiler` novo; as válidas são compiladas juntas, cada uma em `compiler.new_namespace(nome)`. Em `inspect`, criar um `yara_x::Scanner` por chamada (o `Scanner` não é `Sync`).
- [ ] **Step 4: Rodar** `cargo test scan::yara` → PASS.
- [ ] **Step 5: Commit** `feat(scan): yara-x detector`.

---

### Task 5: Detector heurístico de PE

**Files:**
- Modify: `src/scan/pe.rs`

**Interfaces:**
- Consumes: tipos da Task 1.
- Produces:
  ```rust
  pub fn shannon_entropy(data: &[u8]) -> f64; // 0.0 para vazio
  pub struct PeReport { pub score: u32, pub signals: Vec<String> }
  pub fn analyze(bytes: &[u8]) -> Option<PeReport>; // None se não for PE válido
  #[derive(Default)] pub struct PeDetector;
  pub const SUSPICIOUS_THRESHOLD: u32 = 4;
  ```
  Pontuação: seção com entropia > 7.2 → +2; seção com `IMAGE_SCN_MEM_WRITE` e `IMAGE_SCN_MEM_EXECUTE` → +2; ponto de entrada fora de qualquer seção com `MEM_EXECUTE` → +1; nome de seção de empacotador (`UPX0`, `UPX1`, `.aspack`, `.adata`, `.petite`, `.MPRESS1`, `.MPRESS2`, `.themida`, `.vmp0`, `.vmp1`) → +2 (uma vez); diretório de segurança (Authenticode) vazio → +1. Score ≥ 4 → um finding `detector = "pe"`, `rule = "pe-heuristics"`, `Suspicious`, `detail` = sinais unidos por `"; "`. Abaixo disso, nenhum finding.

- [ ] **Step 1: Escrever um construtor de PE para testes** `fn build_pe(sections: &[(&str, u32 /*characteristics*/, Vec<u8>)], entry_rva: u32, signed: bool) -> Vec<u8>` no módulo de testes: PE32+ mínimo com cabeçalho DOS, `PE\0\0`, COFF, optional header com 16 data directories (o índice 4, security, recebe tamanho não zero quando `signed`) e tabela de seções. Validar o construtor com `goblin::pe::PE::parse` em um teste próprio.
- [ ] **Step 2: Testes que falham**:
  - `entropy_bounds`: vazio → 0.0; 4096 bytes iguais → 0.0; bytes 0..=255 repetidos → ~8.0 (±0.01).
  - `not_pe_returns_none`: texto qualquer.
  - `truncated_mz_is_none`: `b"MZ"` seguido de 100 bytes de lixo → `None` e o detector retorna vazio.
  - `normal_signed_pe_is_clean`: `.text` executável com entropia baixa, entry dentro de `.text`, assinado → sem finding.
  - `packed_pe_is_suspicious`: seção `UPX1` W+X com dados aleatórios (entropia > 7.2), não assinado → `Suspicious`, e detail contém `UPX`.
  - `never_malicious`: o pior PE possível nunca gera `Malicious`.
- [ ] **Step 3: Rodar** `cargo test scan::pe` → FAIL.
- [ ] **Step 4: Implementar** com `goblin::pe::PE::parse`; qualquer erro de parse → `None`.
- [ ] **Step 5: Rodar** `cargo test scan::pe` → PASS.
- [ ] **Step 6: Commit** `feat(scan): PE heuristics detector`.

---

### Task 6: Banco de assinaturas

**Files:**
- Modify: `src/signatures.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
  pub const EICAR_RULE: &str; // regra "EICAR_Test_File", meta severity = "malicious", casando a string EICAR
  #[derive(Serialize, Deserialize, Default, Clone)] pub struct SourceInfo { pub name: String, pub url: String, pub fetched_at: String, pub count: usize }
  #[derive(Serialize, Deserialize, Default, Clone)] pub struct Manifest { pub sources: Vec<SourceInfo> }
  pub struct Database { pub hashes: HashSet<[u8; 32]>, pub rule_sources: Vec<(String, String)>, pub manifest: Option<Manifest>, pub warnings: Vec<String> }
  pub fn default_db_dir() -> PathBuf; // usa SENTINELA_DB_DIR se definida (isolamento de testes), senão data_local_dir()/Sentinela/db
  pub fn parse_hashes(text: &str) -> (HashSet<[u8; 32]>, usize /*linhas inválidas*/);
  pub fn load(dir: &Path) -> Database; // nunca falha: problemas viram warnings
  pub fn swap_in(db_dir: &Path, new_dir: &Path) -> anyhow::Result<()>;
  ```
  Layout do diretório: `hashes.txt`, `rules/*.yar`, `manifest.json`. `load` sempre inclui o hash e a regra do EICAR (fonte nomeada `builtin_eicar`), mesmo sem diretório.

- [ ] **Step 1: Testes que falham**:
  - `eicar_constant_hash_matches`: `sha256_bytes(EICAR)` em hex == `EICAR_SHA256` (o teste pode calcular com `sha2` diretamente).
  - `parse_hashes_skips_comments_and_invalid`: `"# c\n<hash válido>\n\nzzzz\n<HASH MAIÚSCULO>"` → 2 hashes, 1 inválida.
  - `load_missing_dir_has_builtin`: diretório inexistente → `hashes` contém EICAR, `rule_sources` contém `builtin_eicar`, `manifest` é `None`.
  - `load_reads_files`: `hashes.txt` com 2 hashes, `rules/a.yar` → 3 hashes e 2 fontes de regra.
  - `corrupt_manifest_becomes_warning`: `manifest.json` inválido → `manifest` é `None` e há 1 warning.
  - `swap_in_replaces_and_cleans`: `db` antigo e `db.new` → depois, `db` tem o conteúdo novo e não existem `db.new` nem `db.old`.
  - `swap_in_without_existing_db` funciona.
- [ ] **Step 2: Rodar** `cargo test signatures` → FAIL.
- [ ] **Step 3: Implementar.** `swap_in`: renomeia `db` → `db.old` (se existir), `new_dir` → `db`; se o segundo rename falhar, desfaz o primeiro; ao final, remove `db.old`.
- [ ] **Step 4: Rodar** `cargo test signatures` → PASS.
- [ ] **Step 5: Commit** `feat(signatures): local signature database`.

---

### Task 7: Orquestração da varredura + relatório

**Files:**
- Modify: `src/scan/mod.rs`, `src/report.rs`

**Interfaces:**
- Consumes: `walk`, `WalkOptions`, `WalkError` (Task 2); `HashDetector`, `sha256_bytes`, `sha256_file` (Task 3); `YaraDetector`, `compile_rules` (Task 4); `PeDetector` (Task 5); `Database` (Task 6).
- Produces:
  ```rust
  // scan/mod.rs
  pub struct ScanOptions { pub roots: Vec<PathBuf>, pub walk: WalkOptions, pub max_size: u64 }
  #[derive(Serialize)] pub struct ScanItem { pub path: PathBuf, pub verdict: Severity, pub findings: Vec<Finding> }
  #[derive(Serialize)] pub struct ScanReport { pub scanned: usize, pub items: Vec<ScanItem>, pub errors: Vec<WalkError>, pub interrupted: bool }
  pub struct Engine { /* detectores */ }
  impl Engine { pub fn from_database(db: &Database) -> (Engine, Vec<String> /*warnings*/); }
  pub fn run_scan(engine: &Engine, opts: &ScanOptions, cancel: &AtomicBool) -> ScanReport;
  impl ScanReport { pub fn exit_code(&self) -> i32; } // 1 se algum verdict >= Suspicious, senão 0
  // report.rs
  pub fn write_scan(report: &ScanReport, json: bool, out: &mut dyn Write) -> std::io::Result<()>;
  ```
  `items` contém só arquivos com verdict ≥ `Suspicious`, ordenados por caminho. JSON: `{"version":1,"summary":{"scanned","malicious","suspicious","errors","interrupted"},"items":[...],"errors":[...]}`.

- [ ] **Step 1: Testes que falham** (`scan/mod.rs`, pasta temporária):
  - `detects_eicar_file`: arquivo com `EICAR` → item `Malicious` com findings de `hash` e de `yara`; `exit_code() == 1`.
  - `clean_folder_exit_zero`: arquivos inofensivos → `items` vazio, `exit_code() == 0`.
  - `large_file_only_hashed`: `max_size = 10` e arquivo de 100 bytes contendo `"XYZZY"` com regra YARA para `XYZZY` → sem achados YARA.
  - `unicode_path_reported`: arquivo `relatório_ção.txt` com EICAR → aparece no relatório e no JSON com o nome correto.
  - `vanished_file_is_error_not_panic`: um `Entry` cujo arquivo foi apagado antes de ser lido (testar a função interna `scan_entry`) → `WalkError`.
  - `cancel_sets_interrupted`: `cancel` já `true` → `interrupted == true`.
  - `report_json_shape` (`report.rs`): o JSON tem as chaves acima e `summary.malicious == 1`.
- [ ] **Step 2: Rodar** `cargo test scan:: report` → FAIL.
- [ ] **Step 3: Implementar.** Coletar as entradas do walker; processar com `rayon` `par_iter`, checando `cancel` antes de cada arquivo. Arquivo ≤ `max_size`: lê os bytes uma vez e calcula `sha256_bytes`; acima: `sha256_file` e `bytes: None`. Verdict = maior severidade. Texto: resumo, uma linha por item (`[MALICIOSO] caminho — regra`), seção "Não verificados" com motivo.
- [ ] **Step 4: Rodar** → PASS.
- [ ] **Step 5: Commit** `feat(scan): parallel scan engine and reports`.

---

### Task 8: Atualizador

**Files:**
- Modify: `src/updater.rs`

**Interfaces:**
- Consumes: `parse_hashes`, `swap_in`, `Manifest`, `SourceInfo` (Task 6); `compile_rules` (Task 4).
- Produces:
  ```rust
  pub trait Fetcher { fn get(&self, url: &str, headers: &[(&str, String)]) -> anyhow::Result<Vec<u8>>; }
  pub struct HttpFetcher; // ureq + rustls, timeout de 60 s
  pub const HASHES_URL: &str;
  pub const RULES_URL: &str;
  pub struct UpdateSummary { pub hashes: usize, pub rules_ok: usize, pub rules_rejected: usize, pub warnings: Vec<String> }
  pub fn update(db_dir: &Path, fetcher: &dyn Fetcher, abuse_ch_key: Option<String>) -> anyhow::Result<UpdateSummary>;
  ```

- [ ] **Step 1: Verificar as fontes reais** (decisão do spec §4.4): confirmar com `curl -sI` que `RULES_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"` responde e localizar o `.yar` dentro do zip; confirmar o formato de `HASHES_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"`. Se a exportação do MalwareBazaar exigir chave, enviar o cabeçalho `Auth-Key` a partir da variável de ambiente `ABUSE_CH_AUTH_KEY`; sem a chave, a fonte de hashes é pulada com aviso (não é erro). Registrar no commit o que foi encontrado.
- [ ] **Step 2: Testes que falham** com um `FakeFetcher` (mapa URL → bytes ou erro):
  - `update_writes_db`: hashes com 2 linhas + zip contendo uma regra válida → `db/hashes.txt`, `db/rules/`, `db/manifest.json` com 2 fontes; summary `hashes == 2`, `rules_ok == 1`.
  - `hashes_are_merged_with_existing`: `db/hashes.txt` existente com 1 hash diferente → depois do update, 3 hashes.
  - `network_failure_keeps_old_db`: fetcher retorna erro → `Err` e `db/` antigo intacto, sem `db.new`.
  - `invalid_rules_rejected_individually`: zip com 1 regra válida e 1 inválida → `rules_ok == 1`, `rules_rejected == 1`.
  - `missing_key_skips_hashes_with_warning`: quando a fonte exige chave (fetcher retorna 401) e não há chave → `Ok`, warning presente, regras atualizadas.
- [ ] **Step 3: Rodar** `cargo test updater` → FAIL.
- [ ] **Step 4: Implementar.** Montar tudo em `db.new` (irmão de `db`), validar e chamar `swap_in`. Os arquivos `.yar` extraídos do zip são gravados um por fonte aprovada.
- [ ] **Step 5: Rodar** `cargo test updater` → PASS.
- [ ] **Step 6: Commit** `feat(updater): verified signature updates`.

---

### Task 9: Núcleo da limpeza + categorias de temporários e crash dumps

**Files:**
- Modify: `src/clean/mod.rs`, `src/clean/category.rs`, `src/clean/categories.rs`

**Interfaces:**
- Consumes: `walk`, `Entry`, `is_link_like` (Task 2).
- Produces:
  ```rust
  // category.rs
  pub struct Env { pub temp: Option<PathBuf>, pub local_app_data: Option<PathBuf>, pub app_data: Option<PathBuf>,
                   pub program_data: Option<PathBuf>, pub system_root: Option<PathBuf>, pub user_profile: Option<PathBuf>, pub now: SystemTime }
  impl Env { pub fn from_system() -> Env; }
  #[derive(Serialize, Clone)] pub struct Candidate { pub path: PathBuf, pub size: u64 }
  #[derive(Serialize, Default)] pub struct Plan { pub items: Vec<Candidate>, pub files: u64, pub bytes: u64, pub warnings: Vec<String> }
  #[derive(Serialize, Default)] pub struct ApplyReport { pub deleted: u64, pub freed: u64, pub skipped: Vec<(PathBuf, String)> }
  pub trait Category: Send + Sync {
      fn id(&self) -> &'static str;
      fn needs_admin(&self) -> bool;
      fn roots(&self, env: &Env) -> Vec<PathBuf>;
      fn plan(&self, env: &Env) -> Plan;
      fn apply(&self, env: &Env, plan: &Plan) -> ApplyReport;
  }
  pub fn safe_root(p: &Path, env: &Env) -> bool; // false se for raiz de drive, "/", user_profile ou system_root
  pub fn plan_files(roots: &[PathBuf], keep: impl Fn(&Entry) -> bool) -> Plan;
  pub fn delete_checked(roots: &[PathBuf], plan: &Plan) -> ApplyReport;
  // categories.rs
  pub struct UserTemp; pub struct WindowsTemp; pub struct CrashDumps;
  pub const MIN_AGE: Duration = Duration::from_secs(24 * 3600);
  // mod.rs
  #[derive(Serialize)] pub struct CategoryResult { pub id: String, pub plan: Plan, pub applied: Option<ApplyReport>, pub skipped_reason: Option<String> }
  #[derive(Serialize)] pub struct CleanReport { pub categories: Vec<CategoryResult> }
  pub fn all_categories() -> Vec<Box<dyn Category>>; // as 6 do spec, na ordem do spec
  pub fn run_clean(env: &Env, cats: &[Box<dyn Category>], selected: &[String], apply: bool, elevated: bool,
                   confirm: &mut dyn FnMut(&CleanReport) -> bool) -> CleanReport;
  ```
  Raízes (spec §4.5): `UserTemp` → `temp`; `WindowsTemp` → `system_root/Temp` (admin); `CrashDumps` → `local_app_data/CrashDumps`, e com admin `system_root/Minidump`, `program_data/Microsoft/Windows/WER/ReportArchive` e `ReportQueue`. Raízes inexistentes são ignoradas; raízes que falham em `safe_root` geram warning e são descartadas. `all_categories()` usa as structs das Tasks 10 e 11; até elas existirem, retorna só as desta tarefa (a Task 13 confere as 6).

- [ ] **Step 1: Testes que falham** (todos com `Env` apontando para pastas dentro de um `tempdir`):
  - `plan_never_deletes`: `run_clean(apply = false)` → arquivos continuam existindo; `plan.files` está correto.
  - `apply_deletes_only_old_files`: em `temp`, um arquivo com `modified` de 2 dias atrás (ajustar com `File::set_modified`) e um recente → só o antigo é apagado.
  - `symlink_escape_blocked` (`#[cfg(unix)]`): link dentro de `temp` apontando para um arquivo fora → o alvo continua existindo.
  - `candidate_outside_roots_refused`: `delete_checked` com um `Candidate` forjado fora das raízes → em `skipped`, arquivo intacto.
  - `dangerous_temp_refused`: `temp = Some("/")`, `temp` igual a `user_profile` e `temp = None` → nada é planejado e há warning.
  - `admin_categories_skipped_when_not_elevated`: `WindowsTemp` com `elevated = false` → `skipped_reason` está preenchido.
  - `confirm_false_aborts_apply`: `apply = true` e `confirm` retornando `false` → nada apagado.
  - `empty_subdirs_removed_root_kept`: depois de apagar, subpastas vazias somem e a raiz permanece.
- [ ] **Step 2: Rodar** `cargo test clean` → FAIL.
- [ ] **Step 3: Implementar.** `delete_checked`: para cada candidato, `symlink_metadata` (se for link → pula), `canonicalize` e checar `starts_with` de alguma raiz canonicalizada; então `remove_file`. Erros (em uso, sem permissão) vão para `skipped`. Depois, remove subpastas vazias de baixo para cima, nunca a própria raiz. `run_clean`: planeja tudo, chama `confirm` uma vez se `apply` e só então aplica.
- [ ] **Step 4: Rodar** `cargo test clean` → PASS.
- [ ] **Step 5: Commit** `feat(clean): safe cleaning core with temp and crash dump categories`.

---

### Task 10: Categoria de cache de navegadores

**Files:**
- Modify: `src/clean/browser.rs`

**Interfaces:**
- Consumes: `Category`, `Env`, `Plan`, `plan_files`, `delete_checked` (Task 9).
- Produces:
  ```rust
  pub struct BrowserCache { pub is_running: fn(&str) -> bool } // nome do processo, ex. "chrome.exe"
  impl Default for BrowserCache; // usa sysinfo
  ```
  Navegadores: Chrome `local_app_data/Google/Chrome/User Data`, Edge `local_app_data/Microsoft/Edge/User Data`, Brave `local_app_data/BraveSoftware/Brave-Browser/User Data` — perfis `Default` e `Profile *`, subpastas `Cache`, `Code Cache`, `GPUCache`. Firefox `local_app_data/Mozilla/Firefox/Profiles/*/cache2`. Processos: `chrome.exe`, `msedge.exe`, `brave.exe`, `firefox.exe`. Navegador em execução → as raízes dele são omitidas e um warning é gerado; os outros seguem.

- [ ] **Step 1: Testes que falham** (árvore falsa em `tempdir`):
  - `only_cache_dirs_planned`: perfil Chrome `Default` com `Cache/f1`, `Code Cache/f2`, `Cookies`, `History`, `Login Data` → planejados só `f1` e `f2`.
  - `apply_preserves_cookies_history`: após apply, `Cookies`, `History` e `Login Data` existem.
  - `profile_glob`: `Profile 1/Cache/x` também é planejado.
  - `firefox_cache2`: `Profiles/abc.default/cache2/entries/x` planejado; `Profiles/abc.default/places.sqlite` não.
  - `running_browser_skipped`: `is_running` retorna `true` para `chrome.exe` → nada do Chrome planejado, warning presente, Edge planejado.
- [ ] **Step 2: Rodar** `cargo test clean::browser` → FAIL.
- [ ] **Step 3: Implementar.** `id() = "browser-cache"`, `needs_admin() = false`.
- [ ] **Step 4: Rodar** → PASS.
- [ ] **Step 5: Commit** `feat(clean): browser cache category`.

---

### Task 11: Plataforma Windows — admin, Lixeira, Windows Update

**Files:**
- Modify: `src/clean/platform.rs`

**Interfaces:**
- Consumes: `Category`, `Env`, `Plan`, `ApplyReport`, `plan_files`, `delete_checked` (Task 9).
- Produces:
  ```rust
  pub fn is_elevated() -> bool; // Windows: IsUserAnAdmin (shell32); outros sistemas: false
  pub struct RecycleBin;     // id "recycle-bin", needs_admin false
  pub struct WindowsUpdate;  // id "windows-update", needs_admin true
  ```
  `RecycleBin::plan`: `SHQueryRecycleBinW(null, ...)` → `Plan { items: vec![], files: i64NumItems, bytes: i64Size }`. `apply`: `SHEmptyRecycleBinW(0, null, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)`. Fora do Windows: plano vazio com warning "disponível só no Windows".
  `WindowsUpdate`: raiz `system_root/SoftwareDistribution/Download`; `plan` via `plan_files` (sem filtro de idade); `apply`: `net stop wuauserv`, `delete_checked`, e `net start wuauserv` **sempre** (mesmo se a exclusão falhar); falhas de parar/iniciar entram em `skipped`.

- [ ] **Step 1: Testes que falham**:
  - `windows_update_plan_uses_download_dir`: `Env.system_root` falso com `SoftwareDistribution/Download/a.cab` → planejado; um arquivo em `SoftwareDistribution/DataStore` não.
  - `is_elevated_false_off_windows` (`#[cfg(not(windows))]`).
  - `recycle_bin_query_does_not_panic` (`#[cfg(windows)]`): só `plan`, sem `apply`.
  - O controle de serviço não é testado automaticamente: isolar a sequência stop → delete → start numa função que recebe closures (`stop`, `start`) e testar que `start` é chamado mesmo quando a exclusão falha.
- [ ] **Step 2: Rodar** `cargo test clean::platform` → FAIL.
- [ ] **Step 3: Implementar** com `windows-sys` (as features da Task 1).
- [ ] **Step 4: Rodar** `cargo test clean::platform` → PASS. O CI em `windows-latest` cobre os testes `cfg(windows)`.
- [ ] **Step 5: Commit** `feat(clean): recycle bin and windows update categories`.

---

### Task 12: Arquivos grandes e duplicados

**Files:**
- Modify: `src/finder.rs`

**Interfaces:**
- Consumes: `walk`, `WalkOptions`, `Entry`, `WalkError` (Task 2); `sha256_file` (Task 3).
- Produces:
  ```rust
  #[derive(Serialize)] pub struct LargeFile { pub path: PathBuf, pub size: u64 }
  #[derive(Serialize)] pub struct DupGroup { pub size: u64, pub sha256: String, pub paths: Vec<PathBuf> }
  pub fn find_large(roots: &[PathBuf], top: usize, min_size: u64) -> (Vec<LargeFile>, Vec<WalkError>);
  pub fn find_dupes(roots: &[PathBuf], min_size: u64) -> (Vec<DupGroup>, Vec<WalkError>);
  ```
  Duplicados: agrupa por tamanho → hash dos primeiros 64 KB → `sha256_file` completo. Grupos ordenados por `size * (paths.len() - 1)` decrescente (espaço desperdiçado).

- [ ] **Step 1: Testes que falham**:
  - `top_n_largest`: 5 arquivos de tamanhos distintos, `top = 2` → os 2 maiores, em ordem decrescente.
  - `min_size_filters`.
  - `finds_duplicates`: 3 cópias iguais e 1 arquivo do mesmo tamanho com conteúdo diferente → 1 grupo com 3 caminhos.
  - `same_prefix_different_tail_not_dupes`: 2 arquivos de 100 KB com os mesmos 64 KB iniciais → nenhum grupo.
  - `never_deletes`: depois de rodar, todos os arquivos existem.
- [ ] **Step 2: Rodar** `cargo test finder` → FAIL.
- [ ] **Step 3: Implementar.**
- [ ] **Step 4: Rodar** `cargo test finder` → PASS.
- [ ] **Step 5: Commit** `feat(finder): large and duplicate file finder`.

---

### Task 13: CLI completa, relatórios de limpeza/finder, release e README

**Files:**
- Modify: `src/cli.rs`, `src/report.rs`, `src/clean/mod.rs` (só `all_categories`), `README.md`
- Create: `.github/workflows/release.yml`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: tudo acima.
- Produces: os comandos do spec §3, exatamente:
  ```
  sentinela scan <caminho>... [--json] [--max-size <MB>] [--exclude <glob>]...
  sentinela update
  sentinela clean [--category <nome>]... [--apply] [--yes] [--json]
  sentinela find-large <caminho> [--top <N>] [--min-size <MB>] [--json]
  sentinela find-dupes <caminho> [--min-size <KB>] [--json]
  sentinela info
  ```
  Padrões: `--max-size 256`, `--top 20`, `find-large --min-size 0`, `find-dupes --min-size 1`. `report.rs` ganha `write_clean(&CleanReport, json, out)` e `write_finder_large/dupes(...)` no mesmo envelope JSON. `info` imprime versão, diretório do banco, fontes do manifest com datas/contagens (ou "banco não inicializado — rode `sentinela update`") e se está elevado.

- [ ] **Step 1: Testes de integração que falham** em `tests/cli.rs` (usando `--json` e `assert_cmd`):
  - `scan_eicar_exits_1`: pasta temporária com EICAR → código 1, JSON com `summary.malicious == 1`. Usar `SENTINELA_DB_DIR` (Task 6) apontando para um diretório temporário vazio.
  - `scan_clean_exits_0`.
  - `scan_missing_path_exits_2`: caminho inexistente como única raiz → código 2.
  - `clean_category_unknown_exits_2`: `--category foo` → código 2, mensagem lista as categorias válidas.
  - `clean_dry_run_lists_categories`: `clean --json` → as 6 categorias (`user-temp`, `windows-temp`, `crash-dumps`, `browser-cache`, `recycle-bin`, `windows-update`) aparecem em `categories[].id`. Sem `--apply`, nenhuma exclusão (nenhuma pasta real é tocada, pois não há apply).
  - `find_dupes_json`.
- [ ] **Step 2: Rodar** `cargo test --test cli` → FAIL.
- [ ] **Step 3: Implementar a CLI.** `scan`: carrega o banco, imprime warnings em stderr, registra `ctrlc` para setar o `AtomicBool` e devolve `exit_code()`. `clean --apply` sem `--yes`: o `confirm` mostra o total e lê `s/N` do stdin. `update`: `HttpFetcher` + `ABUSE_CH_AUTH_KEY`. Qualquer erro global → mensagem em stderr e código 2.
- [ ] **Step 4: Rodar** `cargo test && cargo fmt --check && cargo clippy --all-targets -- -D warnings` → tudo passa.
- [ ] **Step 5: Release** em `.github/workflows/release.yml`: em push de tag `v*`, `windows-latest` → `cargo build --release` → `gh release create ${{ github.ref_name }} target/release/sentinela.exe --generate-notes` (com `permissions: contents: write` e `GH_TOKEN`).
- [ ] **Step 6: README**: exemplos reais de cada comando, explicação de `--apply`, categorias e o que cada uma apaga, aviso sobre falsos positivos.
- [ ] **Step 7: Commit e push**: `feat(cli): wire all commands, release workflow`; `git push`; conferir com `gh run watch` que o CI passa em Windows e Ubuntu.
