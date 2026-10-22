use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::clean::category::Env;
use crate::clean::{self, CleanReport, platform};
use crate::full::{self, FullOptions};
use crate::report::{self, human_bytes};
use crate::scan::{Engine, ScanOptions, run_scan};
use crate::walker::WalkOptions;
use crate::{finder, platform_fs, quarantine, signatures, updater};

#[derive(Parser)]
#[command(
    name = "sentinela",
    version,
    about = "Antivírus e limpador de arquivos",
    after_help = "Códigos de saída: 0 = sucesso/nada encontrado, 1 = ameaças encontradas (em `full`: malware confirmado que não pôde ser isolado), 2 = erro."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verifica arquivos e pastas em busca de malware
    Scan {
        /// Arquivos ou pastas a verificar
        #[arg(required = true, num_args = 1.., value_name = "CAMINHO")]
        paths: Vec<PathBuf>,
        /// Saída em JSON
        #[arg(long)]
        json: bool,
        /// Tamanho máximo (MB) para análise completa; acima disso só o hash
        #[arg(long, value_name = "MB", default_value_t = 256)]
        max_size: u64,
        /// Glob de caminhos a ignorar (repetível)
        #[arg(long, value_name = "GLOB")]
        exclude: Vec<String>,
    },
    /// Baixa as assinaturas e regras mais recentes
    Update,
    /// Limpa arquivos temporários (simulação, a menos que use --apply)
    Clean {
        /// Categoria a limpar (repetível); sem ela, todas
        #[arg(long, value_name = "NOME")]
        category: Vec<String>,
        /// Apaga de verdade (sem isso, apenas simula)
        #[arg(long)]
        apply: bool,
        /// Não pede confirmação
        #[arg(long)]
        yes: bool,
        /// Saída em JSON
        #[arg(long)]
        json: bool,
    },
    /// Lista os maiores arquivos de uma pasta
    FindLarge {
        #[arg(value_name = "CAMINHO")]
        path: PathBuf,
        /// Quantos arquivos listar
        #[arg(long, value_name = "N", default_value_t = 20)]
        top: usize,
        /// Tamanho mínimo em MB
        #[arg(long, value_name = "MB", default_value_t = 0)]
        min_size: u64,
        #[arg(long)]
        json: bool,
    },
    /// Encontra arquivos duplicados (nunca apaga)
    FindDupes {
        #[arg(value_name = "CAMINHO")]
        path: PathBuf,
        /// Tamanho mínimo em KB
        #[arg(long, value_name = "KB", default_value_t = 1)]
        min_size: u64,
        #[arg(long)]
        json: bool,
    },
    /// Verifica o computador inteiro, isola malware confirmado e limpa (sem perguntas)
    Full {
        /// Saída em JSON
        #[arg(long)]
        json: bool,
        /// Só para testes: substitui os discos fixos por estas pastas
        #[arg(long, value_name = "CAMINHO", hide = true)]
        root: Vec<PathBuf>,
    },
    /// Lista os arquivos em quarentena
    Quarantine {
        #[arg(long)]
        json: bool,
    },
    /// Restaura um arquivo da quarentena para o local original
    Restore {
        /// Id mostrado por `sentinela quarantine`
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Mostra versão, banco de assinaturas e privilégios
    Info,
}

pub fn run() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    match dispatch(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("erro: {e:#}");
            2
        }
    }
}

fn dispatch(command: Command) -> Result<i32> {
    match command {
        Command::Scan {
            paths,
            json,
            max_size,
            exclude,
        } => cmd_scan(paths, json, max_size, exclude),
        Command::Update => cmd_update(),
        Command::Clean {
            category,
            apply,
            yes,
            json,
        } => cmd_clean(category, apply, yes, json),
        Command::FindLarge {
            path,
            top,
            min_size,
            json,
        } => {
            require_exists(std::slice::from_ref(&path))?;
            let min = min_size
                .checked_mul(1024 * 1024)
                .context("--min-size grande demais")?;
            let (files, errors) = finder::find_large(&[path], top, min);
            report::write_finder_large(&files, &errors, json, &mut io::stdout().lock())?;
            Ok(0)
        }
        Command::FindDupes {
            path,
            min_size,
            json,
        } => {
            require_exists(std::slice::from_ref(&path))?;
            let min = min_size
                .checked_mul(1024)
                .context("--min-size grande demais")?;
            let (groups, errors) = finder::find_dupes(&[path], min);
            report::write_finder_dupes(&groups, &errors, json, &mut io::stdout().lock())?;
            Ok(0)
        }
        Command::Full { json, root } => cmd_full(json, root),
        Command::Quarantine { json } => {
            let entries = quarantine::list(&quarantine::default_quarantine_dir());
            report::write_quarantine_list(&entries, json, &mut io::stdout().lock())?;
            Ok(0)
        }
        Command::Restore { id } => {
            let path = quarantine::restore(&quarantine::default_quarantine_dir(), &id)?;
            println!("Restaurado: {}", path.display());
            Ok(0)
        }
        Command::Info => cmd_info(),
    }
}

fn require_exists(paths: &[PathBuf]) -> Result<()> {
    for p in paths {
        if std::fs::symlink_metadata(p).is_err() {
            bail!("o caminho não existe: {}", p.display());
        }
    }
    Ok(())
}

fn cmd_scan(paths: Vec<PathBuf>, json: bool, max_size: u64, exclude: Vec<String>) -> Result<i32> {
    require_exists(&paths)?;
    let max_size = max_size
        .checked_mul(1024 * 1024)
        .context("--max-size grande demais")?;
    let excludes = if exclude.is_empty() {
        None
    } else {
        let mut builder = globset::GlobSetBuilder::new();
        for pattern in &exclude {
            // Windows paths are case-insensitive.
            let glob = globset::GlobBuilder::new(pattern)
                .case_insensitive(cfg!(windows))
                .build()
                .with_context(|| format!("glob inválido em --exclude: {pattern}"))?;
            builder.add(glob);
        }
        Some(builder.build().context("falha ao montar os globs")?)
    };

    let db = signatures::load(&signatures::default_db_dir());
    let (engine, engine_warnings) = Engine::from_database(&db);
    for w in db.warnings.iter().chain(&engine_warnings) {
        eprintln!("aviso: {w}");
    }
    if db.manifest.is_none() {
        eprintln!(
            "aviso: banco de assinaturas não inicializado — rode `sentinela update` (só a assinatura de teste EICAR e as heurísticas estão ativas)"
        );
    }

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = Arc::clone(&cancel);
        if let Err(e) = ctrlc::set_handler(move || {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }) {
            eprintln!("aviso: não foi possível registrar o Ctrl+C: {e}");
        }
    }

    let opts = ScanOptions {
        roots: paths,
        walk: WalkOptions {
            excludes,
            ..WalkOptions::default()
        },
        max_size,
    };
    let scan = run_scan(&engine, &opts, &cancel);
    report::write_scan(&scan, json, &mut io::stdout().lock())?;
    Ok(scan.exit_code())
}

/// Scans every fixed drive, quarantines hash-confirmed malware (YARA/PE
/// detections are only reported), then cleans all categories without asking.
/// Exit code: 0 normally (quarantined or suspicious files do not change it),
/// 1 if confirmed malware could not be quarantined and is still on disk,
/// 2 on a global error (e.g. no drives found).
fn cmd_full(json: bool, roots_override: Vec<PathBuf>) -> Result<i32> {
    // The hidden `--root` test path also restricts cleaning to UserTemp:
    // RecycleBin and WindowsUpdate act on real system state, not on `Env`.
    let test_mode = !roots_override.is_empty();
    let roots = if test_mode {
        require_exists(&roots_override)?;
        roots_override
    } else {
        platform_fs::fixed_drive_roots()
    };
    let categories: Vec<Box<dyn clean::category::Category>> = if test_mode {
        vec![Box::new(clean::categories::UserTemp)]
    } else {
        clean::all_categories()
    };
    if roots.is_empty() {
        bail!("nenhum disco fixo encontrado");
    }
    // stderr keeps `--json` output on stdout valid.
    eprintln!(
        "Verificando: {}. Isso pode demorar bastante (todos os discos fixos).",
        roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let cancel = Arc::clone(&cancel);
        if let Err(e) = ctrlc::set_handler(move || {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }) {
            eprintln!("aviso: não foi possível registrar o Ctrl+C: {e}");
        }
    }
    let elevated = platform::is_elevated();
    let mut env = Env::from_system();
    env.elevated = elevated;
    let report = full::run_full(&FullOptions {
        categories,
        roots,
        db_dir: signatures::default_db_dir(),
        quarantine_dir: quarantine::default_quarantine_dir(),
        env,
        elevated,
        max_size: 256 * 1024 * 1024,
        cancel: &cancel,
    });
    for w in &report.warnings {
        eprintln!("aviso: {w}");
    }
    if !report.db_initialized {
        eprintln!(
            "aviso: banco de assinaturas não inicializado — rode `sentinela update` (só a assinatura de teste EICAR e as heurísticas estão ativas)"
        );
    }
    report::write_full(&report, json, &mut io::stdout().lock())?;
    Ok(report.exit_code())
}

fn cmd_update() -> Result<i32> {
    let key = std::env::var("ABUSE_CH_AUTH_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .map(|k| k.trim().to_string());
    let dir = signatures::default_db_dir();
    let s = updater::update(&dir, &updater::HttpFetcher, key)?;
    println!("Banco atualizado em {}", dir.display());
    println!("  Hashes: {}", s.hashes);
    println!(
        "  Regras YARA: {} arquivo(s) aceito(s), {} rejeitado(s), {} regra(s) no total",
        s.rules_ok, s.rules_rejected, s.rules_count
    );
    for w in &s.warnings {
        eprintln!("aviso: {w}");
    }
    Ok(0)
}

fn cmd_clean(selected: Vec<String>, apply: bool, yes: bool, json: bool) -> Result<i32> {
    let cats = clean::all_categories();
    let valid: Vec<&str> = cats.iter().map(|c| c.id()).collect();
    for s in &selected {
        if !valid.contains(&s.as_str()) {
            bail!(
                "categoria desconhecida: {s}. Categorias válidas: {}",
                valid.join(", ")
            );
        }
    }
    let elevated = platform::is_elevated();
    let mut env = Env::from_system();
    env.elevated = elevated;
    let mut confirm = |r: &CleanReport| -> bool {
        if yes {
            return true;
        }
        let files: u64 = r.categories.iter().map(|c| c.plan.files).sum();
        let bytes: u64 = r.categories.iter().map(|c| c.plan.bytes).sum();
        // Prompt goes to stderr so --json output on stdout stays valid.
        for line in confirmation_lines(r) {
            eprintln!("{line}");
        }
        eprint!(
            "Apagar {files} arquivo(s), {} no total? [s/N] ",
            human_bytes(bytes)
        );
        let _ = io::stderr().flush();
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_lowercase().as_str(), "s" | "sim")
    };
    let report = clean::run_clean(&env, &cats, &selected, apply, elevated, &mut confirm);
    report::write_clean(&report, apply, json, &mut io::stdout().lock())?;
    Ok(0)
}

/// Per-category breakdown shown before the `--apply` confirmation prompt.
fn confirmation_lines(r: &CleanReport) -> Vec<String> {
    let mut lines = Vec::new();
    for c in r.categories.iter().filter(|c| c.skipped_reason.is_none()) {
        lines.push(format!(
            "  {}: {} arquivo(s), {}",
            c.id,
            c.plan.files,
            human_bytes(c.plan.bytes)
        ));
        if c.id == "recycle-bin" && c.plan.files > 0 {
            lines.push("  Lixeira será esvaziada permanentemente".to_string());
        }
    }
    for c in r.categories.iter().filter(|c| c.skipped_reason.is_some()) {
        lines.push(format!(
            "  {}: ignorada ({})",
            c.id,
            c.skipped_reason.as_deref().unwrap_or_default()
        ));
    }
    lines
}

fn cmd_info() -> Result<i32> {
    let dir = signatures::default_db_dir();
    println!("sentinela {}", env!("CARGO_PKG_VERSION"));
    println!("Banco de assinaturas: {}", dir.display());
    let db = signatures::load(&dir);
    match &db.manifest {
        Some(m) if !m.sources.is_empty() => {
            for s in &m.sources {
                println!(
                    "  {} — atualizado em {} ({} itens)",
                    s.name, s.fetched_at, s.count
                );
            }
        }
        _ => println!("  banco não inicializado — rode `sentinela update`"),
    }
    for w in &db.warnings {
        eprintln!("aviso: {w}");
    }
    println!(
        "Executando como administrador: {}",
        if platform::is_elevated() {
            "sim"
        } else {
            "não"
        }
    );
    Ok(0)
}
