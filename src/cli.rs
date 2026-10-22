use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::clean::category::Env;
use crate::clean::{self, CleanReport, platform};
use crate::report::{self, human_bytes};
use crate::scan::{Engine, ScanOptions, run_scan};
use crate::walker::WalkOptions;
use crate::{finder, signatures, updater};

#[derive(Parser)]
#[command(
    name = "sentinela",
    version,
    about = "Antivírus e limpador de arquivos",
    after_help = "Códigos de saída: 0 = sucesso/nada encontrado, 1 = ameaças encontradas, 2 = erro."
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
            let glob = globset::Glob::new(pattern)
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
        walk: WalkOptions { excludes },
        max_size,
    };
    let scan = run_scan(&engine, &opts, &cancel);
    report::write_scan(&scan, json, &mut io::stdout().lock())?;
    Ok(scan.exit_code())
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
