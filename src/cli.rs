use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sentinela",
    version,
    about = "Antivírus e limpador de arquivos"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mostra a versão do Sentinela
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
    match cli.command {
        Command::Info => {
            println!("sentinela {}", env!("CARGO_PKG_VERSION"));
            0
        }
    }
}
