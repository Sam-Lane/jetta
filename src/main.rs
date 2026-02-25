mod animation;
mod decode;
mod output;
mod types;
mod validate;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use types::OutputFormat;

/// Jetta - A JWT CLI tool for decoding and validating JSON Web Tokens
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Skip the welcome animation in interactive mode
    #[arg(long, global = true)]
    no_animation: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a JWT without validating the signature
    Decode {
        /// JWT token string (optional, reads from stdin if not provided)
        token: Option<String>,

        /// Read token from file
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,

        /// Output format
        #[arg(short = 'o', long, value_enum, default_value = "human")]
        format: CliOutputFormat,
    },

    /// Validate a JWT signature and decode it
    Validate {
        /// JWT token string (optional, reads from stdin if not provided)
        token: Option<String>,

        /// Read token from file
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,

        /// Secret key for HMAC algorithms (HS256, HS384, HS512)
        #[arg(short = 's', long, conflicts_with_all = ["secret_file", "public_key"])]
        secret: Option<String>,

        /// Read secret key from file
        #[arg(long, conflicts_with_all = ["secret", "public_key"])]
        secret_file: Option<PathBuf>,

        /// Public key file for RSA/ECDSA/EdDSA algorithms (PEM format)
        #[arg(short = 'k', long, conflicts_with_all = ["secret", "secret_file"])]
        public_key: Option<PathBuf>,

        /// Output format
        #[arg(short = 'o', long, value_enum, default_value = "human")]
        format: CliOutputFormat,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum CliOutputFormat {
    /// Human-readable colorful output
    Human,
    /// JSON output
    Json,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(format: CliOutputFormat) -> Self {
        match format {
            CliOutputFormat::Human => OutputFormat::HumanReadable,
            CliOutputFormat::Json => OutputFormat::Json,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Decode {
            token,
            file,
            format,
        }) => {
            let token_str = read_token_input(token, file)?;
            let decoded = decode::decode_token(&token_str).context("Failed to decode JWT token")?;

            let output = output::format_decoded_token(&decoded, format.into())?;
            println!("{}", output);
        }

        Some(Commands::Validate {
            token,
            file,
            secret,
            secret_file,
            public_key,
            format,
        }) => {
            let token_str = read_token_input(token, file)?;

            // Determine the validation key/secret
            let validation_result = if let Some(secret_str) = secret {
                validate::validate_token(&token_str, Some(&secret_str), None)
            } else if let Some(secret_path) = secret_file {
                let secret_content = fs::read_to_string(&secret_path)
                    .context(format!("Failed to read secret file: {:?}", secret_path))?;
                validate::validate_token(&token_str, Some(secret_content.trim()), None)
            } else if let Some(key_path) = public_key {
                let key_content = fs::read_to_string(&key_path)
                    .context(format!("Failed to read public key file: {:?}", key_path))?;
                validate::validate_token(&token_str, None, Some(&key_content))
            } else {
                // Try environment variable
                validate::validate_token(&token_str, None, None)
            };

            let result = validation_result.context("Failed to validate JWT token")?;
            let output = output::format_validation_result(&result, format.into())?;
            println!("{}", output);

            // Exit with error code if validation failed
            if !result.valid {
                std::process::exit(1);
            }
        }

        None => {
            // Interactive mode - show animation and prompt for token
            run_interactive_mode(cli.no_animation)?;
        }
    }

    Ok(())
}

/// Read token input from argument, file, or stdin
fn read_token_input(token: Option<String>, file: Option<PathBuf>) -> Result<String> {
    if let Some(token_str) = token {
        Ok(token_str.trim().to_string())
    } else if let Some(file_path) = file {
        fs::read_to_string(&file_path)
            .context(format!("Failed to read token from file: {:?}", file_path))
            .map(|s| s.trim().to_string())
    } else {
        // Read from stdin
        let mut buffer = String::new();
        io::stdin()
            .read_to_string(&mut buffer)
            .context("Failed to read token from stdin")?;
        Ok(buffer.trim().to_string())
    }
}

/// Run interactive mode with animation and prompt
fn run_interactive_mode(no_animation: bool) -> Result<()> {
    // Show animation unless --no-animation flag is set
    if !no_animation {
        animation::show_welcome_animation()?;
        println!(); // Add blank line after animation
    }

    // Display prompt
    print!("Enter JWT token: ");
    io::stdout().flush()?;

    // Read token from stdin
    let mut token_input = String::new();
    io::stdin()
        .read_line(&mut token_input)
        .context("Failed to read token from stdin")?;

    let token_str = token_input.trim();

    // Handle empty input
    if token_str.is_empty() {
        eprintln!("No token provided");
        std::process::exit(1);
    }

    // Decode the token
    let decoded = decode::decode_token(token_str).context("Failed to decode JWT token")?;

    // Display the result in human-readable format
    let output = output::format_decoded_token(&decoded, OutputFormat::HumanReadable)?;
    println!("\n{}", output);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_output_format_conversion() {
        assert!(matches!(
            OutputFormat::from(CliOutputFormat::Human),
            OutputFormat::HumanReadable
        ));
        assert!(matches!(
            OutputFormat::from(CliOutputFormat::Json),
            OutputFormat::Json
        ));
    }
}
