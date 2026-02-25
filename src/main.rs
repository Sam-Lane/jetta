mod decode;
mod output;
mod types;
mod validate;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use types::OutputFormat;

/// Jetta - A JWT CLI tool for decoding and validating JSON Web Tokens
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
        Commands::Decode {
            token,
            file,
            format,
        } => {
            let token_str = read_token_input(token, file)?;
            let decoded = decode::decode_token(&token_str).context("Failed to decode JWT token")?;

            let output = output::format_decoded_token(&decoded, format.into())?;
            println!("{}", output);
        }

        Commands::Validate {
            token,
            file,
            secret,
            secret_file,
            public_key,
            format,
        } => {
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
