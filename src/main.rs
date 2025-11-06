use std::env;
use std::fs::File;
use std::io::{self, Read};

const DEFAULT_LENGTH: usize = 8;
const DEFAULT_COUNT: usize = 160;
const COLUMNS: usize = 5;

// Наборы символов
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMERALS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const VOWELS: &[u8] = b"aeiouyAEIOUY";
const AMBIGUOUS: &[u8] = b"B8G6I1l0OQDS5Z2";

// Согласные для запоминаемых паролей
const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ";
const CONSONANTS_LOWER: &[u8] = b"bcdfghjklmnpqrstvwxz";
const VOWELS_LOWER: &[u8] = b"aeiouy";

#[derive(Debug)]
struct Config {
    pw_length: usize,
    num_pw: usize,
    capitalize: bool,
    no_capitalize: bool,
    numerals: bool,
    no_numerals: bool,
    symbols: bool,
    remove_chars: Option<Vec<u8>>,
    secure: bool,
    ambiguous: bool,
    columns: bool,
    no_vowels: bool,
    help: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pw_length: DEFAULT_LENGTH,
            num_pw: DEFAULT_COUNT,
            capitalize: false,
            no_capitalize: false,
            numerals: false,
            no_numerals: false,
            symbols: false,
            remove_chars: None,
            secure: false,
            ambiguous: false,
            columns: true,
            no_vowels: false,
            help: false,
        }
    }
}

fn main() -> io::Result<()> {
    let config = parse_args();

    if config.help {
        print_help();
        return Ok(());
    }

    let passwords = generate_passwords(&config)?;
    print_passwords(&passwords, config.columns);

    Ok(())
}

fn parse_args() -> Config {
    let args: Vec<String> = env::args().collect();
    let mut config = Config::default();
    let mut positional_args = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--capitalize" => config.capitalize = true,
            "-A" | "--no-capitalize" => config.no_capitalize = true,
            "-n" | "--numerals" => config.numerals = true,
            "-0" | "--no-numerals" => config.no_numerals = true,
            "-y" | "--symbols" => config.symbols = true,
            "-s" | "--secure" => config.secure = true,
            "-B" | "--ambiguous" => config.ambiguous = true,
            "-C" => config.columns = true,
            "-1" => config.columns = false,
            "-v" | "--no-vowels" => config.no_vowels = true,
            "-h" | "--help" => config.help = true,
            arg if arg.starts_with("-r") || arg.starts_with("--remove-chars") => {
                let chars = if arg.starts_with("-r") && arg.len() > 2 {
                    arg[2..].as_bytes().to_vec()
                } else if let Some(equal_pos) = arg.find('=') {
                    arg[equal_pos + 1..].as_bytes().to_vec()
                } else if i + 1 < args.len() {
                    i += 1;
                    args[i].as_bytes().to_vec()
                } else {
                    eprintln!("Error: Missing characters to remove");
                    std::process::exit(1);
                };
                config.remove_chars = Some(chars);
            }
            arg if !arg.starts_with('-') => {
                positional_args.push(arg);
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Установим значения по умолчанию как в оригинальном pwgen
    if !config.capitalize && !config.no_capitalize {
        config.capitalize = true;
    }
    if !config.numerals && !config.no_numerals {
        config.numerals = true;
    }

    // Обработка позиционных аргументов
    match positional_args.len() {
        0 => {}
        1 => {
            if let Ok(n) = positional_args[0].parse() {
                config.pw_length = n;
            }
        }
        2 => {
            if let Ok(n) = positional_args[0].parse() {
                config.pw_length = n;
            }
            if let Ok(n) = positional_args[1].parse() {
                config.num_pw = n;
            }
        }
        _ => {
            eprintln!("Too many arguments");
            std::process::exit(1);
        }
    }

    config
}

fn generate_passwords(config: &Config) -> io::Result<Vec<String>> {
    let mut passwords = Vec::with_capacity(config.num_pw);
    let mut rng = File::open("/dev/urandom")?;

    for _ in 0..config.num_pw {
        let password = if config.secure {
            generate_secure_password(config.pw_length, config, &mut rng)?
        } else {
            generate_memorable_password(config.pw_length, config, &mut rng)?
        };
        passwords.push(password);
    }

    Ok(passwords)
}

fn generate_secure_password(length: usize, config: &Config, rng: &mut File) -> io::Result<String> {
    let charset = build_charset(config);
    if charset.is_empty() {
        return Ok("a".repeat(length)); // fallback
    }

    let mut password = String::with_capacity(length);

    for _ in 0..length {
        let mut buf = [0u8; 1];
        rng.read_exact(&mut buf)?;
        let idx = buf[0] as usize % charset.len();
        password.push(charset[idx] as char);
    }

    Ok(password)
}

fn generate_memorable_password(
    length: usize,
    config: &Config,
    rng: &mut File,
) -> io::Result<String> {
    let mut password = String::with_capacity(length);

    // Выбираем наборы символов в зависимости от опции --no-capitalize
    let (consonants, vowels) = if config.no_capitalize {
        (CONSONANTS_LOWER, VOWELS_LOWER)
    } else {
        (CONSONANTS, VOWELS)
    };

    // Для запоминаемых паролей используем шаблон согласная-гласная
    for i in 0..length {
        let char_set = if i % 2 == 0 {
            // Четные позиции - согласные
            consonants
        } else {
            // Нечетные позиции - гласные
            vowels
        };

        let mut buf = [0u8; 1];
        loop {
            rng.read_exact(&mut buf)?;
            let idx = buf[0] as usize % char_set.len();
            let candidate = char_set[idx];

            // Проверка на удаляемые символы
            if let Some(remove_chars) = &config.remove_chars {
                if remove_chars.contains(&candidate) {
                    continue;
                }
            }

            // Проверка на неоднозначные символы
            if config.ambiguous && AMBIGUOUS.contains(&candidate) {
                continue;
            }

            // Проверка на гласные (если опция --no-vowels, пропускаем гласные)
            if config.no_vowels && VOWELS.contains(&candidate) {
                continue;
            }

            password.push(candidate as char);
            break;
        }
    }

    // Применяем требования к цифрам и символам (но не к заглавным буквам, если --no-capitalize)
    let password_bytes = password.into_bytes();
    let password = apply_requirements(password_bytes, config, rng)?;
    Ok(password)
}

fn apply_requirements(password: Vec<u8>, config: &Config, rng: &mut File) -> io::Result<String> {
    let mut result = password;
    let mut buf = [0u8; 1];

    // Проверка и добавление заглавной буквы если требуется и разрешено
    if config.capitalize && !config.no_capitalize && !result.iter().any(|&c| c.is_ascii_uppercase())
    {
        let uppercase_filtered: Vec<u8> = UPPERCASE
            .iter()
            .filter(|&&c| {
                if config.ambiguous && AMBIGUOUS.contains(&c) {
                    return false;
                }
                if let Some(remove_chars) = &config.remove_chars {
                    if remove_chars.contains(&c) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        if !uppercase_filtered.is_empty() {
            rng.read_exact(&mut buf)?;
            let upper_idx = buf[0] as usize % uppercase_filtered.len();
            let upper_char = uppercase_filtered[upper_idx];

            rng.read_exact(&mut buf)?;
            let pos = buf[0] as usize % result.len();
            result[pos] = upper_char;
        }
    }

    // Проверка и добавление цифры если требуется
    if config.numerals && !config.no_numerals {
        let has_numeral = result.iter().any(|&c| c.is_ascii_digit());
        if !has_numeral {
            let numerals_filtered: Vec<u8> = NUMERALS
                .iter()
                .filter(|&&c| {
                    if config.ambiguous && AMBIGUOUS.contains(&c) {
                        return false;
                    }
                    if let Some(remove_chars) = &config.remove_chars {
                        if remove_chars.contains(&c) {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();

            if !numerals_filtered.is_empty() {
                rng.read_exact(&mut buf)?;
                let numeral_idx = buf[0] as usize % numerals_filtered.len();
                let numeral = numerals_filtered[numeral_idx];

                rng.read_exact(&mut buf)?;
                let pos = buf[0] as usize % result.len();
                result[pos] = numeral;
            }
        }
    }

    // Проверка и добавление символа если требуется
    if config.symbols {
        let has_symbol = result.iter().any(|&c| SYMBOLS.contains(&c));
        if !has_symbol {
            let symbols_filtered: Vec<u8> = SYMBOLS
                .iter()
                .filter(|&&c| {
                    if let Some(remove_chars) = &config.remove_chars {
                        if remove_chars.contains(&c) {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();

            if !symbols_filtered.is_empty() {
                rng.read_exact(&mut buf)?;
                let symbol_idx = buf[0] as usize % symbols_filtered.len();
                let symbol = symbols_filtered[symbol_idx];

                rng.read_exact(&mut buf)?;
                let pos = buf[0] as usize % result.len();
                result[pos] = symbol;
            }
        }
    }

    Ok(String::from_utf8(result).unwrap())
}

fn build_charset(config: &Config) -> Vec<u8> {
    let mut charset = Vec::new();

    // Строчные буквы всегда включены
    charset.extend_from_slice(LOWERCASE);

    // Заглавные буквы
    if config.capitalize && !config.no_capitalize {
        charset.extend_from_slice(UPPERCASE);
    }

    // Цифры
    if config.numerals && !config.no_numerals {
        charset.extend_from_slice(NUMERALS);
    }

    // Символы
    if config.symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    // Удаляем неоднозначные символы если требуется
    if config.ambiguous {
        charset.retain(|&c| !AMBIGUOUS.contains(&c));
    }

    // Удаляем гласные если требуется
    if config.no_vowels {
        charset.retain(|&c| !VOWELS.contains(&c));
    }

    // Удаляем пользовательские символы
    if let Some(remove_chars) = &config.remove_chars {
        charset.retain(|&c| !remove_chars.contains(&c));
    }

    charset
}

fn print_passwords(passwords: &[String], columns: bool) {
    if !columns || passwords.len() <= COLUMNS {
        for password in passwords {
            println!("{}", password);
        }
        return;
    }

    let rows = (passwords.len() + COLUMNS - 1) / COLUMNS;
    let mut row_buffers = vec![Vec::new(); rows];

    for (i, password) in passwords.iter().enumerate() {
        row_buffers[i % rows].push(password.as_str());
    }

    // Находим максимальную ширину для каждого столбца
    let mut max_widths = vec![0; COLUMNS];
    for row in &row_buffers {
        for (col, &item) in row.iter().enumerate() {
            if item.len() > max_widths[col] {
                max_widths[col] = item.len();
            }
        }
    }

    for row in row_buffers {
        for (col, item) in row.iter().enumerate() {
            if col > 0 {
                print!(" ");
            }
            print!("{:<width$}", item, width = max_widths[col]);
        }
        println!();
    }
}

fn print_help() {
    println!("Usage: pwgen [ OPTIONS ] [ pw_length ] [ num_pw ]");
    println!();
    println!("Options supported by pwgen:");
    println!("  -c or --capitalize");
    println!("    Include at least one capital letter in the password");
    println!("  -A or --no-capitalize");
    println!("    Don't include capital letters in the password");
    println!("  -n or --numerals");
    println!("    Include at least one number in the password");
    println!("  -0 or --no-numerals");
    println!("    Don't include numbers in the password");
    println!("  -y or --symbols");
    println!("    Include at least one special symbol in the password");
    println!("  -r <chars> or --remove-chars=<chars>");
    println!("    Remove characters from the set of characters to generate passwords");
    println!("  -s or --secure");
    println!("    Generate completely random passwords");
    println!("  -B or --ambiguous");
    println!("    Don't include ambiguous characters in the password");
    println!("  -h or --help");
    println!("    Print a help message");
    println!("  -C");
    println!("    Print the generated passwords in columns");
    println!("  -1");
    println!("    Don't print the generated passwords in columns");
    println!("  -v or --no-vowels");
    println!("    Do not use any vowels so as to avoid accidental nasty words");
}
