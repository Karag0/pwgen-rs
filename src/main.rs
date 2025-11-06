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

#[derive(Debug, Clone)]
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
            capitalize: true,
            no_capitalize: false,
            numerals: true,
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
    parse_args_from_vec(args)
}

fn parse_args_from_vec(args: Vec<String>) -> Config {
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

    // Обработка позиционных аргументов
    match positional_args.len() {
        0 => {},
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

fn generate_secure_password<R: Read>(length: usize, config: &Config, rng: &mut R) -> io::Result<String> {
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

fn generate_memorable_password<R: Read>(length: usize, config: &Config, rng: &mut R) -> io::Result<String> {
    // Если установлен флаг no_vowels, используем безопасную генерацию без шаблона
    if config.no_vowels {
        return generate_secure_password(length, config, rng);
    }

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
        let mut attempts = 0;
        loop {
            rng.read_exact(&mut buf)?;
            let idx = buf[0] as usize % char_set.len();
            let candidate = char_set[idx];

            // Проверка на удаляемые символы
            if let Some(remove_chars) = &config.remove_chars {
                if remove_chars.contains(&candidate) {
                    attempts += 1;
                    if attempts > 100 {
                        // Fallback: используем любой символ после множества попыток
                        password.push(candidate as char);
                        break;
                    }
                    continue;
                }
            }

            // Проверка на неоднозначные символы
            if config.ambiguous && AMBIGUOUS.contains(&candidate) {
                attempts += 1;
                if attempts > 100 {
                    password.push(candidate as char);
                    break;
                }
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

fn apply_requirements<R: Read>(password: Vec<u8>, config: &Config, rng: &mut R) -> io::Result<String> {
    let mut result = password;
    let mut buf = [0u8; 1];

    // Проверка и добавление заглавной буквы если требуется и разрешено
    if config.capitalize && !config.no_capitalize && !result.iter().any(|&c| c.is_ascii_uppercase()) {
        let uppercase_filtered: Vec<u8> = UPPERCASE.iter()
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
            let numerals_filtered: Vec<u8> = NUMERALS.iter()
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
            let symbols_filtered: Vec<u8> = SYMBOLS.iter()
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

// Тесты
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Вспомогательная функция для создания конфигурации для тестов
    fn test_config() -> Config {
        Config {
            pw_length: 8,
            num_pw: 1,
            capitalize: true,
            no_capitalize: false,
            numerals: true,
            no_numerals: false,
            symbols: false,
            remove_chars: None,
            secure: false,
            ambiguous: false,
            columns: false,
            no_vowels: false,
            help: false,
        }
    }

    #[test]
    fn test_build_charset_default() {
        let config = Config::default();
        let charset = build_charset(&config);

        // Должен содержать строчные, заглавные и цифры по умолчанию
        assert!(charset.contains(&b'a'));
        assert!(charset.contains(&b'A'));
        assert!(charset.contains(&b'1'));
        assert!(!charset.contains(&b'!')); // Символы по умолчанию отключены
    }

    #[test]
    fn test_build_charset_no_capitalize() {
        let mut config = test_config();
        config.no_capitalize = true;
        let charset = build_charset(&config);

        // Не должен содержать заглавные буквы
        assert!(charset.contains(&b'a'));
        assert!(!charset.contains(&b'A'));
    }

    #[test]
    fn test_build_charset_no_numerals() {
        let mut config = test_config();
        config.no_numerals = true;
        let charset = build_charset(&config);

        // Не должен содержать цифры
        assert!(!charset.iter().any(|&c| c.is_ascii_digit()));
    }

    #[test]
    fn test_build_charset_symbols() {
        let mut config = test_config();
        config.symbols = true;
        let charset = build_charset(&config);

        // Должен содержать символы
        assert!(charset.contains(&b'!'));
        assert!(charset.contains(&b'@'));
    }

    #[test]
    fn test_build_charset_ambiguous() {
        let mut config = test_config();
        config.ambiguous = true;
        let charset = build_charset(&config);

        // Не должен содержать неоднозначные символы
        assert!(!charset.contains(&b'0'));
        assert!(!charset.contains(&b'O'));
        assert!(!charset.contains(&b'1'));
        assert!(!charset.contains(&b'l'));
    }

    #[test]
    fn test_build_charset_no_vowels() {
        let mut config = test_config();
        config.no_vowels = true;
        let charset = build_charset(&config);

        // Не должен содержать гласные
        assert!(!charset.contains(&b'a'));
        assert!(!charset.contains(&b'e'));
        assert!(!charset.contains(&b'i'));
        assert!(!charset.contains(&b'o'));
        assert!(!charset.contains(&b'u'));
        assert!(!charset.contains(&b'A'));
        assert!(!charset.contains(&b'E'));
        assert!(!charset.contains(&b'I'));
        assert!(!charset.contains(&b'O'));
        assert!(!charset.contains(&b'U'));
    }

    #[test]
    fn test_build_charset_remove_chars() {
        let mut config = test_config();
        config.remove_chars = Some(b"aeiouAEIOU".to_vec());
        let charset = build_charset(&config);

        // Не должен содержать удаленные символы
        assert!(!charset.contains(&b'a'));
        assert!(!charset.contains(&b'A'));
    }

    #[test]
    fn test_generate_secure_password() -> io::Result<()> {
        let config = test_config();
        // Mock RNG, который возвращает предсказуемую последовательность
        let mut mock_rng = Cursor::new(vec![0, 1, 2, 3, 4, 5, 6, 7]);

        let password = generate_secure_password(8, &config, &mut mock_rng)?;

        assert_eq!(password.len(), 8);
        Ok(())
    }

    #[test]
    fn test_generate_memorable_password_pattern() -> io::Result<()> {
        let config = test_config();
        // Mock RNG, который возвращает индексы для согласных и гласных
        // Увеличиваем количество данных, чтобы хватило на все чтения
        let mut mock_rng = Cursor::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, // 8 байт для базовой генерации
            0, 0, 0, 0, // дополнительные байты для apply_requirements
        ]);

        let password = generate_memorable_password(8, &config, &mut mock_rng)?;

        assert_eq!(password.len(), 8);
        Ok(())
    }

    #[test]
    fn test_generate_memorable_password_no_capitalize() -> io::Result<()> {
        let mut config = test_config();
        config.no_capitalize = true;
        // Mock RNG, который возвращает индексы
        let mut mock_rng = Cursor::new(vec![0, 0, 1, 1, 2, 2, 3, 3, 0, 0]);

        let password = generate_memorable_password(8, &config, &mut mock_rng)?;

        // Не должно быть заглавных букв
        assert!(!password.chars().any(|c| c.is_uppercase()));
        Ok(())
    }

    #[test]
    fn test_generate_password_no_vowels() -> io::Result<()> {
        let mut config = test_config();
        config.no_vowels = true;
        let mut mock_rng = Cursor::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let password = generate_memorable_password(10, &config, &mut mock_rng)?;

        // Пароль должен быть сгенерирован
        assert_eq!(password.len(), 10);
        // Не должен содержать гласные
        let vowels = "aeiouyAEIOUY";
        assert!(!password.chars().any(|c| vowels.contains(c)));
        Ok(())
    }

    #[test]
    fn test_apply_requirements_adds_capital() -> io::Result<()> {
        let mut config = test_config();
        config.no_numerals = true; // Отключаем цифры, чтобы они не мешали тесту
        let mut mock_rng = Cursor::new(vec![0, 0]); // Только 2 байта нужно для заглавной буквы

        // Пароль без заглавных букв
        let password = b"abcdefgh".to_vec();
        let result = apply_requirements(password, &config, &mut mock_rng)?;

        // Должна быть хотя бы одна заглавная буква
        assert!(result.chars().any(|c| c.is_uppercase()));
        Ok(())
    }

    #[test]
    fn test_apply_requirements_adds_numeral() -> io::Result<()> {
        let config = test_config();
        // Увеличиваем количество данных
        let mut mock_rng = Cursor::new(vec![0, 0, 0, 0, 0, 0]);

        // Пароль без цифр
        let password = b"abcdefgh".to_vec();
        let result = apply_requirements(password, &config, &mut mock_rng)?;

        // Должна быть хотя бы одна цифра
        assert!(result.chars().any(|c| c.is_ascii_digit()));
        Ok(())
    }

    #[test]
    fn test_apply_requirements_adds_symbol() -> io::Result<()> {
        let mut config = test_config();
        config.symbols = true;
        // Увеличиваем количество данных
        let mut mock_rng = Cursor::new(vec![0, 0, 0, 0, 0, 0]);

        // Пароль без символов
        let password = b"abcdefgh".to_vec();
        let result = apply_requirements(password, &config, &mut mock_rng)?;

        // Должен быть хотя бы один символ
        assert!(result.chars().any(|c| SYMBOLS.contains(&(c as u8))));
        Ok(())
    }

    #[test]
    fn test_parse_args_default() {
        let args = vec!["pwgen".to_string()];
        let config = parse_args_from_vec(args);

        assert_eq!(config.pw_length, DEFAULT_LENGTH);
        assert_eq!(config.num_pw, DEFAULT_COUNT);
        assert!(config.capitalize);
        assert!(config.numerals);
    }

    #[test]
    fn test_parse_args_with_length() {
        let args = vec!["pwgen".to_string(), "12".to_string()];
        let config = parse_args_from_vec(args);

        assert_eq!(config.pw_length, 12);
        assert_eq!(config.num_pw, DEFAULT_COUNT);
    }

    #[test]
    fn test_parse_args_with_length_and_count() {
        let args = vec!["pwgen".to_string(), "12".to_string(), "5".to_string()];
        let config = parse_args_from_vec(args);

        assert_eq!(config.pw_length, 12);
        assert_eq!(config.num_pw, 5);
    }

    #[test]
    fn test_parse_args_options() {
        let args = vec![
            "pwgen".to_string(),
            "-A".to_string(), // no-capitalize
            "-0".to_string(), // no-numerals
            "-y".to_string(), // symbols
            "-s".to_string(), // secure
            "-B".to_string(), // ambiguous
            "-v".to_string(), // no-vowels
            "-1".to_string(), // no columns
        ];
        let config = parse_args_from_vec(args);

        assert!(config.no_capitalize);
        assert!(config.no_numerals);
        assert!(config.symbols);
        assert!(config.secure);
        assert!(config.ambiguous);
        assert!(config.no_vowels);
        assert!(!config.columns);
    }

    #[test]
    fn test_parse_args_remove_chars() {
        let args = vec![
            "pwgen".to_string(),
            "-r".to_string(),
            "abc".to_string(),
        ];
        let config = parse_args_from_vec(args);

        assert_eq!(config.remove_chars, Some(b"abc".to_vec()));
    }

    #[test]
    fn test_print_passwords_columns() {
        let passwords = vec![
            "abc".to_string(),
            "defg".to_string(),
            "hi".to_string(),
            "jklmn".to_string(),
            "op".to_string(),
        ];

        // Этот тест просто проверяет, что функция не падает
        print_passwords(&passwords, true);
        print_passwords(&passwords, false);
    }

    #[test]
    fn test_charset_constants() {
        // Проверяем, что константы не пустые
        assert!(!LOWERCASE.is_empty());
        assert!(!UPPERCASE.is_empty());
        assert!(!NUMERALS.is_empty());
        assert!(!SYMBOLS.is_empty());
        assert!(!VOWELS.is_empty());
        assert!(!AMBIGUOUS.is_empty());
        assert!(!CONSONANTS.is_empty());
        assert!(!CONSONANTS_LOWER.is_empty());
        assert!(!VOWELS_LOWER.is_empty());
    }
}
