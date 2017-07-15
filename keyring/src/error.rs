#[cfg(target_os = "linux")]
use secret_service::SsError;
#[cfg(target_os = "macos")]
use security_framework::base::Error as SfError;
#[cfg(target_os = "windows")]
use win32_error::Win32Error;
use std::error;
use std::fmt;
use std::string::FromUtf8Error;
use std::str::Utf8Error;

pub type Result<T> = ::std::result::Result<T, KeyringError>;

#[derive(Debug)]
pub enum KeyringError {
    #[cfg(target_os = "macos")]
    MacOsKeychainError(SfError),
    #[cfg(target_os = "linux")]
    SecretServiceError(SsError),
    #[cfg(target_os = "windows")]
    WindowsVaultError(Win32Error),
    NoBackendFound,
    NoPasswordFound,
    Parse(FromUtf8Error),
    Unicode(Utf8Error),
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => write!(f, "Mac Os Keychain Error: {}", err),
            #[cfg(target_os = "linux")]
            KeyringError::SecretServiceError(ref err) => write!(f, "Secret Service Error: {}", err),
            #[cfg(target_os = "windows")]
            KeyringError::WindowsVaultError(ref err) => write!(f, "Windows Vault Error: {}", err),
            KeyringError::NoBackendFound => write!(f, "Keyring error: No Backend Found"),
            KeyringError::NoPasswordFound => write!(f, "Keyring Error: No Password Found"),
            KeyringError::Parse(ref err) => write!(f, "Keyring Parse Error: {}", err),
            KeyringError::Unicode(ref err) => write!(f, "Keyring Unicode Error: {}", err),
        }
    }
}

impl error::Error for KeyringError {
    fn description(&self) -> &str {
        match *self {
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => err.description(),
            #[cfg(target_os = "linux")]
            KeyringError::SecretServiceError(ref err) => err.description(),
            #[cfg(target_os = "windows")]
            KeyringError::WindowsVaultError(ref err) => err.description(),
            KeyringError::NoBackendFound => "No Backend Found",
            KeyringError::NoPasswordFound => "No Password Found",
            KeyringError::Parse(ref err) => err.description(),
            KeyringError::Unicode(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            #[cfg(target_os = "linux")]
            KeyringError::SecretServiceError(ref err) => Some(err),
            #[cfg(target_os = "macos")]
            KeyringError::MacOsKeychainError(ref err) => Some(err),
            #[cfg(target_os = "windows")]
            KeyringError::WindowsVaultError(ref err) => Some(err),
            KeyringError::Unicode(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
impl From<SsError> for KeyringError {
    fn from(err: SsError) -> KeyringError {
        KeyringError::SecretServiceError(err)
    }
}

#[cfg(target_os = "macos")]
impl From<SfError> for KeyringError {
    fn from(err: SfError) -> KeyringError {
        KeyringError::MacOsKeychainError(err)
    }
}

#[cfg(target_os = "windows")]
impl From<Win32Error> for KeyringError {
    fn from(err: Win32Error) -> KeyringError {
        KeyringError::WindowsVaultError(err)
    }
}

impl From<FromUtf8Error> for KeyringError {
    fn from(err: FromUtf8Error) -> KeyringError {
        KeyringError::Parse(err)
    }
}

impl From<Utf8Error> for KeyringError {
    fn from(err: Utf8Error) -> KeyringError {
        KeyringError::Unicode(err)
    }
}

