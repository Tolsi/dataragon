use std::error::Error as StdError;
use std::io;
use std::str::Utf8Error;
use std::{error, fmt};
use reed_solomon::DecoderError;
use shamirsecretsharing::SSSError;

/// The result of a serialization or deserialization operation.
pub type Result<T> = ::std::result::Result<T, Error>;

/// An error that can be produced during (de)serializing.
pub type Error = Box<ErrorKind>;

/// The kind of error that can be produced during a serialization or deserialization.
#[derive(Debug)]
pub enum ErrorKind {
    /// If the error stems from the reader/writer that is being used
    /// during (de)serialization, that error will be stored and returned here.
    Io(io::Error),
    ECCRecoveryError(DecoderError),
    StoredDataDeserializationError(bincode::Error),
    AEADEncryptionError(io::Error),
    ShamirsSecretSharingEncryptionError(SSSError),
    ShamirsSecretSharingDecryptionError(SSSError),
    /// If (de)serializing a message takes more than the provided size limit, this
    /// error is returned.
    SizeLimit,
}

impl StdError for ErrorKind {
    fn description(&self) -> &str {
        match *self {
            ErrorKind::Io(ref err) => error::Error::description(err),
            ErrorKind::ECCRecoveryError(_) => error::Error::description(self),
            ErrorKind::StoredDataDeserializationError(_) => error::Error::description(self),
            ErrorKind::AEADEncryptionError(_) => error::Error::description(self),
            ErrorKind::ShamirsSecretSharingEncryptionError(_) => error::Error::description(self),
            ErrorKind::ShamirsSecretSharingDecryptionError(_) => error::Error::description(self),
            ErrorKind::SizeLimit => "the size limit has been reached",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            ErrorKind::Io(ref err) => Some(err),
            ErrorKind::AEADEncryptionError(ref err) => Some(err),
            ErrorKind::ShamirsSecretSharingEncryptionError(ref err) => Some(err),
            ErrorKind::ShamirsSecretSharingDecryptionError(ref err) => Some(err),
            ErrorKind::StoredDataDeserializationError(ref err) => Some(err),
            ErrorKind::ECCRecoveryError(ref err) => None,
            ErrorKind::SizeLimit => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        ErrorKind::Io(err).into()
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ErrorKind::Io(ref ioerr) => write!(fmt, "IO error: {}", ioerr),
            ErrorKind::ECCRecoveryError(ref err) => write!(fmt, "Error-correcting code encryption error: {:?}", err),
            ErrorKind::StoredDataDeserializationError(ref err) => write!(fmt, "Stored data deserialization error: {}", err),
            ErrorKind::SizeLimit => write!(fmt, "{}", self.description()),
            ErrorKind::AEADEncryptionError(ref err) => write!(fmt, "AEAD encryption error: {}", err),
            ErrorKind::ShamirsSecretSharingEncryptionError(ref err) => write!(fmt, "Shamir's Secret Sharing encryption error: {}", err),
            ErrorKind::ShamirsSecretSharingDecryptionError(ref err) => write!(fmt, "Shamir's Secret Sharing decryption error: {}", err),
        }
    }
}