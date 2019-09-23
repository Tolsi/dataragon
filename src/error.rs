use std::error::Error as StdError;
use std::io;
use std::str::Utf8Error;
use std::{error, fmt};
use reed_solomon::DecoderError;

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
    /// Returned if the deserializer attempts to deserialize a string that is not valid utf8
    InvalidUtf8Encoding(Utf8Error),
    ECCRecoveryError(DecoderError),
    BincodeDeserializationError(bincode::Error),
    /// If (de)serializing a message takes more than the provided size limit, this
    /// error is returned.
    SizeLimit,
}

impl StdError for ErrorKind {
    fn description(&self) -> &str {
        match *self {
            ErrorKind::Io(ref err) => error::Error::description(err),
            ErrorKind::InvalidUtf8Encoding(_) => "string is not valid utf8",
            // todo
            ErrorKind::ECCRecoveryError(_) => "",
            ErrorKind::BincodeDeserializationError(_) => "",
            ErrorKind::SizeLimit => "the size limit has been reached",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ErrorKind::Io(ref err) => Some(err),
            ErrorKind::InvalidUtf8Encoding(_) => None,
            ErrorKind::ECCRecoveryError(_) => None,
            ErrorKind::BincodeDeserializationError(_) => None,
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
            ErrorKind::Io(ref ioerr) => write!(fmt, "io error: {}", ioerr),
            ErrorKind::InvalidUtf8Encoding(_) => write!(fmt, "{}", self.description()),
            ErrorKind::ECCRecoveryError(_) => write!(fmt, "{}", self.description()),
            ErrorKind::BincodeDeserializationError(_) => write!(fmt, "{}", self.description()),
            ErrorKind::SizeLimit => write!(fmt, "{}", self.description()),
        }
    }
}

//impl From<reed_solomon::DecoderError> for ErrorKind {
//    fn from(de: DecoderError) -> Self {
//        ErrorKind::ECCRecoveryError(de)
//    }
//}
//
//impl From<Box<bincode::ErrorKind>> for Box<ErrorKind> {
//    fn from(e: Box<bincode::ErrorKind>) -> Self {
//        ErrorKind::BincodeDeserializationError(e)?
//    }
//}