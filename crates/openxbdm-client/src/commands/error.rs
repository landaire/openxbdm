use crate::error::ArgumentError;
use crate::error::Error;
use crate::error::ParseError;

pub(crate) fn report_parse(err: ParseError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

pub(crate) fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}
