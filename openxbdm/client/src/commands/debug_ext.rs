//! Debugger extension loading.
//!
//! XBDM can load named extension modules that register additional
//! command prefixes. The PIX capture facility is one such extension (its
//! handler registers the `PIX!` prefix and drives the video capture
//! hardware on the console).

use crate::commands::error::report_argument;
use crate::commands::error::report_parse;
use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_u32;
use crate::error::ArgumentError;
use crate::error::Error;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHandle(pub u32);

/// `dbgextld unload module=0x<handle>`: release one reference to the loaded
/// debugger extension; the module is unloaded when the count reaches zero.
/// A handle other than the loaded one gives `423- bad parameter`.
#[derive(Debug, Clone, Copy)]
pub struct UnloadDebuggerExtension {
    pub module: ExtensionHandle,
}

impl Command for UnloadDebuggerExtension {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("dbgextld")
            .flag("unload")
            .hex32("module", self.module.0)
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;

        Ok(())
    }
}

/// `dbgextld name="<module>"`: load a debugger extension from the DEVKIT
/// `DMEXT` directory. Loading the already loaded extension again increments
/// its reference count and returns the same handle; loading a different one
/// while one is loaded gives `443- `. The reply is `200- module=0x<handle>`.
#[derive(Debug, Clone)]
pub struct LoadDebuggerExtension {
    pub module_name: String,
}

impl Command for LoadDebuggerExtension {
    type Output = ExtensionHandle;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        if self.module_name.is_empty() {
            return Err(report_argument(ArgumentError::EmptyFilename));
        }

        ArgBuilder::new("dbgextld")
            .quoted("name", &self.module_name)
            .map_err(report_argument)
            .map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = parse_kv_line(&head);

        kv.require("module")
            .and_then(|value| value_u32(value, "module"))
            .map(ExtensionHandle)
            .map_err(report_parse)
    }
}
