//! Debugger extension loading.
//!
//! XBDM can load named extension modules that register additional
//! command prefixes. The PIX capture facility is one such extension (its
//! handler registers the `PIX!` prefix and drives the video capture
//! hardware on the console).

use crate::error::ArgumentError;
use crate::error::Error;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Response;

fn report_argument(err: ArgumentError) -> rootcause::Report<Error> {
    rootcause::Report::new(Error::from(err))
}

/// `dbgextld unload module=0x<addr>`: unload a previously loaded debug
/// extension by its module handle.
#[derive(Debug, Clone, Copy)]
pub struct UnloadDebuggerExtension {
    pub module_handle: u32,
}

impl Command for UnloadDebuggerExtension {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("dbgextld").flag("unload").hex32("module", self.module_handle).finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        response.expect_ok().map_err(rootcause::Report::new)?;
        Ok(())
    }
}

/// `dbgextld name="<module>.xex"`: load a named debugger extension. On
/// success the response head contains `module=0x<handle>` which we parse
/// and return for later unloading.
#[derive(Debug, Clone)]
pub struct LoadDebuggerExtension {
    pub module_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHandle(pub u32);

impl Command for LoadDebuggerExtension {
    type Output = ExtensionHandle;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        if self.module_name.is_empty() {
            return Err(report_argument(ArgumentError::EmptyFilename));
        }
        ArgBuilder::new("dbgextld").quoted("name", &self.module_name).map_err(report_argument).map(ArgBuilder::finish)
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        let kv = crate::commands::kv::parse_kv_line(&head);
        let handle = match kv.get("module") {
            Some(value) => {
                crate::commands::kv::value_u32(value, "module").map_err(|e| rootcause::Report::new(Error::from(e)))?
            }
            None => 0,
        };
        Ok(ExtensionHandle(handle))
    }
}
