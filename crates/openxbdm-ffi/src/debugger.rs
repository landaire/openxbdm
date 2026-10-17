#[diplomat::bridge]
pub mod ffi {
    use std::cell::Cell;
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands::AccessViolationKind;
    use openxbdm_client::commands::DataAccess;
    use openxbdm_client::commands::ExceptionDetail;
    use openxbdm_client::commands::NtStatus;
    use openxbdm_client::commands::StopOnFlags;
    use openxbdm_client::commands::StopReason;
    use openxbdm_client::commands::StopState;

    /// `isstopped` reply. Flattened: `kind()` returns a discriminant;
    /// field accessors are valid only for the kinds they name.
    ///
    /// Kinds: 0=Running, 1=Stopped, 2=DebugString, 3=Assertion,
    /// 4=Breakpoint, 5=SingleStep, 6=NtAssertion, 7=DataBreakpoint, 8=Rip,
    /// 9=Exception.
    #[diplomat::opaque]
    pub struct OpenxbdmStopState {
        kind: u32,
        thread: u32,
        address: u32,
        data_address: u32,
        length: u32,
        access: u32,

        code: Option<NtStatus>,
        access_violation: bool,
        first_chance: bool,
        noncontinuable: bool,

        message: Option<String>,
    }

    impl OpenxbdmStopState {
        pub fn kind(&self) -> u32 {
            self.kind
        }

        /// Valid for every kind except 0 (Running) and 1 (Stopped).
        pub fn thread(&self) -> u32 {
            self.thread
        }

        /// Instruction address for kinds 4-7 and 9; string address for 3.
        pub fn address(&self) -> u32 {
            self.address
        }

        /// Kind 7: watched data address. Kind 9: faulting data address when
        /// `is_access_violation()`, else the parameter array address.
        pub fn data_address(&self) -> u32 {
            self.data_address
        }

        /// Kind 3: string length. Kind 9 without access violation: number
        /// of exception parameters.
        pub fn length(&self) -> u32 {
            self.length
        }

        /// Kind 7: 1=Write, 2=Read, 3=Execute. Kind 9 with access
        /// violation: 0=Read, 1=Write.
        pub fn access(&self) -> u32 {
            self.access
        }

        /// Kind 9: the exception code; 0 for other kinds.
        pub fn exception_code(&self) -> u32 {
            self.code.map_or(0, |code| code.0)
        }

        /// Kind 9: the exception is an access violation (0xc0000005).
        pub fn is_access_violation(&self) -> bool {
            self.access_violation
        }

        /// Kind 9: first-chance exception.
        pub fn is_first_chance(&self) -> bool {
            self.first_chance
        }

        /// Kind 9: noncontinuable exception.
        pub fn is_noncontinuable(&self) -> bool {
            self.noncontinuable
        }

        /// Kind 8: whether the stop line carried a string.
        pub fn has_message(&self) -> bool {
            self.message.is_some()
        }

        /// Kind 8: the string, when `has_message()`.
        pub fn message(&self, out: &mut DiplomatWrite) {
            if let Some(message) = &self.message {
                let _ = write!(out, "{message}");
            }
        }
    }

    impl OpenxbdmStopState {
        /// Fields a kind does not name read as zero, as the accessor docs state.
        fn with_kind(kind: u32) -> Self {
            Self {
                kind,
                thread: 0,
                address: 0,
                data_address: 0,
                length: 0,
                access: 0,
                code: None,
                access_violation: false,
                first_chance: false,
                noncontinuable: false,
                message: None,
            }
        }
    }

    impl From<StopState> for OpenxbdmStopState {
        fn from(state: StopState) -> Self {
            let StopState::Halted(reason) = state else {
                return Self::with_kind(0);
            };

            match reason {
                StopReason::Stopped => Self::with_kind(1),
                StopReason::DebugString { thread } => Self {
                    thread: thread.0,
                    ..Self::with_kind(2)
                },
                StopReason::Assertion {
                    thread,
                    string_address,
                    string_length,
                } => Self {
                    thread: thread.0,
                    address: string_address,
                    length: string_length,
                    ..Self::with_kind(3)
                },
                StopReason::Breakpoint { address, thread } => Self {
                    thread: thread.0,
                    address,
                    ..Self::with_kind(4)
                },
                StopReason::SingleStep { address, thread } => Self {
                    thread: thread.0,
                    address,
                    ..Self::with_kind(5)
                },
                StopReason::NtAssertion { address, thread } => Self {
                    thread: thread.0,
                    address,
                    ..Self::with_kind(6)
                },
                StopReason::DataBreakpoint {
                    access,
                    data_address,
                    address,
                    thread,
                } => {
                    let access = match access {
                        DataAccess::Write => 1,
                        DataAccess::Read => 2,
                        DataAccess::Execute => 3,
                    };

                    Self {
                        thread: thread.0,
                        address,
                        data_address,
                        access,
                        ..Self::with_kind(7)
                    }
                }
                StopReason::Rip { thread, message } => Self {
                    thread: thread.0,
                    message,
                    ..Self::with_kind(8)
                },
                StopReason::Exception(exception) => {
                    let base = Self {
                        thread: exception.thread.0,
                        address: exception.address,
                        code: Some(exception.code),
                        first_chance: exception.first_chance,
                        noncontinuable: exception.noncontinuable,
                        ..Self::with_kind(9)
                    };

                    match exception.detail {
                        ExceptionDetail::AccessViolation {
                            access,
                            data_address,
                        } => {
                            let access = match access {
                                AccessViolationKind::Read => 0,
                                AccessViolationKind::Write => 1,
                            };

                            Self {
                                access_violation: true,
                                data_address,
                                access,
                                ..base
                            }
                        }
                        ExceptionDetail::Parameters { count, address } => Self {
                            length: count,
                            data_address: address,
                            ..base
                        },
                    }
                }
            }
        }
    }

    /// Stop-on / nostopon flag set.
    #[diplomat::opaque]
    pub struct OpenxbdmStopOnFlags {
        inner: Cell<StopOnFlags>,
    }

    impl OpenxbdmStopOnFlags {
        #[diplomat::attr(auto, constructor)]
        pub fn new() -> Box<OpenxbdmStopOnFlags> {
            Box::new(OpenxbdmStopOnFlags {
                inner: Cell::new(StopOnFlags::default()),
            })
        }

        pub fn set_create_thread(&self, v: bool) {
            self.update(|flags| flags.create_thread = v);
        }

        pub fn set_first_chance_exception(&self, v: bool) {
            self.update(|flags| flags.first_chance_exception = v);
        }

        pub fn set_debugstr(&self, v: bool) {
            self.update(|flags| flags.debugstr = v);
        }

        pub fn set_stacktrace(&self, v: bool) {
            self.update(|flags| flags.stacktrace = v);
        }

        pub fn set_module_load(&self, v: bool) {
            self.update(|flags| flags.module_load = v);
        }

        pub fn set_pogo_module_start(&self, v: bool) {
            self.update(|flags| flags.pogo_module_start = v);
        }

        pub fn set_all(&self, v: bool) {
            self.update(|flags| flags.all = v);
        }
    }

    impl OpenxbdmStopOnFlags {
        pub(crate) fn flags(&self) -> StopOnFlags {
            self.inner.get()
        }

        fn update(&self, apply: impl FnOnce(&mut StopOnFlags)) {
            let mut flags = self.inner.get();
            apply(&mut flags);
            self.inner.set(flags);
        }
    }
}
