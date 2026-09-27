//! Process start/exit events from the Microsoft-Windows-Kernel-Process ETW
//! provider.
//!
//! A real-time session receives ProcessStart (1), ProcessStop (2) and
//! ProcessRundown (15). A rundown is requested with CAPTURE_STATE and
//! announces every running process with the same payload as a start event,
//! so it replaces a separate process snapshot. Events are decoded with a
//! field layout that TDH describes once per event version.

use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;

use stemma_core::model::{ParentRef, ProcessInfo, ProcessKey};
use stemma_core::platform::{PlatformError, ProcessEvent, ProcessEventSink, ProcessSource};
use tracing::{debug, info, warn};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_CAPTURE_STATE,
    EVENT_CONTROL_CODE_DISABLE_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_HEADER_FLAG_32_BIT_HEADER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, PropertyParamCount,
    PropertyParamFixedCount, PropertyParamFixedLength, PropertyParamLength, PropertyStruct,
    StartTraceW, TDH_INTYPE_ANSISTRING, TDH_INTYPE_BINARY, TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_DOUBLE, TDH_INTYPE_FILETIME, TDH_INTYPE_FLOAT, TDH_INTYPE_GUID,
    TDH_INTYPE_HEXINT32, TDH_INTYPE_HEXINT64, TDH_INTYPE_INT8, TDH_INTYPE_INT16,
    TDH_INTYPE_INT32, TDH_INTYPE_INT64, TDH_INTYPE_POINTER, TDH_INTYPE_SID,
    TDH_INTYPE_SIZET, TDH_INTYPE_SYSTEMTIME, TDH_INTYPE_UINT8, TDH_INTYPE_UINT16,
    TDH_INTYPE_UINT32, TDH_INTYPE_UINT64, TDH_INTYPE_UNICODESTRING, TRACE_EVENT_INFO,
    TRACE_LEVEL_INFORMATION, TdhGetEventInformation, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

use crate::util::{os_error, wide};

const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
const KEYWORD_PROCESS: u64 = 0x10;
const EVENT_START: u16 = 1;
const EVENT_STOP: u16 = 2;
const EVENT_RUNDOWN: u16 = 15;
const SESSION_NAME: &str = "StemmaProcessEtw";
/// Parent sequence number of processes without a parent (Idle, System).
const NO_PARENT: u64 = u64::MAX;
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

/// Process events from a real-time ETW session named `StemmaProcessEtw`.
#[derive(Default)]
pub struct EtwProcessSource {
    session: Mutex<Option<Session>>,
}

struct Session {
    control: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
    thread: JoinHandle<()>,
    context: *mut Context,
}

// SAFETY: the context pointer is only dereferenced by the trace thread and
// freed after that thread has been joined.
unsafe impl Send for Session {}

struct Context {
    sink: ProcessEventSink,
    plans: Mutex<HashMap<(u16, u8), Option<Plan>>>,
    events_lost: AtomicU32,
}

impl EtwProcessSource {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Drop for EtwProcessSource {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ProcessSource for EtwProcessSource {
    fn start(&self, sink: ProcessEventSink) -> Result<(), PlatformError> {
        let mut session = self.session.lock().unwrap();
        if session.is_some() {
            return Ok(());
        }
        let name = wide(SESSION_NAME);
        // A session left behind by a crashed run would make StartTrace fail.
        stop_session_by_name(&name);
        let mut control = CONTROLTRACE_HANDLE::default();
        let mut properties = Properties::new();
        // SAFETY: `properties` is a correctly sized EVENT_TRACE_PROPERTIES buffer.
        let mut rc = unsafe { StartTraceW(&mut control, name.as_ptr(), properties.as_mut_ptr()) };
        if rc == ERROR_ALREADY_EXISTS {
            stop_session_by_name(&name);
            properties = Properties::new();
            // SAFETY: as above.
            rc = unsafe { StartTraceW(&mut control, name.as_ptr(), properties.as_mut_ptr()) };
        }
        if rc != 0 {
            return Err(os_error("StartTraceW", rc));
        }
        if let Err(err) = enable_provider(control) {
            stop_session(control);
            return Err(err);
        }

        let context = Box::into_raw(Box::new(Context {
            sink,
            plans: Mutex::new(HashMap::new()),
            events_lost: AtomicU32::new(0),
        }));
        let mut logger_name = name.clone();
        // SAFETY: an all-zero EVENT_TRACE_LOGFILEW is a valid initial value.
        let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { zeroed() };
        logfile.LoggerName = logger_name.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        logfile.BufferCallback = Some(on_buffer);
        logfile.Context = context.cast();
        // SAFETY: `logfile` is fully initialized for a real-time consumer.
        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == INVALID_PROCESSTRACE_HANDLE {
            let err = os_error("OpenTraceW", crate::util::last_error());
            stop_session(control);
            // SAFETY: the context was never handed to a running trace.
            drop(unsafe { Box::from_raw(context) });
            return Err(err);
        }
        let thread = std::thread::Builder::new()
            .name("stemma-etw".to_owned())
            .spawn(move || {
                // SAFETY: `trace` is an open trace handle; ProcessTrace blocks
                // until the session stops or the handle is closed.
                let rc = unsafe { ProcessTrace(&trace, 1, null(), null()) };
                debug!(rc, "ETW ProcessTrace returned");
            })
            .map_err(|e| PlatformError::Other(format!("cannot start ETW thread: {e}")))?;
        info!("ETW process session started");
        *session = Some(Session {
            control,
            trace,
            thread,
            context,
        });
        Ok(())
    }

    fn request_resync(&self) {
        let session = self.session.lock().unwrap();
        let Some(session) = session.as_ref() else {
            return;
        };
        // SAFETY: the session handle is valid while `session` exists.
        let rc = unsafe {
            EnableTraceEx2(
                session.control,
                &KERNEL_PROCESS,
                EVENT_CONTROL_CODE_CAPTURE_STATE,
                TRACE_LEVEL_INFORMATION as u8,
                KEYWORD_PROCESS,
                0,
                0,
                null(),
            )
        };
        if rc == 0 {
            debug!("ETW process rundown requested");
        } else {
            warn!(rc, "ETW process rundown request failed");
        }
    }

    fn stop(&self) {
        let Some(session) = self.session.lock().unwrap().take() else {
            return;
        };
        stop_session(session.control);
        // SAFETY: the trace handle came from OpenTraceW and is closed once.
        unsafe { CloseTrace(session.trace) };
        let _ = session.thread.join();
        // SAFETY: the trace thread, the only user of the context, has exited.
        drop(unsafe { Box::from_raw(session.context) });
        info!("ETW process session stopped");
    }
}

/// An EVENT_TRACE_PROPERTIES block followed by room for the session name.
struct Properties(Vec<u64>);

impl Properties {
    fn new() -> Self {
        let name_bytes = (SESSION_NAME.len() + 1) * 2;
        let total = size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes;
        let mut buffer = vec![0u64; total.div_ceil(8)];
        // SAFETY: the buffer is zeroed, 8-byte aligned and large enough.
        let properties = unsafe { &mut *buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() };
        properties.Wnode.BufferSize = total as u32;
        properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.Wnode.ClientContext = 1; // QueryPerformanceCounter timestamps
        properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        properties.BufferSize = 64;
        properties.MinimumBuffers = 4;
        properties.MaximumBuffers = 16;
        properties.FlushTimer = 1;
        Self(buffer)
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.0.as_mut_ptr().cast()
    }
}

fn stop_session_by_name(name: &[u16]) {
    let mut properties = Properties::new();
    // SAFETY: valid name and properties buffer; failure means no such session.
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            name.as_ptr(),
            properties.as_mut_ptr(),
            EVENT_TRACE_CONTROL_STOP,
        )
    };
}

fn stop_session(control: CONTROLTRACE_HANDLE) {
    let mut properties = Properties::new();
    // SAFETY: `control` is a started session; both calls tolerate a session
    // that has already stopped.
    unsafe {
        EnableTraceEx2(
            control,
            &KERNEL_PROCESS,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0,
            0,
            0,
            0,
            null(),
        );
        ControlTraceW(control, null(), properties.as_mut_ptr(), EVENT_TRACE_CONTROL_STOP);
    }
}

fn enable_provider(control: CONTROLTRACE_HANDLE) -> Result<(), PlatformError> {
    // EVENT_FILTER_EVENT_ID: FilterIn, Reserved, Count, then the event ids.
    let ids = [EVENT_START, EVENT_STOP, EVENT_RUNDOWN];
    let mut filter = vec![1u8, 0];
    filter.extend((ids.len() as u16).to_le_bytes());
    for id in ids {
        filter.extend(id.to_le_bytes());
    }
    let mut descriptor = EVENT_FILTER_DESCRIPTOR {
        Ptr: filter.as_ptr() as u64,
        Size: filter.len() as u32,
        Type: EVENT_FILTER_TYPE_EVENT_ID,
    };
    let parameters = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableProperty: 0,
        ControlFlags: 0,
        SourceId: GUID::from_u128(0),
        EnableFilterDesc: &mut descriptor,
        FilterDescCount: 1,
    };
    // SAFETY: all pointers are valid for the duration of the call.
    let rc = unsafe {
        EnableTraceEx2(
            control,
            &KERNEL_PROCESS,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION as u8,
            KEYWORD_PROCESS,
            0,
            0,
            &parameters,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(os_error("EnableTraceEx2", rc))
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // SAFETY: ETW passes a valid record whose UserContext is our Context.
    let (record, context) = unsafe {
        let record = &*record;
        (record, &*(record.UserContext as *const Context))
    };
    if !guid_eq(&record.EventHeader.ProviderId, &KERNEL_PROCESS) {
        return;
    }
    let descriptor = &record.EventHeader.EventDescriptor;
    let id = descriptor.Id;
    if !matches!(id, EVENT_START | EVENT_STOP | EVENT_RUNDOWN) {
        return;
    }
    let fields = {
        let mut plans = context.plans.lock().unwrap();
        let plan = plans
            .entry((id, descriptor.Version))
            .or_insert_with(|| Plan::build(record));
        match plan {
            Some(plan) => plan.decode(record),
            None => return,
        }
    };
    let Some(fields) = fields else {
        return;
    };
    let (Some(pid), Some(instance)) = (fields.pid, fields.sequence) else {
        return;
    };
    let key = ProcessKey { pid, instance };
    let event = if id == EVENT_STOP {
        ProcessEvent::Exited(key)
    } else {
        let parent = match (fields.parent_pid, fields.parent_sequence) {
            (None | Some(0), _) | (_, Some(NO_PARENT)) => None,
            (Some(pid), Some(instance)) if instance != 0 => Some(ParentRef {
                pid,
                instance: Some(instance),
            }),
            (Some(pid), _) => Some(ParentRef {
                pid,
                instance: None,
            }),
        };
        ProcessEvent::Started(ProcessInfo {
            key,
            parent,
            name: fields.image_name.unwrap_or_default(),
            create_time: fields.create_time.unwrap_or(0),
        })
    };
    (context.sink)(event);
}

unsafe extern "system" fn on_buffer(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    // SAFETY: ETW passes the logfile we opened; its Context is our Context.
    let (lost, context) = unsafe {
        let logfile = &*logfile;
        (logfile.EventsLost, &*(logfile.Context as *const Context))
    };
    let previous = context.events_lost.swap(lost, Ordering::Relaxed);
    if lost > previous {
        (context.sink)(ProcessEvent::Lost {
            count: u64::from(lost - previous),
        });
    }
    1 // keep processing
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[derive(Default)]
struct Fields {
    pid: Option<u32>,
    sequence: Option<u64>,
    create_time: Option<u64>,
    parent_pid: Option<u32>,
    parent_sequence: Option<u64>,
    image_name: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wanted {
    Pid,
    Sequence,
    CreateTime,
    ParentPid,
    ParentSequence,
    ImageName,
}

struct Field {
    in_type: i32,
    /// Element count for fixed-size arrays, 1 otherwise.
    count: usize,
    /// Byte length of fixed-length binary fields.
    fixed_length: Option<usize>,
    /// The size cannot be computed (struct or length/count from another field).
    unsupported: bool,
    wanted: Option<Wanted>,
}

/// Where the fields we need are in one event version.
struct Plan {
    /// Fields up to and including the last wanted one.
    fields: Vec<Field>,
}

impl Plan {
    fn build(record: &EVENT_RECORD) -> Option<Self> {
        let mut size = 0u32;
        // SAFETY: a null buffer queries the required size.
        let rc = unsafe { TdhGetEventInformation(record, 0, null(), null_mut(), &mut size) };
        if rc != ERROR_INSUFFICIENT_BUFFER {
            warn!(rc, "TdhGetEventInformation size query failed");
            return None;
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let info = buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
        // SAFETY: `buffer` holds `size` bytes, suitably aligned.
        let rc = unsafe { TdhGetEventInformation(record, 0, null(), info, &mut size) };
        if rc != 0 {
            warn!(rc, "TdhGetEventInformation failed");
            return None;
        }
        // SAFETY: TDH filled a TRACE_EVENT_INFO followed by its property
        // array and the strings the offsets point to.
        let (count, properties, base) = unsafe {
            let info = &*info;
            (
                info.TopLevelPropertyCount as usize,
                info.EventPropertyInfoArray.as_ptr(),
                buffer.as_ptr().cast::<u8>(),
            )
        };
        let mut fields = Vec::with_capacity(count);
        for i in 0..count {
            // SAFETY: TDH returned `count` top-level properties.
            let property = unsafe { &*properties.add(i) };
            // SAFETY: NameOffset points to a NUL-terminated UTF-16 string.
            let name = unsafe { read_wide(base.add(property.NameOffset as usize).cast()) };
            let flags = property.Flags;
            // SAFETY: the union variants are selected by `flags`.
            let (in_type, count, length) = unsafe {
                (
                    i32::from(property.Anonymous1.nonStructType.InType),
                    property.Anonymous2.count,
                    property.Anonymous3.length,
                )
            };
            fields.push(Field {
                in_type,
                count: if flags & PropertyParamFixedCount != 0 {
                    usize::from(count)
                } else {
                    1
                },
                fixed_length: (flags & PropertyParamFixedLength != 0).then_some(usize::from(length)),
                unsupported: flags & (PropertyStruct | PropertyParamCount | PropertyParamLength) != 0,
                wanted: match name.as_str() {
                    "ProcessID" => Some(Wanted::Pid),
                    "ProcessSequenceNumber" => Some(Wanted::Sequence),
                    "CreateTime" => Some(Wanted::CreateTime),
                    "ParentProcessID" => Some(Wanted::ParentPid),
                    "ParentProcessSequenceNumber" => Some(Wanted::ParentSequence),
                    "ImageName" => Some(Wanted::ImageName),
                    _ => None,
                },
            });
        }
        let last = fields.iter().rposition(|f| f.wanted.is_some())?;
        fields.truncate(last + 1);
        debug!(
            id = record.EventHeader.EventDescriptor.Id,
            version = record.EventHeader.EventDescriptor.Version,
            fields = fields.len(),
            "ETW event layout read"
        );
        Some(Self { fields })
    }

    fn decode(&self, record: &EVENT_RECORD) -> Option<Fields> {
        // SAFETY: UserData holds UserDataLength bytes.
        let data = unsafe {
            std::slice::from_raw_parts(
                record.UserData.cast::<u8>(),
                usize::from(record.UserDataLength),
            )
        };
        let is_32_bit =
            u32::from(record.EventHeader.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0;
        let mut out = Fields::default();
        let mut offset = 0;
        for field in &self.fields {
            if field.unsupported {
                return None;
            }
            let rest = data.get(offset..)?;
            let size = match field.fixed_length {
                Some(length) if field.in_type == TDH_INTYPE_BINARY => length,
                _ => field_size(field.in_type, rest, is_32_bit)? * field.count,
            };
            let value = rest.get(..size)?;
            match field.wanted {
                Some(Wanted::Pid) => out.pid = read_u32(value),
                Some(Wanted::ParentPid) => out.parent_pid = read_u32(value),
                Some(Wanted::Sequence) => out.sequence = read_u64(value),
                Some(Wanted::ParentSequence) => out.parent_sequence = read_u64(value),
                Some(Wanted::CreateTime) => out.create_time = read_u64(value),
                Some(Wanted::ImageName) if field.in_type == TDH_INTYPE_UNICODESTRING => {
                    out.image_name = Some(basename(value));
                }
                _ => {}
            }
            offset += size;
        }
        Some(out)
    }
}

/// Size of one value of `in_type` at the start of `data`.
fn field_size(in_type: i32, data: &[u8], is_32_bit: bool) -> Option<usize> {
    Some(match in_type {
        TDH_INTYPE_INT8 | TDH_INTYPE_UINT8 => 1,
        TDH_INTYPE_INT16 | TDH_INTYPE_UINT16 => 2,
        TDH_INTYPE_INT32 | TDH_INTYPE_UINT32 | TDH_INTYPE_HEXINT32 | TDH_INTYPE_FLOAT
        | TDH_INTYPE_BOOLEAN => 4,
        TDH_INTYPE_INT64 | TDH_INTYPE_UINT64 | TDH_INTYPE_HEXINT64 | TDH_INTYPE_FILETIME
        | TDH_INTYPE_DOUBLE => 8,
        TDH_INTYPE_GUID | TDH_INTYPE_SYSTEMTIME => 16,
        TDH_INTYPE_POINTER | TDH_INTYPE_SIZET => {
            if is_32_bit {
                4
            } else {
                8
            }
        }
        TDH_INTYPE_UNICODESTRING => data
            .as_chunks::<2>()
            .0
            .iter()
            .position(|c| *c == [0, 0])
            .map_or(data.len(), |units| (units + 1) * 2),
        TDH_INTYPE_ANSISTRING => data.iter().position(|&b| b == 0).map_or(data.len(), |n| n + 1),
        TDH_INTYPE_SID => 8 + 4 * usize::from(*data.get(1)?),
        _ => return None,
    })
}

fn read_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

/// File name from an NT path such as `\Device\HarddiskVolume3\Windows\cmd.exe`.
fn basename(utf16: &[u8]) -> String {
    let units: Vec<u16> = utf16
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .take_while(|&u| u != 0)
        .collect();
    let path = String::from_utf16_lossy(&units);
    path.rsplit('\\').next().unwrap_or_default().to_owned()
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `ptr` must point to a readable, NUL-terminated UTF-16 string.
unsafe fn read_wide(ptr: *const u16) -> String {
    let mut len = 0;
    // SAFETY: guaranteed by the caller.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn variable_field_sizes() {
        let name = utf16("cmd.exe");
        let mut data = name.clone();
        data.extend([1, 2, 3]);
        assert_eq!(field_size(TDH_INTYPE_UNICODESTRING, &data, false), Some(name.len()));
        assert_eq!(field_size(TDH_INTYPE_ANSISTRING, b"abc\0xyz", false), Some(4));
        // A SID with two sub-authorities.
        assert_eq!(field_size(TDH_INTYPE_SID, &[1, 2, 0, 0, 0, 0, 0, 5], false), Some(16));
        assert_eq!(field_size(TDH_INTYPE_POINTER, &[], true), Some(4));
        assert_eq!(field_size(TDH_INTYPE_BOOLEAN, &[], false), Some(4));
        assert_eq!(field_size(TDH_INTYPE_BINARY, &[], false), None);
    }

    #[test]
    fn basename_of_nt_path() {
        let path = utf16(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe");
        assert_eq!(basename(&path), "cmd.exe");
        assert_eq!(basename(&utf16("微信.exe")), "微信.exe");
    }
}
