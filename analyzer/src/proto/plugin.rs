use std::{
    ffi::c_void,
    fs,
    io::{Error, ErrorKind},
    path::Path,
    slice,
};

use libloading::{Library, Symbol};

use crate::parser::layer::{Field, Layer};

use super::{ApplicationDecoder, DecoderRegistry, TransportInfo};

pub const PLUGIN_ABI_VERSION: u32 = 1;
pub const PLUGIN_ENTRY_SYMBOL: &[u8] = b"requin_plugin_init_v1\0";

pub type PluginEmitFieldFn = unsafe extern "C" fn(
    context: *mut c_void,
    field_name: *const u8,
    field_name_len: usize,
    value: *const u8,
    value_len: usize,
    offset: usize,
    length: usize,
) -> bool;

pub type PluginDecodeFn = unsafe extern "C" fn(
    packet: *const u8,
    packet_len: usize,
    ip_protocol: u8,
    source_port: u16,
    destination_port: u16,
    payload_offset: usize,
    context: *mut c_void,
    emit_field: PluginEmitFieldFn,
) -> bool;

pub type PluginRegisterDecoderFn = unsafe extern "C" fn(
    context: *mut c_void,
    name: *const u8,
    name_len: usize,
    decode: PluginDecodeFn,
) -> bool;

pub type PluginEntryV1 = unsafe extern "C" fn(host: *const PluginHostV1) -> bool;

#[repr(C)]
pub struct PluginHostV1 {
    pub abi_version: u32,
    pub context: *mut c_void,
    pub register_application_decoder: PluginRegisterDecoderFn,
}

struct RegisteredDecoder {
    name: String,
    decode: PluginDecodeFn,
}

#[derive(Default)]
struct Registration {
    decoders: Vec<RegisteredDecoder>,
    invalid_registration: bool,
}

struct EmitContext {
    fields: Vec<Field>,
    packet_len: usize,
}

struct PluginApplicationDecoder {
    name: String,
    decode: PluginDecodeFn,
}

impl ApplicationDecoder for PluginApplicationDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        let mut context = EmitContext {
            fields: Vec::new(),
            packet_len: offset.saturating_add(payload.len()),
        };
        let recognized = unsafe {
            (self.decode)(
                payload.as_ptr(),
                payload.len(),
                transport.protocol,
                transport.source_port,
                transport.destination_port,
                offset,
                (&mut context as *mut EmitContext).cast(),
                emit_field,
            )
        };
        recognized.then(|| Layer {
            name: self.name.clone().into(),
            fields: context.fields,
        })
    }
}

impl DecoderRegistry {
    /// Loads a trusted native library exporting `requin_plugin_init_v1`.
    ///
    /// Native plugins execute with the permissions of this process. Only load
    /// libraries from sources the user trusts and that implement ABI version 1.
    pub fn load_plugin(&mut self, path: impl AsRef<Path>) -> Result<(), Error> {
        let path = path.as_ref();
        let library = unsafe { Library::new(path) }
            .map_err(|error| Error::other(format!("loading {}: {error}", path.display())))?;
        let mut registration = Registration::default();
        {
            let entry: Symbol<'_, PluginEntryV1> = unsafe {
                library.get(PLUGIN_ENTRY_SYMBOL).map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "{} does not export requin_plugin_init_v1: {error}",
                            path.display()
                        ),
                    )
                })?
            };
            let host = PluginHostV1 {
                abi_version: PLUGIN_ABI_VERSION,
                context: (&mut registration as *mut Registration).cast(),
                register_application_decoder: register_decoder,
            };
            if !unsafe { entry(&host) } {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("{} rejected plugin ABI version 1", path.display()),
                ));
            }
        }

        if registration.invalid_registration || registration.decoders.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{} registered no valid application decoders",
                    path.display()
                ),
            ));
        }
        if registration.decoders.iter().any(|decoder| {
            self.plugin_names
                .iter()
                .any(|existing| existing == &decoder.name)
        }) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "{} registers a duplicate plugin decoder name",
                    path.display()
                ),
            ));
        }

        self.plugin_names.extend(
            registration
                .decoders
                .iter()
                .map(|decoder| decoder.name.clone()),
        );
        self.application_decoders
            .extend(registration.decoders.into_iter().map(|decoder| {
                Box::new(PluginApplicationDecoder {
                    name: decoder.name,
                    decode: decoder.decode,
                }) as Box<dyn ApplicationDecoder>
            }));
        self.plugin_libraries.push(library);
        Ok(())
    }

    pub fn load_plugins_from_dir(&mut self, directory: impl AsRef<Path>) -> Result<usize, Error> {
        let directory = directory.as_ref();
        let mut paths = fs::read_dir(directory)
            .map_err(|error| Error::other(format!("reading {}: {error}", directory.display())))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        let mut loaded = 0;
        for path in paths {
            if !is_dynamic_library(&path) {
                continue;
            }
            self.load_plugin(&path)?;
            loaded += 1;
        }
        Ok(loaded)
    }
}

unsafe extern "C" fn register_decoder(
    context: *mut c_void,
    name: *const u8,
    name_len: usize,
    decode: PluginDecodeFn,
) -> bool {
    if context.is_null() {
        return false;
    }
    let Some(name) = (unsafe { input_slice(name, name_len) }) else {
        return false;
    };
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    let registration = unsafe { &mut *context.cast::<Registration>() };
    if registration
        .decoders
        .iter()
        .any(|decoder| decoder.name == name)
    {
        registration.invalid_registration = true;
        return false;
    }
    registration.decoders.push(RegisteredDecoder {
        name: name.to_owned(),
        decode,
    });
    true
}

unsafe extern "C" fn emit_field(
    context: *mut c_void,
    field_name: *const u8,
    field_name_len: usize,
    value: *const u8,
    value_len: usize,
    offset: usize,
    length: usize,
) -> bool {
    if context.is_null() {
        return false;
    }
    let Some(field_name) = (unsafe { input_slice(field_name, field_name_len) }) else {
        return false;
    };
    let Some(value) = (unsafe { input_slice(value, value_len) }) else {
        return false;
    };
    let context = unsafe { &mut *context.cast::<EmitContext>() };
    if offset > context.packet_len || length > context.packet_len - offset {
        return false;
    }
    let field_name = String::from_utf8_lossy(field_name).into_owned();
    let value = String::from_utf8_lossy(value).into_owned();
    context
        .fields
        .push(Field::new(field_name, value).at(offset, length));
    true
}

unsafe fn input_slice<'a>(pointer: *const u8, length: usize) -> Option<&'a [u8]> {
    if pointer.is_null() {
        return (length == 0).then_some(&[]);
    }
    Some(unsafe { slice::from_raw_parts(pointer, length) })
}

#[cfg(target_os = "windows")]
fn is_dynamic_library(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
}

#[cfg(target_os = "macos")]
fn is_dynamic_library(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dylib"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn is_dynamic_library(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "so")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_fields_are_copied_and_bounds_checked() {
        let mut context = EmitContext {
            fields: Vec::new(),
            packet_len: 12,
        };
        let field = b"Marker";
        let value = b"decoded";
        assert!(unsafe {
            emit_field(
                (&mut context as *mut EmitContext).cast(),
                field.as_ptr(),
                field.len(),
                value.as_ptr(),
                value.len(),
                4,
                2,
            )
        });
        assert!(!unsafe {
            emit_field(
                (&mut context as *mut EmitContext).cast(),
                field.as_ptr(),
                field.len(),
                value.as_ptr(),
                value.len(),
                11,
                2,
            )
        });
        assert_eq!(context.fields[0].name, "Marker");
        assert_eq!(context.fields[0].value.to_string(), "decoded");
    }
}
