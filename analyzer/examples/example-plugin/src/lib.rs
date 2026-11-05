use std::ffi::c_void;

use analyzer::proto::{PLUGIN_ABI_VERSION, PluginHostV1};

unsafe extern "C" fn decode_xproto(
    packet: *const u8,
    packet_len: usize,
    _ip_protocol: u8,
    _source_port: u16,
    _destination_port: u16,
    payload_offset: usize,
    context: *mut c_void,
    emit_field: analyzer::proto::PluginEmitFieldFn,
) -> bool {
    if packet.is_null() || packet_len < 6 {
        return false;
    }
    let packet = unsafe { std::slice::from_raw_parts(packet, packet_len) };
    if !packet.starts_with(b"XPROTO") {
        return false;
    }
    let field_name = b"Signature";
    let value = b"XPROTO";
    unsafe {
        emit_field(
            context,
            field_name.as_ptr(),
            field_name.len(),
            value.as_ptr(),
            value.len(),
            payload_offset,
            6,
        )
    }
}

unsafe extern "C" fn initialize(host: *const PluginHostV1) -> bool {
    let Some(host) = (unsafe { host.as_ref() }) else {
        return false;
    };
    if host.abi_version != PLUGIN_ABI_VERSION {
        return false;
    }
    let name = b"XPROTO";
    unsafe {
        (host.register_application_decoder)(
            host.context,
            name.as_ptr(),
            name.len(),
            decode_xproto,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn requin_plugin_init_v1(host: *const PluginHostV1) -> bool {
    unsafe { initialize(host) }
}
