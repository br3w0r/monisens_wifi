use std::ffi::{c_char, CStr};

pub fn str_from_c_char(raw: *const c_char) -> String {
    let cstr = unsafe { CStr::from_ptr(raw) };

    String::from_utf8_lossy(cstr.to_bytes()).to_string()
}

pub fn as_string(raw: *const c_char) -> Option<String> {
    Some(str_from_c_char(raw))
}
