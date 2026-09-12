use std::{
    ffi::{CStr, CString, c_char},
    ptr,
};

use crate::{Device, EnigmaError, KeyType, KeyUsage, protocol::KeyListFilter};

const ENIGMA_OK: i32 = 0x00;
const ENIGMA_INVALID_ARG: i32 = 0x01;
const ENIGMA_DEVICE_NOT_FOUND: i32 = 0x02;
const ENIGMA_MULTIPLE_DEVICES: i32 = 0x03;
const ENIGMA_INCOMPATIBLE_DEVICE: i32 = 0x04;
const ENIGMA_USB_ERROR: i32 = 0x05;
const ENIGMA_PROTOCOL_ERROR: i32 = 0x06;
const ENIGMA_DEVICE_ERROR: i32 = 0x07;
const ENIGMA_INTERNAL_ERROR: i32 = 0x08;
const ENIGMA_MALFORMED_OUTPUT: i32 = 0x09;

#[derive(Debug)]
#[repr(C)]
pub struct EnigmaErrorInfo {
    pub code: i32,
    pub device_code: u32,
    pub message: [c_char; 256],
}

#[repr(C)]
pub struct EnigmaStatusInfo {
    pub token_state: u32,
    pub session_state: u32,
}

#[repr(C)]
pub struct EnigmaKeyMeta {
    pub key_id: u32,
    pub key_type: u32,
    pub key_usage: u32,
    pub key_size: u16,
    pub key_label: *const c_char,
    pub key_created_at: u32,
}

#[repr(C)]
pub struct EnigmaKeyList {
    pub count: u32,
    pub keys: *const EnigmaKeyMeta,
}

#[repr(C)]
struct OwnedKeyList {
    view: EnigmaKeyList,
    entries: Box<[EnigmaKeyMeta]>,
    labels: Vec<CString>,
}

#[derive(Debug)]
pub struct EnigmaDevice {
    device: crate::Device,
}

impl EnigmaErrorInfo {
    fn empty() -> Self {
        Self {
            code: 0,
            device_code: 0,
            message: [0; 256],
        }
    }

    fn from_error(error: &crate::EnigmaError) -> EnigmaErrorInfo {
        let mut info = Self::empty();

        info.code = match error {
            crate::EnigmaError::DeviceNotFound => ENIGMA_DEVICE_NOT_FOUND,
            crate::EnigmaError::MultipleDevicesFound => ENIGMA_MULTIPLE_DEVICES,
            crate::EnigmaError::MissingInterface {
                interface: _,
                alternate: _,
            } => ENIGMA_INCOMPATIBLE_DEVICE,
            crate::EnigmaError::MissingBulkEndpoint(_) => ENIGMA_INCOMPATIBLE_DEVICE,
            crate::EnigmaError::Usb(_) => ENIGMA_USB_ERROR,
            crate::EnigmaError::Protocol(_) => ENIGMA_PROTOCOL_ERROR,
            crate::EnigmaError::Device(_) => ENIGMA_DEVICE_ERROR,
            crate::EnigmaError::InvalidArgument => ENIGMA_INVALID_ARG,
            crate::EnigmaError::MalformedOutput => ENIGMA_MALFORMED_OUTPUT,
        };

        info.device_code = match error {
            crate::EnigmaError::Device(device_error) => device_error.code as u32,
            _ => 0,
        };

        let message = error.to_string().replace('\0', "\\0");
        let mut length = message.len().min(info.message.len() - 1);
        while !message.is_char_boundary(length) {
            length -= 1;
        }

        for (destination, byte) in info.message[..length]
            .iter_mut()
            .zip(message.as_bytes()[..length].iter())
        {
            *destination = *byte as c_char;
        }

        info
    }
}

/// # Safety
/// `out_device`, when non-null, must point to aligned, writable storage
/// for one device pointer. `out_error`, when non-null, must point to
/// aligned, writable storage for one `EnigmaErrorInfo`.
/// These regions must not overlap or be accessed concurrently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_open(
    out_device: *mut *mut EnigmaDevice,
    out_error: *mut EnigmaErrorInfo,
) -> i32 {
    if out_device.is_null() {
        if !out_error.is_null() {
            let mut error = EnigmaErrorInfo::empty();
            error.code = ENIGMA_INVALID_ARG;
            unsafe {
                out_error.write(error);
            }
        }
        return ENIGMA_INVALID_ARG;
    }

    unsafe {
        out_device.write(ptr::null_mut());
    }

    let outcome = std::panic::catch_unwind(|| {
        Device::open()
            .map(|device| Box::new(EnigmaDevice { device }))
            .map_err(|error| EnigmaErrorInfo::from_error(&error))
    });

    match outcome {
        Ok(Ok(boxed)) => {
            let pointer = Box::into_raw(boxed);
            unsafe {
                out_device.write(pointer);
                if !out_error.is_null() {
                    out_error.write(EnigmaErrorInfo::empty());
                }
            }
        }
        Ok(Err(error)) => {
            let code = error.code;
            if !out_error.is_null() {
                unsafe {
                    out_error.write(error);
                }
            }
            return code;
        }
        Err(panic) => {
            if !out_error.is_null() {
                let mut error = EnigmaErrorInfo::empty();
                error.code = ENIGMA_INTERNAL_ERROR;
                unsafe {
                    out_error.write(error);
                }
            }
            std::mem::forget(panic);
            return ENIGMA_INTERNAL_ERROR;
        }
    }

    ENIGMA_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_status(
    in_device: *mut EnigmaDevice,
    out_status: *mut EnigmaStatusInfo,
    out_error: *mut EnigmaErrorInfo,
) -> i32 {
    if in_device.is_null() || out_status.is_null() {
        if !out_error.is_null() {
            let mut err = EnigmaErrorInfo::empty();
            err.code = ENIGMA_INVALID_ARG;
            unsafe {
                out_error.write(err);
            }
        }
        return ENIGMA_INVALID_ARG;
    }

    let outcome = std::panic::catch_unwind(|| {
        let device = unsafe { &mut *in_device };

        device
            .device
            .status()
            .map(|status| EnigmaStatusInfo {
                token_state: status.token as u32,
                session_state: status.session as u32,
            })
            .map_err(|err| EnigmaErrorInfo::from_error(&err))
    });

    match outcome {
        Ok(Ok(status)) => unsafe {
            out_status.write(status);
            if !out_error.is_null() {
                out_error.write(EnigmaErrorInfo::empty());
            }
        },
        Ok(Err(err)) => {
            let code = err.code;
            if !out_error.is_null() {
                unsafe {
                    out_error.write(err);
                }
            }
            return code;
        }
        Err(panic) => {
            if !out_error.is_null() {
                let mut err = EnigmaErrorInfo::empty();
                err.code = ENIGMA_INTERNAL_ERROR;
                unsafe {
                    out_error.write(err);
                }
            }
            std::mem::forget(panic);
            return ENIGMA_INTERNAL_ERROR;
        }
    }

    ENIGMA_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_authenticate(
    in_device: *mut EnigmaDevice,
    in_pin: *const c_char,
    out_error: *mut EnigmaErrorInfo,
) -> i32 {
    if in_device.is_null() || in_pin.is_null() {
        if !out_error.is_null() {
            let mut err = EnigmaErrorInfo::empty();
            err.code = ENIGMA_INVALID_ARG;
            unsafe {
                out_error.write(err);
            }
        }
        return ENIGMA_INVALID_ARG;
    }

    let outcome = std::panic::catch_unwind(|| {
        let device = unsafe { &mut *in_device };
        let c_pin = unsafe { CStr::from_ptr(in_pin) };
        let pin = c_pin
            .to_str()
            .map_err(|_| EnigmaErrorInfo::from_error(&EnigmaError::InvalidArgument))?;

        device
            .device
            .authenticate(pin)
            .map_err(|err| EnigmaErrorInfo::from_error(&err))
    });

    match outcome {
        Ok(Ok(_)) => {
            if !out_error.is_null() {
                unsafe {
                    out_error.write(EnigmaErrorInfo::empty());
                }
            }
            ENIGMA_OK
        }
        Ok(Err(err)) => {
            let code = err.code;
            if !out_error.is_null() {
                unsafe {
                    out_error.write(err);
                }
            }
            return code;
        }
        Err(panic) => {
            if !out_error.is_null() {
                let mut err = EnigmaErrorInfo::empty();
                err.code = ENIGMA_INTERNAL_ERROR;
                unsafe {
                    out_error.write(err);
                }
            }
            std::mem::forget(panic);
            return ENIGMA_INTERNAL_ERROR;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_lock(
    in_device: *mut EnigmaDevice,
    out_error: *mut EnigmaErrorInfo,
) -> i32 {
    if in_device.is_null() {
        if !out_error.is_null() {
            let mut err = EnigmaErrorInfo::empty();
            err.code = ENIGMA_INVALID_ARG;
            unsafe {
                out_error.write(err);
            }
        }
        return ENIGMA_INVALID_ARG;
    }

    let outcome = std::panic::catch_unwind(|| {
        let device = unsafe { &mut *in_device };

        device
            .device
            .lock()
            .map_err(|err| EnigmaErrorInfo::from_error(&err))
    });

    match outcome {
        Ok(Ok(_)) => {
            if !out_error.is_null() {
                unsafe {
                    out_error.write(EnigmaErrorInfo::empty());
                }
            }
            ENIGMA_OK
        }
        Ok(Err(err)) => {
            let code = err.code;
            if !out_error.is_null() {
                unsafe {
                    out_error.write(err);
                }
            }
            code
        }
        Err(panic) => {
            if !out_error.is_null() {
                let mut err = EnigmaErrorInfo::empty();
                err.code = ENIGMA_INTERNAL_ERROR;
                unsafe {
                    out_error.write(err);
                }
            }
            std::mem::forget(panic);
            return ENIGMA_INTERNAL_ERROR;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_list_keys(
    in_device: *mut EnigmaDevice,
    in_filter_type: *const u32,
    in_filter_usage: *const u32,
    in_filter_label: *const c_char,
    in_filter_key_id: *const u32,
    out_list: *mut *const EnigmaKeyList,
    out_error: *mut EnigmaErrorInfo,
) -> i32 {
    if in_device.is_null() || out_list.is_null() {
        if !out_error.is_null() {
            let mut err = EnigmaErrorInfo::empty();
            err.code = ENIGMA_INVALID_ARG;
            unsafe {
                out_error.write(err);
            }
        }
        return ENIGMA_INVALID_ARG;
    }

    unsafe {
        out_list.write(std::ptr::null());
    }

    let outcome = std::panic::catch_unwind(|| {
        let key_type = unsafe { in_filter_type.as_ref() }
            .copied()
            .map(KeyType::try_from)
            .transpose()
            .map_err(|_| EnigmaErrorInfo::from_error(&EnigmaError::InvalidArgument))?;

        let key_usage = unsafe { in_filter_usage.as_ref() }
            .copied()
            .map(KeyUsage::try_from)
            .transpose()
            .map_err(|_| EnigmaErrorInfo::from_error(&EnigmaError::InvalidArgument))?;

        let key_label = if in_filter_label.is_null() {
            None
        } else {
            let label = unsafe { CStr::from_ptr(in_filter_label) }
                .to_str()
                .map_err(|_| EnigmaErrorInfo::from_error(&EnigmaError::InvalidArgument))?;
            Some(label)
        };

        let key_id = unsafe { in_filter_key_id.as_ref() }.copied();

        let filter = KeyListFilter {
            key_type,
            key_usage,
            key_label,
            key_id,
        };

        let device = unsafe { &mut *in_device };

        let result = device
            .device
            .list_keys(filter)
            .map_err(|err| EnigmaErrorInfo::from_error(&err))?;

        let mut labels = Vec::new();
        let mut entries = Vec::new();

        for key in result.keys {
            let label = CString::new(key.label)
                .map_err(|_| EnigmaErrorInfo::from_error(&EnigmaError::MalformedOutput))?;
            let label_ptr = label.as_ptr();

            labels.push(label);
            entries.push(EnigmaKeyMeta {
                key_id: key.id,
                key_type: key.key_type as u32,
                key_usage: key.key_usage as u32,
                key_size: key.size,
                key_label: label_ptr,
                key_created_at: key.created_at,
            });
        }

        let entries = entries.into_boxed_slice();
        let count = u32::try_from(entries.len())
            .map_err(|_| EnigmaErrorInfo::from_error(&EnigmaError::MalformedOutput))?;

        let keys = if entries.is_empty() {
            ptr::null()
        } else {
            entries.as_ptr()
        };

        let owned = Box::new(OwnedKeyList {
            view: EnigmaKeyList { count, keys },
            entries,
            labels,
        });

        Ok::<Box<OwnedKeyList>, EnigmaErrorInfo>(owned)
    });

    match outcome {
        Ok(Ok(result)) => {
            let pointer = Box::into_raw(result).cast::<EnigmaKeyList>();

            unsafe {
                out_list.write(pointer);
                if !out_error.is_null() {
                    out_error.write(EnigmaErrorInfo::empty());
                }
            }

            ENIGMA_OK
        }
        Ok(Err(err)) => {
            let code = err.code;
            if !out_error.is_null() {
                unsafe {
                    out_error.write(err);
                }
            }
            code
        }
        Err(panic) => {
            if !out_error.is_null() {
                let mut err = EnigmaErrorInfo::empty();
                err.code = ENIGMA_INTERNAL_ERROR;
                unsafe {
                    out_error.write(err);
                }
            }
            std::mem::forget(panic);
            return ENIGMA_INTERNAL_ERROR;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_key_list_free(in_list: *const EnigmaKeyList) {
    if in_list.is_null() {
        return;
    }

    let outcome = std::panic::catch_unwind(|| unsafe {
        drop(Box::from_raw(in_list.cast_mut().cast::<OwnedKeyList>()));
    });

    if let Err(panic) = outcome {
        std::mem::forget(panic);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn enigma_close(
    in_device: *mut EnigmaDevice,
    out_error: *mut EnigmaErrorInfo,
) -> i32 {
    if in_device.is_null() {
        if !out_error.is_null() {
            unsafe {
                out_error.write(EnigmaErrorInfo::empty());
            }
        }
        return ENIGMA_OK;
    }

    let outcome = std::panic::catch_unwind(|| {
        let mut boxed = unsafe { Box::from_raw(in_device) };

        boxed
            .device
            .close()
            .map_err(|err| EnigmaErrorInfo::from_error(&err))
    });

    match outcome {
        Ok(Ok(())) => {
            if !out_error.is_null() {
                unsafe {
                    out_error.write(EnigmaErrorInfo::empty());
                }
            }
            return ENIGMA_OK;
        }
        Ok(Err(err)) => {
            let code = err.code;
            if !out_error.is_null() {
                unsafe { out_error.write(err) }
            }
            return code;
        }
        Err(panic) => {
            if !out_error.is_null() {
                let mut err = EnigmaErrorInfo::empty();
                err.code = ENIGMA_INTERNAL_ERROR;
                unsafe { out_error.write(err) }
            }
            std::mem::forget(panic);
            return ENIGMA_INTERNAL_ERROR;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;
    use crate::{DeviceError, DeviceErrorCode, EnigmaError};

    #[test]
    fn list_free_accepts_null() {
        unsafe { enigma_key_list_free(ptr::null()) };
    }

    #[test]
    fn list_owner_round_trip_preserves_entries_and_labels() {
        // Construct a fixture without USB. This exercises the public view and
        // actual free function, not the conversion embedded in enigma_list_keys.
        for count in [0usize, 1, 64] {
            let labels: Vec<CString> = (0..count)
                .map(|i| CString::new(format!("test-é-{i}")).unwrap())
                .collect();
            let entries: Box<[EnigmaKeyMeta]> = labels
                .iter()
                .enumerate()
                .map(|(i, label)| EnigmaKeyMeta {
                    key_id: i as u32,
                    key_type: 1,
                    key_usage: 1,
                    key_size: 256,
                    key_label: label.as_ptr(),
                    key_created_at: 0x01020304,
                })
                .collect();
            let keys = if count == 0 {
                ptr::null()
            } else {
                entries.as_ptr()
            };
            let owner = Box::new(OwnedKeyList {
                view: EnigmaKeyList {
                    count: count as u32,
                    keys,
                },
                entries,
                labels,
            });
            assert_eq!(
                (&*owner as *const OwnedKeyList).cast::<EnigmaKeyList>(),
                &owner.view as *const EnigmaKeyList,
            );
            let raw = Box::into_raw(owner).cast::<EnigmaKeyList>();
            unsafe {
                assert_eq!((*raw).count, count as u32);
                if count == 0 {
                    assert!((*raw).keys.is_null());
                }
                for i in 0..count {
                    let entry = &*(*raw).keys.add(i);
                    assert_eq!(entry.key_id, i as u32);
                    assert_eq!(
                        CStr::from_ptr(entry.key_label).to_str().unwrap(),
                        format!("test-é-{i}")
                    );
                }
                enigma_key_list_free(raw);
            }
        }
    }

    #[test]
    fn list_null_device_reports_invalid_argument_without_usb() {
        let mut output = ptr::null();
        let mut error = EnigmaErrorInfo::empty();
        let code = unsafe {
            enigma_list_keys(
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                &mut output,
                &mut error,
            )
        };
        assert_eq!(code, ENIGMA_INVALID_ARG);
        assert_eq!(error.code, ENIGMA_INVALID_ARG);
        assert!(output.is_null());
    }

    #[test]
    fn it_converts_a_device_error() {
        let device_error: DeviceError = DeviceError {
            code: DeviceErrorCode::AuthFailed,
            message: "error message".to_owned(),
        };
        let lib_error = EnigmaError::Device(device_error);
        let info = EnigmaErrorInfo::from_error(&lib_error);

        let bytes: Vec<u8> = info.message.iter().map(|&b| b as u8).collect();
        let message = CStr::from_bytes_until_nul(&bytes)
            .expect("message must be NUL-terminated")
            .to_str()
            .expect("message must be valid UTF-8");

        assert_eq!(info.code, ENIGMA_DEVICE_ERROR);
        assert_eq!(info.device_code, 0x02);
        assert_eq!(
            message,
            "Device error: Authentication failed: error message"
        );
    }

    #[test]
    fn it_converts_an_error() {
        let lib_error = EnigmaError::DeviceNotFound;
        let info = EnigmaErrorInfo::from_error(&lib_error);

        let bytes: Vec<u8> = info.message.iter().map(|&b| b as u8).collect();
        let message = CStr::from_bytes_until_nul(&bytes)
            .expect("message must be NUL-terminated")
            .to_str()
            .expect("message must be valid UTF-8");

        assert_eq!(info.code, ENIGMA_DEVICE_NOT_FOUND);
        assert_eq!(info.device_code, 0);
        assert_eq!(message, "Device not found");
    }
}
