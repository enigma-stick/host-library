use std::{
    ffi::{CStr, c_char},
    ptr,
};

use crate::{Device, EnigmaError};

const ENIGMA_OK: i32 = 0x00;
const ENIGMA_INVALID_ARG: i32 = 0x01;
const ENIGMA_DEVICE_NOT_FOUND: i32 = 0x02;
const ENIGMA_MULTIPLE_DEVICES: i32 = 0x03;
const ENIGMA_INCOMPATIBLE_DEVICE: i32 = 0x04;
const ENIGMA_USB_ERROR: i32 = 0x05;
const ENIGMA_PROTOCOL_ERROR: i32 = 0x06;
const ENIGMA_DEVICE_ERROR: i32 = 0x07;
const ENIGMA_INTERNAL_ERROR: i32 = 0x08;

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
