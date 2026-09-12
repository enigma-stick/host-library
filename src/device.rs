use crate::protocol::{
    AuthenticateRequest, EmptyRequest, KmCommand, KmDecode, KmEncode, KmFrameHeader,
    usb_decode_response, usb_encode_request,
};
use crate::{
    EnigmaError::{self, Usb},
    Status,
};

const VENDOR_ID: u16 = 0x303A;
const PRODUCT_ID: u16 = 0x1001;
const CONFIGURATION: u8 = 1;
const CONTROL_INTERFACE: u8 = 0;
const DATA_INTERFACE: u8 = 1;
const ALTERNATE_SETTING: u8 = 0;
const OUT_ENDPOINT: u8 = 0x01;
const IN_ENDPOINT: u8 = 0x81;

#[derive(Debug)]
pub struct Device {
    handle: rusb::DeviceHandle<rusb::GlobalContext>,
    received: Vec<u8>,
    timeout: std::time::Duration,
    claimed: bool,
    restored: bool,
}

impl Device {
    pub fn open() -> Result<Self, EnigmaError> {
        let devices = rusb::devices()?;
        let target_devices: Vec<rusb::Device<rusb::GlobalContext>> = devices
            .iter()
            .filter(|dev| {
                dev.device_descriptor()
                    .map(|d| d.vendor_id() == VENDOR_ID && d.product_id() == PRODUCT_ID)
                    .unwrap_or(false)
            })
            .collect();
        if target_devices.is_empty() {
            return Err(EnigmaError::DeviceNotFound);
        }

        if target_devices.len() > 1 {
            return Err(EnigmaError::MultipleDevicesFound);
        }

        let device = &target_devices[0];
        let config = device.active_config_descriptor()?;

        if config.number() != CONFIGURATION {
            return Err(EnigmaError::DeviceNotFound);
        }

        let interface = config
            .interfaces()
            .find(|interface| interface.number() == DATA_INTERFACE)
            .ok_or(EnigmaError::MissingInterface {
                interface: DATA_INTERFACE,
                alternate: ALTERNATE_SETTING,
            })?;

        let descriptor = interface
            .descriptors()
            .find(|desc| desc.setting_number() == ALTERNATE_SETTING)
            .ok_or(EnigmaError::MissingInterface {
                interface: DATA_INTERFACE,
                alternate: ALTERNATE_SETTING,
            })?;

        for address in [OUT_ENDPOINT, IN_ENDPOINT] {
            let found = descriptor.endpoint_descriptors().any(|endpoint| {
                endpoint.address() == address
                    && endpoint.transfer_type() == rusb::TransferType::Bulk
            });

            if !found {
                return Err(EnigmaError::MissingBulkEndpoint(address));
            }
        }

        let handle = device.open()?;
        let had_kernel_driver = handle.kernel_driver_active(DATA_INTERFACE)?;

        handle.set_auto_detach_kernel_driver(true)?;
        handle.claim_interface(DATA_INTERFACE)?;

        Ok(Self {
            handle,
            received: vec![],
            timeout: std::time::Duration::new(10, 0),
            claimed: true,
            restored: !had_kernel_driver,
        })
    }

    fn transact<Request, Response>(
        &mut self,
        command: KmCommand,
        request: Request,
    ) -> Result<Response, EnigmaError>
    where
        Request: KmEncode,
        Response: KmDecode<Response>,
    {
        if !self.claimed {
            return Err(Usb(rusb::Error::Busy));
        }

        let request_bytes = usb_encode_request(command, request);
        let n_write = self
            .handle
            .write_bulk(OUT_ENDPOINT, &request_bytes, self.timeout)?;

        if n_write < request_bytes.len() {
            return Err(EnigmaError::Usb(rusb::Error::Interrupted));
        }

        let mut chunk = [0u8; 64];

        loop {
            let magic_position = self
                .received
                .windows(4)
                .position(|window| window == b"KMGR");
            match magic_position {
                Some(start) => {
                    self.received.drain(..start);
                }
                None => {
                    let discard = self.received.len().saturating_sub(3);
                    self.received.drain(..discard);
                }
            }

            if self.received.len() >= 8 {
                let header = KmFrameHeader::decode(&self.received[..8])?;
                let frame_len = 8 + usize::from(header.length);

                if self.received.len() >= frame_len {
                    let result =
                        usb_decode_response::<Response>(command, &self.received[..frame_len]);
                    self.received.drain(..frame_len);
                    return result;
                }
            }
            let n_read = self
                .handle
                .read_bulk(IN_ENDPOINT, &mut chunk, self.timeout)?;
            self.received.extend_from_slice(&chunk[..n_read]);
        }
    }

    pub fn status(&mut self) -> Result<Status, EnigmaError> {
        self.transact(KmCommand::Status, EmptyRequest {})
    }

    pub fn authenticate(&mut self, pin: &str) -> Result<(), EnigmaError> {
        if pin.is_empty() || pin.as_bytes().contains(&0) || pin.len() > 1020 {
            return Err(EnigmaError::InvalidArgument);
        }

        let request = AuthenticateRequest { pin };
        self.transact(KmCommand::Authenticate, request)
    }

    pub fn close(&mut self) -> Result<(), EnigmaError> {
        if self.claimed {
            self.handle.release_interface(DATA_INTERFACE)?;
            self.claimed = false;
        }

        if !self.restored {
            self.handle.attach_kernel_driver(CONTROL_INTERFACE)?;
            self.restored = true;
        }

        Ok(())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
