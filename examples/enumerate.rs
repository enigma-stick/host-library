use enigma::{Device, EnigmaError};

fn main() -> Result<(), EnigmaError> {
    let mut device = Device::open()?;

    let status = device.status();
    let cleanup = device.close();

    let status = status?;
    cleanup?;

    println!("{status:#?}");
    Ok(())
}
