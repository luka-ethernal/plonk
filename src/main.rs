use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
use rand_core::OsRng;
use std::fs::File;
use std::io::prelude::*;

fn main() -> std::io::Result<()> {
    let public_parameters =
        PublicParameters::setup(2usize.pow(17), &mut OsRng).unwrap();

    let mut file = File::create("setup2to17")?;
    file.write_all(&public_parameters.to_raw_var_bytes())?;

    Ok(())
}
