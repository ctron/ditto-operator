use kube::CustomResourceExt;
use std::fs::File;
use std::io::{stdout, BufWriter, Write};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();

    let mut output: BufWriter<Box<dyn Write>> = BufWriter::new(match args.get(1) {
        Some(name) => {
            println!("Writing output to: {}", name);
            Box::new(File::create(name)?)
        }
        None => Box::new(stdout()),
    });

    write!(
        &mut output,
        "{}",
        serde_yaml::to_string(&ditto_operator::crd::Ditto::crd()).unwrap()
    )?;

    Ok(())
}
