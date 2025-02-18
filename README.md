```rust
use http_reader::HttpReader;

fn main() -> std::io::Result<()> {

    //
    //  cargo add zip
    //
    let reader = HttpReader::new("http://192.168.0.102:9212/upgrade.zip")?;
    let mut archive = zip::read::ZipArchive::new(reader)?;
    let mut file = archive.by_name("rootfs.emmc")?;
    let mut fd = std::fs::File::create("./rootfs.emmc")?;
    std::io::copy(&mut file, &mut fd)?;

    //
    //  cargo add sevenz-rust
    //
    let reader = HttpReader::new_with_bufsize("http://192.168.0.143:9212/test.7z", 12*1024*1024)?;
    // sevenz_rust::decompress_with_extract_fn(reader, "output", sevenz_rust::default_entry_extract_fn).expect("complete");
    sevenz_rust::decompress(reader, "output").expect("complete");

    Ok(())
    }
```