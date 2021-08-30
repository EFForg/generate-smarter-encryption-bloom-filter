use async_tar::Archive;
use bloomfilter::Bloom;
use futures_util::{AsyncBufReadExt, StreamExt, TryStreamExt};
use futures_util::io::{AsyncRead, BufReader as AsyncBufReader};
use futures_util::stream::Stream;
use serde_json::{json, Value};
use ring::digest;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Error, ErrorKind, Write};
use std::collections::HashSet;

fn help_message_and_exit(program_name: &str, status_code: i32) -> String {
    println!("Usage: {} OUTFILE", program_name);
    std::process::exit(status_code);
}

fn create_file(file_name: &str, program_name: &str, file_summary: &str) -> File {
    let of = File::create(file_name);
    if let Err(ref e) = of {
        println!("Error creating {}: {}", e, file_summary);
        help_message_and_exit(program_name, 1);
    };
    of.unwrap()
}

fn create_bloom_filter(entries: HashSet<String>, items_count: usize, fp_rate: f64) -> Bloom<str> {
    let bitmap_size = Bloom::<()>::compute_bitmap_size(items_count, fp_rate);
    println!("Using a bitmap size of {} bytes, appropriate for a false positive rate of {}.", bitmap_size, fp_rate);
    let mut bf = Bloom::<str>::new(bitmap_size, items_count);
    for entry in entries.iter() {
        bf.set(entry);
    }
    bf
}

fn write_outfile(bf: &Bloom<str>, outfile: File) {
    let mut bw = BufWriter::new(outfile);
    bw.write_all(&bf.bitmap()).unwrap();
}

fn write_metadata(json_value: Value, mut metadata_file: File) {
    metadata_file.write_all(json_value.to_string().as_bytes()).unwrap();
}

type S = dyn Stream<Item = Result<bytes::Bytes, Error>> + Unpin;
async fn fetch_mm_list() -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    fetch_csv_list(http_stream("https://downloads.majestic.com/majestic_million.csv").await?).await
}

async fn fetch_csv_list(resp: Box<S>) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let mut reader = AsyncBufReader::new(resp.into_async_read());
    {
        let mut _header = String::new();
        reader.read_line(&mut _header).await?;
    }
    let lines = reader.lines().filter_map(|l| async {
        let entry = l.unwrap();
        let mut entry_vec = entry.split(",").collect::<Vec<&str>>();
        if entry_vec.len() > 2 {
            Some(String::from(entry_vec.remove(2)))
        } else {
            None
        }
    });
    let entries: HashSet<String> = lines.collect().await;
    Ok(entries)
}

async fn fetch_se_list_matches(mm_list: &HashSet<String>) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    fetch_tgz_list_matches(http_stream("https://staticcdn.duckduckgo.com/https/smarter_encryption_latest.tgz").await?, mm_list).await
}

async fn fetch_tgz_list_matches(resp: Box<S>, mm_list: &HashSet<String>) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let tar = decompress_stream(resp);
    let file = untarred_file_from_stream(tar, "smarter_encryption_latest/smarter_encryption.txt").await?.unwrap();

    let reader = AsyncBufReader::new(file);
    let lines = reader.lines().filter_map(|l| async {
        let entry = l.unwrap();
        if mm_list.contains(&entry) {
            Some(entry)
        } else {
            None
        }
    });
    let entries: HashSet<String> = lines.collect().await;
    Ok(entries)
}

async fn http_stream(url: &str) -> Result<Box<S>, Box<dyn std::error::Error>> {
    Ok(Box::new(reqwest::get(url)
        .await?
        .error_for_status()?
        .bytes_stream()
        .map(|result| result.map_err(|e| Error::new(ErrorKind::Other, e)))))
}

fn decompress_stream(inflow: Box<S>) -> Box<S> {
    Box::new(tokio_util::io::ReaderStream::new(
        async_compression::tokio::bufread::GzipDecoder::new(
            tokio_util::io::StreamReader::new(inflow)
        )
    ))
}

async fn untarred_file_from_stream(inflow: Box<S>, filename: &str) -> Result<Option<Box<dyn AsyncRead + Unpin>>, Box<dyn std::error::Error>> {
    let inflow = inflow.into_async_read();
    let ar = Archive::new(inflow);
    let mut entries = ar.entries()?.filter(|entry| {
        futures_util::future::ready(
            entry.is_ok() &&
            entry.as_ref().unwrap().path().is_ok() &&
            entry.as_ref().unwrap().path().unwrap().to_str() == Some(filename))
    });
    match entries.next().await {
        Some(Ok(entry)) => Ok(Some(Box::new(entry))),
        _ => Ok(None),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        help_message_and_exit(&args[0], 1);
    }

    let outfile = create_file(&args[1], &args[0], "OUTFILE");
    let metadata_file = create_file(&format!("{}.json", &args[1]), &args[0], "metadata file OUTFILE.json");

    println!("Downloading and parsing Majestic Million list...");
    let mm_list = fetch_mm_list().await.unwrap();
    println!("Downloading and parsing Smarter Encryption list...");
    let se_list_matches = fetch_se_list_matches(&mm_list).await.unwrap();
    
    let fp_rate = 0.0000001;
    let items_count = se_list_matches.len();
    println!("Found {} entries common in Majestic Million and Smarter Encryption lists.", items_count);

    let bf = create_bloom_filter(se_list_matches, items_count, fp_rate);

    println!("Writing bloom filter to file...");
    write_outfile(&bf, outfile);
    let sip_keys = bf.sip_keys();
    let json = json!({
        "sha256sum": hex::encode(digest::digest(&digest::SHA256, &bf.bitmap()).as_ref()),
        "bitmap_bits": bf.number_of_bits(),
        "k_num": bf.number_of_hash_functions(),
        "sip_keys": [
            [sip_keys[0].0.to_string(), sip_keys[0].1.to_string()],
            [sip_keys[1].0.to_string(), sip_keys[1].1.to_string()],
        ]
    });
    write_metadata(json, metadata_file);
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use mktemp::Temp;
    use std::fs::{self, File};
    use std::io::prelude::*;
    use super::*;

    fn create_bloom_mock() -> Bloom<str> {
        let mut entries = HashSet::new();
        entries.insert("A Dance With Dragons".to_string());
        entries.insert("To Kill a Mockingbird".to_string());
        entries.insert("The Odyssey".to_string());
        entries.insert("The Great Gatsby".to_string());
        let items_count = 4;
        let fp_rate = 0.001;

        create_bloom_filter(entries, items_count, fp_rate)
    }

    fn create_file_mock() -> (Temp, File, String) {
        let temp_dir = Temp::new_dir().unwrap();
        let mut temp_path_buf = temp_dir.to_path_buf();
        temp_path_buf.push("temp_file");
        let temp_file_str = temp_path_buf.to_str().unwrap();

        (temp_dir, create_file(temp_file_str, "test", "TESTFILE"), String::from(temp_file_str))
    }

    fn file_read(file: &str) -> Result<bytes::Bytes, Error> {
        let mut f = File::open(file)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        let file_bytes = bytes::Bytes::from(buffer);
        Ok(file_bytes)
    }

    fn file_stream(file: &str) -> Box<S> {
        Box::new(stream::iter(vec![file_read(file)]))
    }

    #[test]
    fn creates_file_successfully() {
        let (_t, _, temp_file_str) = create_file_mock();
        assert!(File::open(&temp_file_str).is_ok());
    }

    #[test]
    fn create_bloom_filter_succeeds() {
        let bf = create_bloom_mock();
        assert_eq!(bf.check("The Great Gatsby"), true);
    }

    #[test]
    fn write_outfile_succeeds() {
        let bf = create_bloom_mock();
        let (_t, temp_file, temp_file_str) = create_file_mock();
        write_outfile(&bf, temp_file);
        let metadata = fs::metadata(temp_file_str).unwrap();
        assert_eq!(metadata.len(), 8);
    }

    #[test]
    fn write_metadata_succeeds() {
        let (_t, temp_file, temp_file_str) = create_file_mock();
        let json = json!({
            "foo": 1,
            "bar": [true, "baz"]
        });
        write_metadata(json, temp_file);
        let contents = fs::read_to_string(temp_file_str).unwrap();
        assert_eq!(contents, "{\"bar\":[true,\"baz\"],\"foo\":1}");
    }

    #[tokio::test]
    async fn fetch_csv_list_succeeds() {
        let csv_file_stream = file_stream("test/m50.csv");
        let csv_list = fetch_csv_list(csv_file_stream).await.unwrap();
        assert!(csv_list.contains("en.wikipedia.org"));
    }


    #[tokio::test]
    async fn fetch_tgz_list_matches_succeeds() {
        let csv_file_stream = file_stream("test/m50.csv");
        let csv_list = fetch_csv_list(csv_file_stream).await.unwrap();

        let matches_file_stream = file_stream("test/se100.tgz");
        let matches = fetch_tgz_list_matches(matches_file_stream, &csv_list).await.unwrap();
        assert!(matches.contains("en.wikipedia.org"));
        assert!(!matches.contains("mozilla.org"));
    }

    #[tokio::test]
    async fn simple_reqwest_succeeds() {
        let example_resp = reqwest::get("https://www.example.com/")
            .await.unwrap()
            .error_for_status().unwrap()
            .text()
            .await.unwrap();
        assert!(example_resp.len() > 0);
    }
}
