use async_compression::stream::GzipDecoder;
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
    let resp = http_stream("https://downloads.majestic.com/majestic_million.csv").await?;

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
    let resp = http_stream("https://staticcdn.duckduckgo.com/https/smarter_encryption_latest.tgz").await?;
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
    Box::new(GzipDecoder::new(inflow))
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

    println!("Downoading and parsing Majestic Million list...");
    let mm_list = fetch_mm_list().await.unwrap();
    println!("Downoading and parsing Smarter Encryption list...");
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
