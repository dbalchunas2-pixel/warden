use std::time::Duration;
#[tokio::main]
async fn main() {
    for url in ["https://www.rust-lang.org", "https://api.github.com", "https://api.tokenfactory.nebius.com/v1/models"] {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(3))
            .build().unwrap();
        let t = std::time::Instant::now();
        match client.get(url).header("User-Agent", "probe").send().await {
            Ok(r) => println!("{} -> {} in {:?}", url, r.status(), t.elapsed()),
            Err(e) => println!("{} -> ERR in {:?} :: {}", url, t.elapsed(), e),
        }
    }
}
