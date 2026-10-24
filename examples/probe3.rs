use std::time::Duration;
#[tokio::main]
async fn main() {
    let key = std::env::var("NEBIUS_API_KEY").unwrap_or_default();
    let body = serde_json::json!({"model":"nvidia/Nemotron-3_5-Lightning","messages":[{"role":"user","content":"say ok"}],"max_tokens":4,"temperature":0.0,"seed":42});
    for i in 0..3 {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(3))
            .build().unwrap();
        let t = std::time::Instant::now();
        match client.post("https://api.tokenfactory.nebius.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", key))
            .json(&body).send().await {
            Ok(r) => {
                let st = r.status();
                let b = r.text().await.unwrap_or_default();
                println!("#{} POST {} in {:?} len={} first120={}", i, st, t.elapsed(), b.len(), &b[..b.len().min(120)]);
            }
            Err(e) => println!("#{} POST ERR in {:?} :: {}", i, t.elapsed(), e),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
