#[tokio::main]
async fn main() -> std::io::Result<()> {
    unified_server::run().await
}
