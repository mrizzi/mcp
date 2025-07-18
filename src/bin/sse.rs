use rmcp::transport::sse_server::SseServer;
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    {self},
};
mod common;
use common::trustify::Trustify;

const BIND_ADDRESS: &str = "[::]:8081";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "debug".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let ct = SseServer::serve(BIND_ADDRESS.parse()?)
        .await?
        .with_service(Trustify::new);

    tokio::signal::ctrl_c().await?;
    ct.cancel();
    Ok(())
}
