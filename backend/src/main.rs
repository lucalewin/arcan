mod auth;
mod middleware;
mod pull;
mod push;

use axum::{Router, routing::post};
use base64::prelude::*;
use opaque_ke::{ServerSetup, rand::rngs::OsRng};
use redis::aio::MultiplexedConnection;
use shared::DefaultCipherSuite;
use sqlx::PgPool;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::Level;

struct AppState {
    pool: PgPool,
    redis: MultiplexedConnection,
    server_setup: ServerSetup<DefaultCipherSuite>,
    jwt_secret: String,
}

type AppStateRef = Arc<AppState>;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let pool = get_database_connection().await;
    let redis = get_redis_connection().await;
    let server_setup = get_server_setup();

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|e| {
        tracing::error!(%e, "JWT_SECRET must be set");
        std::process::exit(1);
    });

    let state = AppState {
        pool,
        redis,
        server_setup,
        jwt_secret,
    };

    let auth_routes = Router::new()
        .route("/salt", post(crate::auth::salt::get_salt))
        .route("/login/start", post(crate::auth::login::login_start))
        .route("/login/finish", post(crate::auth::login::login_finish))
        .route(
            "/register/start",
            post(crate::auth::register::register_start),
        )
        .route(
            "/register/finish",
            post(crate::auth::register::register_finish),
        );

    let sync_routes = Router::new()
        .route("/push", post(crate::push::sync_push_handler))
        .route("/pull", post(crate::pull::sync_pull_handler));

    let app = Router::new()
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/sync", sync_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state));

    tracing::info!("Starting server...");
    let listener = TcpListener::bind(("0.0.0.0", 3000)).await.unwrap();
    tracing::info!("Server listening on port 3000");

    axum::serve(listener, app).await.unwrap();
}

async fn get_database_connection() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|e| {
        tracing::error!(%e, "DATABASE_URL must be set");
        std::process::exit(1);
    });

    match PgPool::connect(&database_url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(%e, "Failed to connect to database");
            std::process::exit(1);
        }
    }
}

async fn get_redis_connection() -> MultiplexedConnection {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|e| {
        tracing::error!(%e, "REDIS_URL must be set");
        std::process::exit(1);
    });

    let redis_client = match redis::Client::open(redis_url) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "Failed to create Redis client");
            std::process::exit(1);
        }
    };

    match redis_client.get_multiplexed_async_connection().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(%e, "Failed to connect to Redis");
            std::process::exit(1);
        }
    }
}

fn get_server_setup() -> ServerSetup<DefaultCipherSuite> {
    std::fs::create_dir_all("./data").unwrap();
    if std::fs::exists(Path::new("./data/.state.safe")).unwrap() {
        let mut file = File::open("./data/.state.safe").unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        let setup = ServerSetup::deserialize(&BASE64_STANDARD.decode(content).unwrap()).unwrap();
        setup
    } else {
        let setup = ServerSetup::new(&mut OsRng);
        let mut file = File::create("./data/.state.safe").unwrap();
        let content = BASE64_STANDARD.encode(setup.serialize());
        file.write_all(&content.as_bytes()).unwrap();
        setup
    }
}
