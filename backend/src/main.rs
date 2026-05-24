mod auth;
mod middleware;
mod pull;
mod push;

use axum::{
    Router,
    extract::State,
    routing::{delete, post},
};
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

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let redis_client = redis::Client::open(redis_url).unwrap();
    let redis = redis_client
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let server_setup = get_server_setup();
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let state = AppState {
        pool,
        redis,
        server_setup,
        jwt_secret,
    };

    let protected_routes = Router::new()
        .route("/api/v1/account", delete(delete_account))
        .route("/api/v1/sync/push", post(crate::push::sync_push_handler))
        .route("/api/v1/sync/pull", post(crate::pull::sync_pull_handler))
        .layer(axum::middleware::from_fn(auth_middleware));

    let app = Router::new()
        .route(
            "/api/v1/auth/login/start",
            post(crate::auth::login::login_start),
        )
        .route(
            "/api/v1/auth/login/finish",
            post(crate::auth::login::login_finish),
        )
        .route(
            "/api/v1/auth/register/start",
            post(crate::auth::register::register_start),
        )
        .route(
            "/api/v1/auth/register/finish",
            post(crate::auth::register::register_finish),
        )
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state));

    tracing::info!("Starting server on port 3000");

    let listener = TcpListener::bind(("0.0.0.0", 3000)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn delete_account(State(_app): State<AppStateRef>) {}

async fn auth_middleware(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Hardcode a UUID that exists in your 'users' table
    let mock_user_id = uuid::Uuid::parse_str("ce7809b9-fe22-4ed6-baf0-b2dbbc654be0").unwrap();
    req.extensions_mut().insert(mock_user_id);

    next.run(req).await
}

fn get_server_setup() -> ServerSetup<DefaultCipherSuite> {
    if std::fs::exists(Path::new(".state.safe")).unwrap() {
        let mut file = File::open(".state.safe").unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        let setup = ServerSetup::deserialize(&BASE64_STANDARD.decode(content).unwrap()).unwrap();
        setup
    } else {
        let setup = ServerSetup::new(&mut OsRng);
        let mut file = File::create(".state.safe").unwrap();
        let content = BASE64_STANDARD.encode(setup.serialize());
        file.write_all(&content.as_bytes()).unwrap();
        setup
    }
}
