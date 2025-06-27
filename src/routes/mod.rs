use axum::Router;
use sqlx::MySqlPool;

mod auth;
mod hello;

use auth::create_auth_router;
use hello::create_hello_router;

pub fn create_router(pool: MySqlPool) -> Router {
    let auth_router = create_auth_router(pool);
    let hello_router = create_hello_router();

    Router::new()
        .merge(hello_router)
        .nest("/auth", auth_router)
} 