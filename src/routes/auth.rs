use axum::{
    routing::post,
    Router,
};
use sqlx::MySqlPool;
use crate::auth::auth::{login_handler, signup_handler};

pub fn create_auth_router(pool: MySqlPool) -> Router {
    Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .with_state(pool)
} 