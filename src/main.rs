mod db;
mod auth;

use axum::{routing::{get, post}, Router};
use crate::db::db_pool::create_db_pool;
use crate::auth::auth::signup_handler;

async fn hello_world() -> &'static str {
    "Hello, World!"
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL이 설정되지 않았습니다");
    let pool = create_db_pool(&database_url).await;
    println!("DB 연결에 성공하였습니다");

    let app = Router::new()
        .route("/", get(hello_world))
        .route("/signup", post(signup_handler))
        .with_state(pool);

    let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    println!("서버 실행중: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
