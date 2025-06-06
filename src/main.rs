use axum::{routing::get, Router};
use std::net::SocketAddr;

async fn hello_world() -> &'static str {
    "Hello, World!"
}

#[tokio::main]
async fn main() {
    // 라우터 생성
    let app = Router::new().route("/", get(hello_world));

    // 바인딩할 주소
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("서버 실행중: http://{}", addr);

    // 서버 실행 (axum::serve 사용)
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
