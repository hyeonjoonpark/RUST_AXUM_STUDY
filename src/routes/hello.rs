use axum::routing::get;
use axum::Router;

// "Hello, World!"를 반환하는 기본 핸들러입니다.
async fn hello_world() -> &'static str {
    "Hello, World!"
}

// / 경로에 대한 라우터를 생성합니다.
pub fn create_hello_router() -> Router {
    Router::new().route("/", get(hello_world))
} 