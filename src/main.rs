mod db;
mod auth;
mod routes;

use crate::db::db_pool::create_db_pool;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL이 설정되지 않았습니다");
    let pool = create_db_pool(&database_url).await;
    println!("DB 연결에 성공하였습니다");

    let app = routes::create_router(pool);

    // SERVER_ADDR 환경변수에서 서버 주소를 읽어옵니다. 예: "127.0.0.1:8080"
    let addr_str = std::env::var("SERVER_ADDR").expect("서버주소가 설정되지 않았습니다");
    let addr: std::net::SocketAddr = addr_str.parse().expect("서버주소 형식이 올바르지 않습니다");
    println!("서버 실행중: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
