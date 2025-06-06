use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Pool, MySql};

pub async fn create_db_pool(database_url: &str) -> Pool<MySql> {
    MySqlPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .expect("DB 연결에 실패하였습니다")
}