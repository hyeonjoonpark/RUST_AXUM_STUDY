use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupRequest {
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Debug, Serialize)]
pub struct SignupResponse {
    message: String,
}

pub async fn signup_handler(
    State(pool): State<MySqlPool>,
    Json(signup_req): Json<SignupRequest>,
) -> Result<Json<SignupResponse>, (StatusCode, String)> {
    // 비밀번호 확인 검증
    if signup_req.password != signup_req.password_confirm {
        return Err((
            StatusCode::BAD_REQUEST,
            "비밀번호가 일치하지 않습니다.".to_string(),
        ));
    }

    // 사용자 존재 여부 확인
    let existing_user = sqlx::query!(
        "SELECT username FROM users WHERE username = ?",
        signup_req.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("데이터베이스 오류: {}", e),
        )
    })?;

    if existing_user.is_some() {
        return Err((
            StatusCode::CONFLICT,
            "이미 존재하는 사용자입니다.".to_string(),
        ));
    }

    // 새 사용자 등록
    sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        signup_req.username,
        signup_req.password // 실제 구현시에는 반드시 비밀번호를 해시화해야 합니다!
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("사용자 등록 실패: {}", e),
        )
    })?;

    Ok(Json(SignupResponse {
        message: "회원가입이 완료되었습니다.".to_string(),
    }))
} 