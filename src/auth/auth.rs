use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use bcrypt::{hash, DEFAULT_COST};

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

/**
회원가입 핸들러
- 회원가입 요청을 처리하고 결과를 반환합니다.
- 비밀번호 확인 검증
- 사용자 존재 여부 확인
- 새 사용자 등록
- 성공 메시지 반환
- 실패 시 오류 메시지 반환
@return 회원가입 결과 메시지 또는 오류 메시지
*/
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

    // 비밀번호 해시화
    let hashed_password = hash(signup_req.password.as_bytes(), DEFAULT_COST)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("비밀번호 해시화 실패: {}", e),
            )
        })?;

    // 새 사용자 등록
    sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        signup_req.username,
        hashed_password
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