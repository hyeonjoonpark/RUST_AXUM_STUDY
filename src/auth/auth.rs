use serde::{Deserialize, Serialize};
use sqlx::MySqlPool;
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::env;

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

// JWT Claims 구조체
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// 로그인 요청 구조체
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

// 로그인 응답 구조체
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    token: String,
}

const JWT_EXPIRATION_HOURS: usize = 24;

fn get_jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| "mysecretkey".to_string())
}

fn create_jwt(username: &str) -> Result<String, jsonwebtoken::errors::Error> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let exp = now + JWT_EXPIRATION_HOURS * 3600;
    let claims = Claims {
        sub: username.to_string(),
        exp,
    };
    let secret = get_jwt_secret();
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

/// 로그인 요청을 처리하는 핸들러 함수입니다.
///
/// # Arguments
/// * `pool` - MySQL 데이터베이스 연결 풀
/// * `login_req` - 로그인 요청 데이터
///
/// # Returns
/// * `Ok(Json<LoginResponse>)` - 로그인 성공 시 JWT 토큰 반환
/// * `Err((StatusCode, String))` - 실패 시 에러 코드와 에러 메시지
pub async fn login_handler(
    State(pool): State<MySqlPool>,
    Json(login_req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    // 사용자 조회
    let user = sqlx::query!(
        "SELECT username, password FROM users WHERE username = ?",
        login_req.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "데이터베이스 오류".to_string()))?;

    let user = match user {
        Some(u) => u,
        None => {
            return Err((StatusCode::UNAUTHORIZED, "아이디 또는 비밀번호가 올바르지 않습니다.".to_string()));
        }
    };

    // 비밀번호 검증
    let valid = verify(&login_req.password, &user.password)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "비밀번호 검증 오류".to_string()))?;
    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "아이디 또는 비밀번호가 올바르지 않습니다.".to_string()));
    }

    // JWT 생성
    let token = create_jwt(&user.username)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "JWT 생성 오류".to_string()))?;

    Ok(Json(LoginResponse { token }))
}

/// 회원가입 요청을 처리하는 핸들러 함수입니다.
///
/// # 기능
/// - 회원가입 요청을 처리하고 결과를 반환합니다.
/// - 비밀번호 확인 검증을 수행합니다.
/// - 사용자 존재 여부를 확인합니다.
/// - 비밀번호를 bcrypt로 해시화합니다.
/// - 새 사용자를 데이터베이스에 등록합니다.
///
/// # Arguments
/// * `pool` - MySQL 데이터베이스 연결 풀
/// * `signup_req` - 회원가입 요청 데이터
///
/// # Returns
/// * `Ok(Json<SignupResponse>)` - 회원가입 성공 시 성공 메시지
/// * `Err((StatusCode, String))` - 실패 시 에러 코드와 에러 메시지
///
/// # Errors
/// - 비밀번호가 일치하지 않는 경우
/// - 이미 존재하는 사용자인 경우
/// - 데이터베이스 오류가 발생한 경우
/// - 비밀번호 해시화 실패한 경우
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