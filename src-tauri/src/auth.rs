use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // username
    pub role: String, // super | admin | support | viewer
    pub iat: usize,
    pub exp: usize,
}

fn jwt_secret() -> String {
    if let Ok(s) = std::env::var("AGY_JWT_SECRET") {
        if !s.trim().is_empty() {
            return s;
        }
    }
    let cfg = crate::common::read_config();
    if !cfg.api_token.trim().is_empty() {
        return format!("ibp-jwt-{}", cfg.api_token.trim());
    }
    "it-elkhawga-default-jwt-secret-key".to_string()
}

pub fn make_jwt(username: &str, role: &str) -> Result<String, String> {
    let now = Utc::now();
    let claims = Claims {
        sub: username.trim().to_owned(),
        role: crate::common::normalize_admin_role(role),
        iat: now.timestamp().max(0) as usize,
        exp: (now + Duration::hours(12)).timestamp().max(0) as usize,
    };
    let secret = jwt_secret();
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

pub fn verify_jwt(token: &str) -> Result<Claims, String> {
    let secret = jwt_secret();
    decode::<Claims>(
        token.trim(),
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| "انتهت الجلسة أو التوكين غير صالح، يرجى تسجيل الدخول مجدداً".to_string())
}
