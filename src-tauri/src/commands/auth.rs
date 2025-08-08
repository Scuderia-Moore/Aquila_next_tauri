use tauri::{command, Emitter, Window};
use tauri::Manager;
use tauri_plugin_oauth::{start_with_config, OauthConfig};
use tauri_plugin_opener::OpenerExt;
use std::sync::atomic::{AtomicBool, Ordering};

use dotenvy;
use std::env;
use once_cell::sync::Lazy;


// ===== Config =====
#[derive(Debug)]
struct EnvConfig {
    client_id: String,
    scopes: String,
    oauth_port: u16,
    redirect_path: String,
    keyring_service: String,
}

static ENVCONF: Lazy<EnvConfig> = Lazy::new(|| {
    // Try to load .env files (both default and src-tauri/.env)
    let _ = dotenvy::from_filename("src-tauri/.env");
    let _ = dotenvy::dotenv();

    let client_id = env::var("DISCORD_CLIENT_ID").unwrap_or_else(|_| "1398967218842108006".into());
    let scopes = env::var("DISCORD_SCOPES").unwrap_or_else(|_| "identify email".into());
    let oauth_port = env::var("OAUTH_PORT").ok().and_then(|s| s.parse::<u16>().ok()).unwrap_or(53682);
    let redirect_path = env::var("REDIRECT_PATH").unwrap_or_else(|_| "/callback".into());
    let keyring_service = env::var("KEYRING_SERVICE").unwrap_or_else(|_| "Aquila".into());

    EnvConfig { client_id, scopes, oauth_port, redirect_path, keyring_service }
});

// ===== 内部で使う定数 =====
const DISCORD_AUTHORIZE_URL: &str = "https://discord.com/api/oauth2/authorize";
const DISCORD_TOKEN_URL: &str = "https://discord.com/api/oauth2/token";

// ===== 依存: rand, sha2, base64(url-safe no pad), url, reqwest, serde =====
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use url::Url;
use serde::Deserialize;
use reqwest::Client;
use std::sync::{Arc, Mutex};

// ===== PKCE & state =====
fn gen_code_verifier() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn code_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn gen_state() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

#[derive(Debug, Clone)]
struct PendingOauth {
    code_verifier: String,
    state: String,
    redirect_uri: String,
}

#[derive(Deserialize, Debug)]
struct TokenResp {
    access_token: String,
    token_type: String, // "Bearer"
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

#[derive(serde::Serialize, Clone, Debug)]
struct DonePayload {
    token_type: String,
    scope: String,
    username: String,
    avatar_url: String,
}

#[derive(Deserialize, Debug)]
struct UserInfo {
    id: String,
    username: String,
    avatar: String,
}

// Anti-duplication guard
static OAUTH_HANDLED: AtomicBool = AtomicBool::new(false);

async fn get_user_info(access_token: &str) -> Result<UserInfo, String> {
    let cli = Client::new();
    let resp = cli
        .get("https://discord.com/api/users/@me")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("failed to get user info: {:?}", resp.text().await.ok()));
    }

    resp.json::<UserInfo>()
        .await
        .map_err(|e| e.to_string())
}

async fn exchange_code_for_token(
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResp, String> {
    let form = [
        ("client_id", client_id),
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];

    let cli = Client::new();
    let resp = cli
        .post(DISCORD_TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("token exchange error: {:?}", resp.text().await.ok()));
    }

    resp.json::<TokenResp>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct StoredTokens {
    access_token: String,
    refresh_token: String,
    token_type: String,
    scope: String,
    expires_in: u64,
    saved_at: i64, // unix epoch seconds
}

fn save_tokens(t: &TokenResp) -> Result<(), String> {
    use keyring::Entry;
    use std::time::{SystemTime, UNIX_EPOCH};

    let saved_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let payload = StoredTokens {
        access_token: t.access_token.clone(),
        refresh_token: t.refresh_token.clone(),
        token_type: t.token_type.clone(),
        scope: t.scope.clone(),
        expires_in: t.expires_in,
        saved_at,
    };

    let json = serde_json::to_string(&payload)
        .map_err(|e| format!("serialize tokens: {}", e))?;

    println!("keyring: saving oauth_tokens (single entry)");
    Entry::new(&ENVCONF.keyring_service, "oauth_tokens")
        .map_err(|e| format!("keyring new ({}): {}", std::env::consts::OS, e))?
        .set_password(&json)
        .map_err(|e| format!("keyring set oauth_tokens ({}): {}", std::env::consts::OS, e))?
        ;
    Ok(())
}

fn load_tokens() -> Result<StoredTokens, String> {
    use keyring::Entry;
    let json = Entry::new(&ENVCONF.keyring_service, "oauth_tokens")
        .map_err(|e| format!("keyring new ({}): {}", std::env::consts::OS, e))?
        .get_password()
        .map_err(|e| format!("keyring get oauth_tokens ({}): {}", std::env::consts::OS, e))?;
    serde_json::from_str::<StoredTokens>(&json)
        .map_err(|e| format!("deserialize tokens: {}", e))
}

// =========== Public Commands ==========

/// Discord OAuth ログインを開始
/// 1) PKCE/state 生成
/// 2) ローカルサーバを固定ポートで起動
/// 3) 認可URLを外部ブラウザで開く
/// 4) リダイレクト受信 → state検証 → トークン交換 → keyring保存 → イベント通知
#[command]
pub async fn start_discord_login(window: Window) -> Result<u16, String> {
    // 1) PKCE と state を生成
    let verifier = gen_code_verifier();
    let challenge = code_challenge_s256(&verifier);
    let state = gen_state();

    // 固定ポートの redirect_uri
    let redirect_uri = format!("http://127.0.0.1:{}{}", ENVCONF.oauth_port, ENVCONF.redirect_path);

    // 共有状態（クロージャ内で使用）
    let pending = Arc::new(Mutex::new(Some(PendingOauth {
        code_verifier: verifier.clone(),
        state: state.clone(),
        redirect_uri: redirect_uri.clone(),
    })));

    // 重複ハンドリング防止フラグをリセット
    OAUTH_HANDLED.store(false, Ordering::SeqCst);

    // 2) サーバ起動（固定ポート）。ブラウザに表示する完了メッセージも設定可能
    let cfg = OauthConfig {
        ports: Some(vec![ENVCONF.oauth_port as u16]),
        response: Some("You can close this window.".into()),
    };

    // 先にサーバを立ち上げ（非同期で待受）。handler 内で URL 検証とトークン交換を行う
    let win_clone = window.clone();
    let pending_clone = pending.clone();
    let port = start_with_config(cfg, move |url: String| {
        // 受け取ったリダイレクトURLを検証＆交換は別タスクで（非ブロック）
        let window = win_clone.clone();
        let pending = pending_clone.clone();
        tauri::async_runtime::spawn(async move {
            // リダイレクト多重呼び出しをガード（最初の1回だけ処理）
            if OAUTH_HANDLED.swap(true, Ordering::SeqCst) {
                let _ = window.emit("oauth:debug", "redirect ignored: already handled");
                return;
            }

            // 取り出し（使い捨て）
            let Some(p) = pending.lock().unwrap().take() else {
                let _ = window.emit("oauth:error", "no pending state");
                return;
            };

            // URLをパース
            let parsed = match Url::parse(&url) {
                Ok(u) => u,
                Err(e) => {
                    let _ = window.emit("oauth:error", format!("invalid url: {}", e));
                    return;
                }
            };

            let _ = window.emit("oauth:debug", format!("redirect url received: {}", parsed));

            // host/path チェック（127.0.0.1 と /callback）
            let host_ok = parsed.host_str() == Some("127.0.0.1");
            let path_ok = parsed.path() == ENVCONF.redirect_path;
            if !host_ok || !path_ok {
                let _ = window.emit("oauth:error", "invalid redirect host/path");
                return;
            }

            let qp = parsed.query_pairs();
            let mut code_opt: Option<String> = None;
            let mut state_opt: Option<String> = None;
            for (k, v) in qp {
                let owned = v.into_owned();
                    if k == "code" {
                    code_opt = Some(owned.clone());
                }
                if k == "state" {
                    state_opt = Some(owned);
                }
            }

            // state検証
            if state_opt.as_deref() != Some(&p.state) {
                let _ = window.emit("oauth:error", "state mismatch");
                return;
            }

            let Some(code) = code_opt else {
                let _ = window.emit("oauth:error", "missing code");
                return;
            };

            // トークン交換
            match exchange_code_for_token(&ENVCONF.client_id, &code, &p.redirect_uri, &p.code_verifier).await {
                Ok(token) => {
                    let _ = window.emit("oauth:debug", "attempting to save tokens to keychain");
                    if let Err(e) = save_tokens(&token) {
                        let _ = window.emit("oauth:error", format!("save token error: {}", e));
                        return;
                    }
                    // Get user info
                    match get_user_info(&token.access_token).await {
                        Ok(user) => {
                            let _ = window.emit("oauth:debug", "user info fetched");
                            let avatar_url = format!("https://cdn.discordapp.com/avatars/{}/{}.png", user.id, user.avatar);
                            let _ = window.emit(
                                "oauth:done",
                                DonePayload {
                                    token_type: token.token_type.clone(),
                                    scope: token.scope.clone(),
                                    username: user.username,
                                    avatar_url,
                                },
                            );
                        }
                        Err(e) => {
                            let _ = window.emit("oauth:error", format!("failed to fetch user info: {}", e));
                            return;
                        }
                    }
                }
                Err(e) => {
                    let _ = window.emit("oauth:error", format!("token exchange failed: {}", e));
                }
            }
        });
    }).map_err(|err| err.to_string())?;

    // 3) 認可URLを作って外部ブラウザで開く
    let auth_url = Url::parse_with_params(
        DISCORD_AUTHORIZE_URL,
        &[
            ("response_type", "code"),
            ("client_id", &ENVCONF.client_id),
            ("redirect_uri", &redirect_uri),
            ("scope", &ENVCONF.scopes),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
        ],
    ).map_err(|e| e.to_string())?.to_string();

    let _ = window.emit("oauth:debug", format!("opening auth url: {}", auth_url));

    // 外部ブラウザで開く（Tauri v2: shell プラグイン）
    let app = window.app_handle();
    if let Err(e) = app.opener().open_url(auth_url, None::<String>) {
        eprintln!("failed to open browser: {}", e);
    }

    Ok(port)
}

/// リフレッシュトークンで更新（必要に応じてフロントからinvoke）
#[command]
pub async fn refresh_discord_token() -> Result<(), String> {
    let stored = load_tokens()?;
    let refresh = stored.refresh_token;

    let form = [
        ("client_id", ENVCONF.client_id.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh.as_str()),
    ];

    let cli = Client::new();
    let resp = cli
        .post(DISCORD_TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("refresh error: {:?}", resp.text().await.ok()));
    }

    let token: TokenResp = resp.json().await.map_err(|e| e.to_string())?;
    save_tokens(&token)
}
