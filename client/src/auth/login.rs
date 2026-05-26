use base64::prelude::*;
use chacha20poly1305::aead::OsRng;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
use reqwest::Client;
use shared::{
    DefaultCipherSuite, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse,
};

pub fn login_client_start(
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    match ClientLogin::<DefaultCipherSuite>::start(&mut rng, password) {
        Ok(login) => Ok((
            login.state.serialize().to_vec(),
            login.message.serialize().to_vec(),
        )),
        Err(err) => return Err(err.to_string().into()),
    }
}

pub fn login_client_finish(
    password: &[u8],
    client_start: &[u8],
    server_start: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client_state = ClientLogin::<DefaultCipherSuite>::deserialize(client_start)?;
    let credential_response = CredentialResponse::deserialize(server_start)?;

    let result = client_state.finish(
        &mut OsRng,
        password,
        credential_response,
        ClientLoginFinishParameters::default(),
    )?;

    Ok(result.message.serialize().to_vec())
}

pub async fn authenticate(
    // pool: &SqlitePool,
    email: &str,
    auth_key: &[u8],
    api_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // let state = ClientState::get(pool).await?;
    let client = Client::new();

    // 1. OPAQUE Client Start
    // You will need to wrap the opaque_ke client logic in your shared crate
    let (opaque_client_state, client_start_bytes) = login_client_start(auth_key)?;

    let start_res = client
        .post(format!("{}/api/v1/auth/login/start", api_url))
        .json(&LoginStartRequest {
            email: email.to_string(),
            client_start: BASE64_STANDARD.encode(client_start_bytes),
        })
        .send()
        .await?;

    let start_data: LoginStartResponse = start_res.json().await?;
    let server_start_bytes = BASE64_STANDARD.decode(&start_data.message)?;

    // 2. OPAQUE Client Finish
    let client_finish_bytes =
        login_client_finish(auth_key, &opaque_client_state, &server_start_bytes)?;

    let finish_res = client
        .post(format!("{}/api/v1/auth/login/finish", api_url))
        .json(&LoginFinishRequest {
            email: email.to_string(),
            attempt_id: start_data.attempt_id,
            client_finish: BASE64_STANDARD.encode(client_finish_bytes),
        })
        .send()
        .await?;

    let finish_data: LoginFinishResponse = finish_res.json().await?;

    // Return the JWT
    Ok(finish_data.access_token)
}
