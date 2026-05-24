use argon2::password_hash::SaltString;
use base64::prelude::*;
use bytes::Bytes;
use chacha20poly1305::aead::OsRng;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use shared::{
    DefaultCipherSuite, RegistrationFinishRequest, RegistrationStartRequest,
    RegistrationStartResponse,
};

// use crate::API_BASE;

pub fn register_client_start(
    password: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    match ClientRegistration::<DefaultCipherSuite>::start(&mut OsRng, password) {
        Ok(start) => Ok((
            start.state.serialize().to_vec(),
            start.message.serialize().to_vec(),
        )),
        Err(err) => return Err(err.to_string().into()),
    }
}

pub fn register_client_finish(
    password: &[u8],
    client_state: &[u8],
    server_message: &[u8],
) -> Result<Bytes, Box<dyn std::error::Error>> {
    let client_state = match ClientRegistration::<DefaultCipherSuite>::deserialize(client_state) {
        Ok(s) => s,
        Err(err) => return Err(err.to_string().into()),
    };

    let mut rng = OsRng;

    match client_state.finish(
        &mut rng,
        password,
        RegistrationResponse::deserialize(server_message)?,
        ClientRegistrationFinishParameters::default(),
    ) {
        Ok(finish) => Ok(Bytes::copy_from_slice(&finish.message.serialize()[..])),
        Err(err) => Err(err.to_string().into()),
    }
}

pub async fn register(
    email: &str,
    password: &[u8],
    salt: &SaltString,
    api_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let (state, message) = register_client_start(&password)?;

    let response = client
        .post(format!("{}/api/v1/auth/register/start", api_url))
        .json(&RegistrationStartRequest {
            email: email.to_string(),
            client_start: BASE64_STANDARD.encode(message),
        })
        .send()
        .await?;

    if !response.status().is_success() {
        return Err("Registration start failed".into());
    }

    let response = response.json::<RegistrationStartResponse>().await?;

    let server_message = BASE64_STANDARD.decode(response.server_start)?;
    let message = register_client_finish(&password, &state, &server_message)?;

    let status = client
        .post(format!("{}/api/v1/auth/register/finish", api_url))
        .json(&RegistrationFinishRequest {
            email: email.to_string(),
            salt: salt.to_string(),
            client_finish: BASE64_STANDARD.encode(message),
        })
        .send()
        .await?
        .status();

    if !status.is_success() {
        return Err("Registration finish failed".into());
    }

    Ok(())
}
