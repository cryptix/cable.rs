// SPDX-FileCopyrightText: 2024 the cabal-club authors
//
// SPDX-License-Identifier: LGPL-3.0-or-later

use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    constants::{
        EPHEMERAL_AND_STATIC_KEY_BYTES_LEN, EPHEMERAL_KEY_BYTES_LEN, STATIC_KEY_BYTES_LEN,
    },
    Handshake, HandshakeComplete, Result,
};

/// Initiate the handshake over an asynchronous stream and run to completion.
pub async fn client<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    psk: [u8; 32],
    private_key: Vec<u8>,
) -> Result<Handshake<HandshakeComplete>> {
    let mut buf = [0; 256];

    let handshake = Handshake::new_client(psk, private_key);

    // Build Noise state machine.
    let handshake = handshake.build_client_noise_state_machine()?;

    // Send ephemeral key.
    let send_buf = &mut buf[..EPHEMERAL_KEY_BYTES_LEN];
    let handshake = handshake.send_client_ephemeral_key(send_buf)?;
    stream.write_all(send_buf).await?;

    // Receive ephemeral and static keys.
    let recv_buf = &mut buf[..EPHEMERAL_AND_STATIC_KEY_BYTES_LEN];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_server_ephemeral_and_static_key(recv_buf)?;

    // Send static key.
    let send_buf = &mut buf[..STATIC_KEY_BYTES_LEN];
    let handshake = handshake.send_client_static_key(send_buf)?;
    stream.write_all(send_buf).await?;

    let handshake = handshake.init_client_transport_mode()?;

    Ok(handshake)
}

/// Respond to a handshake over an asynchronous stream and run to completion.
pub async fn server<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    psk: [u8; 32],
    private_key: Vec<u8>,
) -> Result<Handshake<HandshakeComplete>> {
    let mut buf = [0; 256];

    let handshake = Handshake::new_server(psk, private_key);

    // Build Noise state machine.
    let handshake = handshake.build_server_noise_state_machine()?;

    // Receive ephemeral key.
    let recv_buf = &mut buf[..EPHEMERAL_KEY_BYTES_LEN];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_client_ephemeral_key(recv_buf)?;

    // Send ephemeral and static keys.
    let send_buf = &mut buf[..EPHEMERAL_AND_STATIC_KEY_BYTES_LEN];
    let handshake = handshake.send_server_ephemeral_and_static_key(send_buf)?;
    stream.write_all(send_buf).await?;

    // Receive static key.
    let recv_buf = &mut buf[..STATIC_KEY_BYTES_LEN];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_client_static_key(recv_buf)?;

    let handshake = handshake.init_server_transport_mode()?;

    Ok(handshake)
}
