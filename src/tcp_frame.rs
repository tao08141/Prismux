use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame<R>(reader: &mut R) -> Result<Bytes>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;

    let mut frame = BytesMut::with_capacity(8 + len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    Ok(frame.freeze())
}

pub async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if frame.len() < 8 {
        return Err(anyhow!("frame too short"));
    }
    writer.write_all(frame).await?;
    Ok(())
}
