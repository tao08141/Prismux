use anyhow::{anyhow, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame_into<R>(reader: &mut R, frame: &mut BytesMut) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 8];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    frame.clear();
    frame.reserve(8 + len);
    frame.extend_from_slice(&header);
    frame.resize(8 + len, 0);
    reader.read_exact(&mut frame[8..]).await?;
    Ok(())
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
