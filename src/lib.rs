#![feature(let_chains)]
#![allow(unused_braces)]
#![allow(non_snake_case)]
// #[allow(unused_imports)]
/*********************************************************
**
** Copyright (C) 2023-2025 Funh2029. All rights reserved.
**
**
** GNU Lesser General Public License Usage
**
** Alternatively, this file may be used for
** non-commercial projects under the terms of the GNU
** Lesser General Public License version 3 as published
** by the Free Software Foundation:
**
**         https://www.gnu.org/licenses/lgpl-3.0.html
**
** The above copyright notice and this permission
** notice shall be included in all copies or substantial
** portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
** ANY KIND, OF MERCHANTABILITY, EXPRESS OR IMPLIED,
** INCLUDING BUT NOT LIMITED TO THE WARRANTIES FITNESS
** FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
** IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
** LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
** WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
** ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
** OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
*********************************************************/
use reqwest::{blocking::{RequestBuilder, Response}};
use std::io::{self, SeekFrom, Read};
use std::str::FromStr;

use lru_cache::LruCache;

///
/// min req size
///
const CHUNK_SIZE: usize = 2048;
const CACHE_COUNT: usize = 16;
const FRAGMENT_MAX:usize = CHUNK_SIZE/10;

pub struct HttpReader {
    // url: String,
    pub len: usize,
    pub etag: String,
    pub pos: u64,
    pub reqbuilder: RequestBuilder,
    pub cache: LruCache<usize, Vec<u8>>,
    pub httpcache_base: usize,
    pub httpcache: Option<Vec<u8>>,
    pub HTTPCACHE_SIZE: u32,
    pub PRECACHE_SIZE: u32,
    pub debug_enabled: bool,
    pub trace_enabled: bool,
    }


fn reqwest_error_to_io_error(error: reqwest::Error) -> std::io::Error {
    if error.is_timeout() {
        std::io::Error::new(std::io::ErrorKind::TimedOut, format!("Request timed out: {}", error))
    } else if error.is_request() {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Request error: {}", error))
    } else if error.is_redirect() {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Redirect error: {}", error))
    } else if error.is_status() {
        std::io::Error::new(std::io::ErrorKind::Other, format!("HTTP status error: {}", error))
    } else if error.is_body() {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Body error: {}", error))
    } else if error.is_decode() {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Decode error: {}", error))
    } else if error.is_connect() {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Connect error: {}", error))
    } else if error.is_builder() {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Builder error: {}", error))
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Unknown error: {}", error))
    }
}

//
// return single interval like [x, y), The interval includes the left side, not the right side
//
fn interval_analysis<T: std::cmp::Ord + Copy>(a: (T, T), b: (T, T)) -> (Option<(T, T)>, Option<(T, T)>, Option<(T, T)>) {
    let (start, end) = (std::cmp::max(a.0, b.0), std::cmp::min(a.1, b.1));
    let intersection = if start < end { Some((start, end)) } else { None };

    let left = if a.0 < start { Some((a.0, std::cmp::min(a.1, start))) } else { None };
    let right = if end < a.1 { Some((std::cmp::max(a.0, end), a.1)) } else { None };

    //
    //  000  x
    //  001  o  read and cache
    //  010  o  read union
    //  011  o  read union + read and cache
    //  100  o  read and cache
    //  101  x
    //  110  o  read left + read union
    //  111  o  read entire
    //
    (left, intersection, right)
    }

macro_rules! trace {
    ($logger:expr, $($arg:tt)*) => {
        if $logger.trace_enabled {
            eprint!($($arg)*);
        }
    };
}

macro_rules! debug {
    ($logger:expr, $($arg:tt)*) => {
        if $logger.debug_enabled {
            eprint!($($arg)*);
        }
    };
}

impl HttpReader {
    pub fn new_with_bufsize(url:&str, prefetch_size:u32) -> io::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(9))
            .build().unwrap();
        Self::new_with_config(url, prefetch_size, &client)
        }

    pub fn new(url:&str) -> io::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(9))
            .build().unwrap();
        Self::new_with_config(url, (1.5*1024.0) as u32 *1024, &client)
        }

    pub fn new_with_config(url:&str, prefetch_size:u32, client: &reqwest::blocking::Client) -> io::Result<Self> {
        let (len, etag) = get_file_size_custom(&client, url)?;
        Ok(Self {
            len,
            etag,
            pos: 0,
            reqbuilder: client.clone().request(reqwest::Method::GET, url),
            cache: LruCache::new(CACHE_COUNT),
            httpcache_base: len,
            httpcache: None,
            HTTPCACHE_SIZE: prefetch_size,
            PRECACHE_SIZE: prefetch_size / 4,
            debug_enabled: false,
            trace_enabled: false
            })
        }

    fn get_file_range(&self, range_start: usize, range_size: usize) -> io::Result<Response> {
        let res = self.reqbuilder.try_clone().unwrap()
            .header("Range", format!("bytes={}-{}", range_start as isize, range_start as isize + range_size as isize - 1))
            .send().map_err(reqwest_error_to_io_error)?;
        debug!(self, "[GET] pos = {}, len = {}\n", range_start, range_size);
        // unsafe{core::arch::asm!("int $3");}
        if ! res.status().is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("Server Error: {} (pos:{} size:{})", res.status(), range_start, range_start + range_size - 1)));
            }
        let etag = res.headers().get("etag")
            .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Response doesn't include the ETag")))
            ?.to_str().map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid ETag header"))?;
        if self.etag != etag {
            Err(io::Error::new(io::ErrorKind::Other, "Server: File Modified - ETag Changed"))
            }
        else{
            Ok(res)
            }
        }

    fn read_range(&mut self, range_start: usize, buf: &mut [u8]) -> io::Result<()> {
        let mut buf_pos = 0;
        let a = (range_start, range_start + buf.len());
        if self.httpcache.is_none() {
            self.httpcache = Some(vec![0u8; self.HTTPCACHE_SIZE as usize]);
            }
        let b = (
            self.httpcache_base,
            self.httpcache_base + self.httpcache.as_ref().unwrap().len(),
            );

        let mut interval = interval_analysis(a, b);
        if interval.0.is_some() && interval.2.is_some() {
            //  111  o  read entire
            trace!(self, "read entire range{:?}\n", a);
            let mut res = self.get_file_range(a.0, a.1 - a.0)?;
            res.read_exact(buf)?;
            return Ok(());
            }

        trace!(self, "----------------------------------------------------------\n");
        trace!(self, "[read_range] pos = {}, len = {}\n", range_start, buf.len());

        //
        // ------------------------------------------------
        //          buf.len = a1 - a0
        //
        // 0     a0                 a1
        //                 b0             b1
        //      left0    left1
        //               union0  union1
        //
        // ------------------------------------------------
        //          buf.len = a1 - a0
        //
        // 0         a0                 a1
        //     b0             b1
        //          union0  union1
        // 		           i00       i01
        // 		                  b0    <- b_size ->   b1
        // ------------------------------------------------
        //
        if interval.1.is_some(){
            //
            //  110  o  read left + read union
            //  010  o  read union
            //  011  o  read union +
            //
            if let Some(left) = interval.0 {
                trace!(self, "read left range{:?}\n", left);
                let size = (left.1 - left.0) as usize;
                debug_assert!(size as isize > 0);
                let mut res = self.get_file_range(left.0, size)?;
                debug_assert!(left.0 == a.0);
                res.read_exact(&mut buf[buf_pos..buf_pos + size])?;
                buf_pos = buf_pos + size;
                }
            if let Some(union) = interval.1 {
                trace!(self, "read union range{:?} [CACHE]\n", union);
                let size = (union.1 - union.0) as usize;
                debug_assert!(size as isize > 0);
                let httpcache_start = union.0 - self.httpcache_base;
                buf[buf_pos..buf_pos + size].copy_from_slice(&self.httpcache.as_ref().unwrap()[httpcache_start..httpcache_start + size]);
                buf_pos = buf_pos + size;
                if interval.2.is_none() {
                    return Ok(());
                    }
                else{
                    interval = (None, None, interval.2);
                    }
                }
            }

        //
        //  001  o  read and cache
        //
        if interval.0.is_none() && interval.1.is_none() && interval.2.is_some(){
            interval = (interval.2, None, None, );
            }

        //
        //  011  o  ... + read and cache
        //  100  o  read and cache
        //
        debug_assert!(interval.1.is_none());
        debug_assert!(interval.2.is_none());
        let i = interval.0.as_ref().unwrap();
        let i_size = (i.1 - i.0) as usize;
        debug_assert!(i.0 as i64 >= 0 && i.1 as i64 >= 0);
        let precache_size: usize = std::cmp::min(self.PRECACHE_SIZE as usize, i_size);
        let end = std::cmp::min(a.1 + (self.HTTPCACHE_SIZE as usize - precache_size), self.len);
        trace!(self, "read and cache range{:?}->{:?}\n", (i.0, i.1), (i.0, end));
        let mut res = self.get_file_range(i.0, end - i.0 as usize)?;
        res.read_exact(&mut buf[buf_pos..buf_pos + i_size])?;
        // println!("{:x?}", buf);
        buf_pos = buf_pos + i_size;
        self.httpcache.as_mut().unwrap()[..precache_size].copy_from_slice(&buf[buf_pos - precache_size..buf_pos]);
        res.read_exact(&mut self.httpcache.as_mut().unwrap()[precache_size..precache_size + end-i.1 as usize])?;
        self.httpcache_base = i.1 as usize - precache_size;
        Ok(())
        }
    }

impl io::Read for HttpReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self.pos as usize;
        let remaining = self.len - pos;
        if remaining == 0 || buf.len() == 0 {
            trace!(self, " ... [OK]\n");
            return Ok(0);
        }

        let len = std::cmp::min(buf.len(), remaining as usize) as usize;
        trace!(self, "read pos = {}, len = {}", self.pos, len);

        if len < CHUNK_SIZE {
            // use cache
            let index = pos / CHUNK_SIZE;
            let offset_start = pos % CHUNK_SIZE;
            if let Some(chunk) = self.cache.get_mut(&index) {
                // hit
                trace!(self, " [hit] idx = {}, offset = {} ", index, offset_start);
                let bytes_to_read = std::cmp::min(len, chunk.len() as usize - offset_start);
                buf[..bytes_to_read].copy_from_slice(&chunk[offset_start..(offset_start + bytes_to_read)]);
                self.pos += bytes_to_read as u64;
                return Ok(bytes_to_read + self.read(&mut buf[bytes_to_read..])?);
                }
            else if len < FRAGMENT_MAX {
                // add new to cache
                let pos_at_chunk_start = (index*CHUNK_SIZE as usize) as usize;
                let bytes_to_read = std::cmp::min(self.len - pos_at_chunk_start, CHUNK_SIZE as usize);
                trace!(self, " [GET] Range({}, {}) to cache idx {}. ", pos_at_chunk_start, pos_at_chunk_start + bytes_to_read, index);

                let mut chunk = vec![0; bytes_to_read];
                self.read_range(pos_at_chunk_start, &mut chunk)?;
                //let mut res = self.get_file_range(pos_at_chunk_start, bytes_to_read)?;
                //res.read_exact(&mut chunk[..]).ok();
                self.cache.insert(index, chunk);
                return self.read(&mut buf[..]);
                }
            else{
                // read directly
                }
            }

        // read directly
        trace!(self, " ... [GET]\n");
        self.read_range(self.pos as usize, &mut buf[..len])?;
        self.pos += len as u64;
        Ok(len as usize)
        }
    }

impl io::Seek for HttpReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(new_pos) => {
                if new_pos <= self.len as u64 {
                    self.pos = new_pos;
                    Ok(new_pos)
                    }
                else{
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of data",
                        ))
                    }
                }
            SeekFrom::End(offset) => {
                if self.pos as i64 + offset <= self.len as i64 {
                    self.pos = (self.len as i64 + offset) as u64;
                    Ok((self.pos) as u64)
                    }
                else{
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of data",
                        ))
                    }
                }
            SeekFrom::Current(offset) => {
                let new_pos = (self.pos as i64 + offset) as usize;
                if new_pos <= self.len {
                    self.pos = new_pos as u64;
                    Ok((self.pos) as u64)
                    }
                else{
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot seek past end of data",
                        ))
                    }
                }
            }
        }
    }

pub fn get_file_size_custom(client: &reqwest::blocking::Client, url: &str) -> Result<(usize, String), std::io::Error>  {
    let res = client
        .request(reqwest::Method::HEAD, url)
        .send().map_err(reqwest_error_to_io_error)?;

    let length = res.headers().get("content-length")
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("response doesn't include the content length")))?
        .to_str().map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid Content-Length header"))?;

    let length = usize::from_str(length).map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid Content-Length header"))?;

    let etag = res.headers().get("etag")
        .ok_or(io::Error::new(io::ErrorKind::NotFound, format!("Server file not found. (ETag not included)")))
        ?.to_str().map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid ETag header"))?;
    Ok((length, String::from(etag)))
    }

pub fn get_file_size(url: &str) -> Result<(usize, String), std::io::Error>  {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(9))
        .build().map_err(reqwest_error_to_io_error)?;
    get_file_size_custom(&client, &url)
    }

pub fn get_file_range_custom(client: &reqwest::blocking::Client, url: &str, range_start: usize, range_end: usize) -> Result<reqwest::blocking::Response, std::io::Error> {
    let res = client
        .request(reqwest::Method::GET, url).header("Range", format!("bytes={}-{}", range_start, range_end))
        .send().map_err(reqwest_error_to_io_error)?;
    let status = res.status();
    if !(status == reqwest::StatusCode::PARTIAL_CONTENT) {
        Err(io::Error::new(io::ErrorKind::NotFound, format!("Unexpected server response: {}", status)))
        }
    else{
        Ok(res)
        }
    }

pub fn get_file_range(url: &str, range_start: usize, range_end: usize) -> Result<reqwest::blocking::Response, std::io::Error> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(9))
        .build().map_err(reqwest_error_to_io_error)?;
    get_file_range_custom(&client, url, range_start, range_end)
    }

pub fn get_file_with_size_custom(client: &reqwest::blocking::Client, url: &str, range_start: usize, range_size: usize) -> Result<reqwest::blocking::Response, std::io::Error> {
    get_file_range_custom(&client, url, range_start, range_start + range_size - 1)
    }

pub fn get_file_with_size(url: &str, range_start: usize, range_size: usize) -> Result<reqwest::blocking::Response, std::io::Error> {
    get_file_range(url, range_start, range_start + range_size - 1)
    }

