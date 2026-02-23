use crate::config::{ProtocolDefinition, SignatureRule};
use std::collections::HashMap;

#[derive(Clone)]
pub struct ProtocolDetector {
    protocols: HashMap<String, ProcessedProtocol>,
}

#[derive(Clone)]
struct ProcessedProtocol {
    match_all: bool,
    signatures: Vec<ProcessedSignature>,
}

#[derive(Clone)]
struct ProcessedSignature {
    rule: SignatureRule,
    bytes: Vec<u8>,
    mask: Vec<u8>,
    contains: Vec<u8>,
}

impl ProtocolDetector {
    pub fn new(defs: HashMap<String, ProtocolDefinition>) -> Self {
        let mut protocols = HashMap::with_capacity(defs.len());
        for (name, def) in defs {
            let mut signatures = Vec::with_capacity(def.signatures.len());
            for sig in def.signatures {
                let bytes = decode_field(&sig.bytes, sig.hex);
                let mask = decode_field(&sig.mask, sig.hex);
                let contains = decode_field(&sig.contains, sig.hex);
                signatures.push(ProcessedSignature {
                    rule: sig,
                    bytes,
                    mask,
                    contains,
                });
            }
            protocols.insert(
                name,
                ProcessedProtocol {
                    match_all: def.match_logic.eq_ignore_ascii_case("and"),
                    signatures,
                },
            );
        }
        Self { protocols }
    }

    pub fn detect(&self, data: &[u8], use_detectors: &[String]) -> Option<String> {
        for name in use_detectors {
            let Some(proto) = self.protocols.get(name) else {
                continue;
            };
            if self.matches_proto(data, proto) {
                return Some(name.clone());
            }
        }
        None
    }

    fn matches_proto(&self, data: &[u8], proto: &ProcessedProtocol) -> bool {
        if proto.signatures.is_empty() {
            return false;
        }

        if proto.match_all {
            proto.signatures.iter().all(|sig| self.matches_signature(data, sig))
        } else {
            proto.signatures.iter().any(|sig| self.matches_signature(data, sig))
        }
    }

    fn matches_signature(&self, data: &[u8], sig: &ProcessedSignature) -> bool {
        if let Some(length) = &sig.rule.length {
            if length.min > 0 && data.len() < length.min {
                return false;
            }
            if length.max > 0 && data.len() > length.max {
                return false;
            }
        }

        if !sig.bytes.is_empty() {
            if sig.rule.offset + sig.bytes.len() > data.len() {
                return false;
            }
            if !sig.mask.is_empty() {
                for (i, b) in sig.bytes.iter().enumerate() {
                    let m = *sig.mask.get(i).unwrap_or(&0xff);
                    if (data[sig.rule.offset + i] & m) != (*b & m) {
                        return false;
                    }
                }
            } else if &data[sig.rule.offset..sig.rule.offset + sig.bytes.len()] != sig.bytes.as_slice() {
                return false;
            }
        }

        if !sig.contains.is_empty() && !find_subslice(data, &sig.contains) {
            return false;
        }

        true
    }
}

fn decode_field(field: &str, is_hex: bool) -> Vec<u8> {
    if field.is_empty() {
        return Vec::new();
    }
    if !is_hex {
        return field.as_bytes().to_vec();
    }
    hex::decode(field).unwrap_or_default()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
