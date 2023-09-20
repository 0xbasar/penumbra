use crate::error::WasmResult;
use penumbra_proto::DomainType;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// decode SCT root
/// Arguments:
///     tx_bytes: `HEX string`
/// Returns: `penumbra_tct::Root`
#[wasm_bindgen]
pub fn decode_nct_root(tx_bytes: &str) -> WasmResult<JsValue> {
    let tx_vec: Vec<u8> = hex::decode(tx_bytes)?;
    let root = penumbra_tct::Root::decode(tx_vec.as_slice())?;
    let result = serde_wasm_bindgen::to_value(&root)?;
    Ok(result)
}
