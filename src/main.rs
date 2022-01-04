use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use hmac::{Hmac, Mac, NewMac};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use ta::indicators::{BollingerBands, BollingerBandsOutput};
use ta::{errors, DataItem, Next};
use tokio::time::sleep;

#[derive(Debug, Deserialize)]
pub struct MarketData<T> {
    pub error: Vec<String>,
    pub result: Option<T>,
}

#[derive(Debug, Default, Deserialize)]
pub struct OHLCResult {
    #[serde(flatten)]
    pub data: HashMap<String, Vec<OHLC>>,
    pub last: u32,
}

// #[derive(Debug, Deserialize)]
// pub struct TradeBalanceResult {
//     pub eb: String,
//     pub tb: String,
//     pub m: String,
//     pub n: String,
//     pub c: String,
//     pub v: String,
//     pub e: String,
//     pub mf: String,
// }

#[derive(Debug, Default, Deserialize)]
#[serde(
    expecting = "expecting [<timestamp>, <open>, <high>, <low>, <close>, <vwap>, <volume>, <trades>] array"
)]
pub struct OHLC {
    pub timestamp: u32,
    pub open: String,
    pub high: String,
    pub low: String,
    pub close: String,
    pub vwap: String,
    pub volume: String,
    pub trades: u32,
}

#[derive(Debug, Default, Deserialize)]
pub struct OpenOrderResult {
    pub open: HashMap<String, OpenOrder>,
}

#[derive(Debug, Default, Deserialize)]
pub struct OpenOrder {
    pub descr: OpenOrderDescription,
    pub vol: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct OpenOrderDescription {
    pub pair: String,
    pub r#type: String,
    pub price: String,
    pub order: String,
}

static PAIR: &str = "DOTUSDT";
static ASSET: &str = "DOT";
static CURRENCY: &str = "USDT";
static MIN_TRADE_VOLUME: f64 = 0.5;

#[tokio::main]
async fn main() {
    let client = reqwest::Client::new();
    let mut current_bb: Option<BollingerBandsOutput> = None;
    let mut previous_bb: Option<BollingerBandsOutput> = None;
    let mut buy = false;
    let mut sell = false;
    let mut timestamp: u32 = Utc::now()
        .checked_sub_signed(Duration::hours(6))
        .unwrap()
        .timestamp() as u32;

    let mut bb = BollingerBands::new(72, 2.0_f64).unwrap();

    loop {
        let ohlc_result = client
            .get("https://api.kraken.com/0/public/OHLC")
            .query(&[
                ("pair", PAIR),
                ("interval", "5"),
                ("since", &timestamp.to_string()),
            ])
            .send()
            .await;

        let key = "m4iOCVVWoi31Ij+VaBqbLhYNZYEuEXDhLXVRxIwh6nnrJShF8xGFxhW3";
        let secret = "Bxhw2cX6OkIGaYq2qbujMD/czzmJ6Ve8OCRDU54CLwGOfJm3AxK+eeGqsqio7zKX9vf8fHN+/+EMWH22KaXp0A==";
        let nonce = Utc::now().timestamp_millis();
        let balance_body = format!("nonce={}", nonce);
        let open_orders_body = format!("nonce={}", nonce + 1);

        let balance_result = client
            .post("https://api.kraken.com/0/private/Balance")
            .body(balance_body.clone())
            .header("API-Key", key)
            .header(
                "API-Sign",
                get_kraken_signature(
                    "/0/private/Balance",
                    &balance_body,
                    secret,
                    &nonce.to_string(),
                ),
            )
            .send()
            .await;

        let open_orders_result = client
            .post("https://api.kraken.com/0/private/OpenOrders")
            .body(open_orders_body.clone())
            .header("API-Key", key)
            .header(
                "API-Sign",
                get_kraken_signature(
                    "/0/private/OpenOrders",
                    &open_orders_body,
                    secret,
                    &(nonce + 1).to_string(),
                ),
            )
            .send()
            .await;

        match [ohlc_result, balance_result, open_orders_result] {
            [Ok(ohlc_response), Ok(balance_response), Ok(open_orders_response)] => {
                let ohlc: MarketData<OHLCResult> = ohlc_response.json().await.unwrap();
                let balance: MarketData<HashMap<String, String>> =
                    balance_response.json().await.unwrap();
                let open_orders: MarketData<OpenOrderResult> =
                    open_orders_response.json().await.unwrap();

                let errors = [ohlc.error, balance.error, open_orders.error].concat();
                if !errors.is_empty() {
                    eprintln!("{:#?}", errors);
                }
                if let (Some(candles), Some(balance), Some(open_orders)) = (
                    ohlc.result.as_ref().and_then(|r| r.data.get(PAIR)),
                    balance.result,
                    open_orders.result,
                ) {
                    for (i, candle) in candles.iter().enumerate() {
                        let item = DataItem::builder()
                            .open(candle.open.parse().unwrap())
                            .high(candle.high.parse().unwrap())
                            .low(candle.low.parse().unwrap())
                            .close(candle.close.parse().unwrap())
                            .volume(candle.volume.parse().unwrap())
                            .build()
                            .unwrap();

                        let output = bb.next(&item);
                        if i == candles.len() - 1 {
                            timestamp = candle.timestamp;
                            previous_bb = current_bb.or(previous_bb);
                            current_bb = Some(output);
                        } else if i == candles.len() - 2 {
                            previous_bb = Some(output);
                        }
                    }

                    let open_buy_cost: f64 = open_orders
                        .open
                        .values()
                        .filter(|o| o.descr.pair == PAIR && o.descr.r#type == "buy")
                        .map(|o| {
                            o.vol.parse::<f64>().unwrap() * o.descr.price.parse::<f64>().unwrap()
                        })
                        .sum();

                    let open_sell_total: f64 = open_orders
                        .open
                        .values()
                        .filter(|o| o.descr.pair == PAIR && o.descr.r#type == "sell")
                        .map(|o| o.vol.parse::<f64>().unwrap())
                        .sum();

                    let asset_balance: f64 = balance
                        .get(ASSET)
                        .unwrap_or(&"0.0".to_string())
                        .parse::<f64>()
                        .unwrap()
                        - open_sell_total;

                    let currency_balance: f64 = balance
                        .get(CURRENCY)
                        .unwrap_or(&"0.0".to_string())
                        .parse::<f64>()
                        .unwrap()
                        - open_buy_cost;

                    let current_price: f64 = candles.last().unwrap().close.parse().unwrap();
                    let amount_to_purchase = currency_balance / current_price;

                    // TODO: Create buy/sell orders using API key if criteria is met
                    if current_price <= current_bb.as_ref().unwrap().lower
                        && amount_to_purchase >= MIN_TRADE_VOLUME
                    {
                        buy = true;
                    } else if current_price >= current_bb.as_ref().unwrap().upper
                        && asset_balance >= MIN_TRADE_VOLUME
                    {
                        sell = true;
                    }

                    if current_bb.as_ref().unwrap().lower - previous_bb.as_ref().unwrap().lower
                        >= 0.0
                        && buy
                    {
                        let order_body = format!(
                            "nonce={}&type=buy&ordertype=limit&pair={}&price={}&volume={}",
                            nonce + 2,
                            PAIR,
                            current_price,
                            amount_to_purchase
                        );

                        client
                            .post("https://api.kraken.com/0/private/AddOrder")
                            .body(order_body.clone())
                            .header("API-Key", key)
                            .header(
                                "API-Sign",
                                get_kraken_signature(
                                    "/0/private/AddOrder",
                                    &order_body,
                                    secret,
                                    &(nonce + 2).to_string(),
                                ),
                            )
                            .send()
                            .await
                            .unwrap();

                        buy = false;
                        println!("BUY AT {}", current_price);
                    } else if current_bb.as_ref().unwrap().upper
                        - previous_bb.as_ref().unwrap().upper
                        <= 0.0
                        && sell
                    {
                        let order_body = format!(
                            "nonce={}&type=sell&ordertype=limit&pair={}&price={}&volume={}",
                            nonce + 2,
                            PAIR,
                            current_price,
                            asset_balance
                        );

                        client
                            .post("https://api.kraken.com/0/private/AddOrder")
                            .body(order_body.clone())
                            .header("API-Key", key)
                            .header(
                                "API-Sign",
                                get_kraken_signature(
                                    "/0/private/AddOrder",
                                    &order_body,
                                    secret,
                                    &(nonce + 2).to_string(),
                                ),
                            )
                            .send()
                            .await
                            .unwrap();

                        sell = false;
                        println!("SELL AT {}", current_price);
                    }

                    println!("[{}]: {}", timestamp, current_price);
                    println!(
                        "{} {}, {} {}",
                        asset_balance, ASSET, currency_balance, CURRENCY,
                    );
                    println!("Selling: {}, Buying: {}", sell, buy);
                    println!("Open Orders: {:#?}", open_orders.open);
                    // println!(
                    //     "{:#?}, {:#?}",
                    //     current_bb.as_ref().unwrap(),
                    //     previous_bb.as_ref().unwrap()
                    // );
                    println!();
                } else {
                    eprintln!("API requests missing requested data");
                }
            }
            errors => {
                for error in errors {
                    if let Err(e) = error {
                        eprintln!("{:?}", e);
                    }
                }
            }
        }

        sleep(std::time::Duration::from_secs(5 * 60)).await;
    }
}

// HMAC-SHA512 of (URI path + SHA256(nonce + POST data)) and base64 decoded secret API key
fn get_kraken_signature(endpoint: &str, data: &str, secret: &str, nonce: &str) -> String {
    let sha2_result = {
        let mut hasher = Sha256::default();
        hasher.update(nonce);
        hasher.update(data);
        hasher.finalize()
    };

    let hmac_sha_key = base64::decode(secret).unwrap();

    type HmacSha = Hmac<Sha512>;
    let mut mac = HmacSha::new_varkey(&hmac_sha_key).unwrap();
    mac.update(endpoint.as_bytes());
    mac.update(&sha2_result);
    let mac = mac.finalize().into_bytes();

    base64::encode(&mac)
}
