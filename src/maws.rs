use serde::Serialize;

/*
 DEBUG maws2iotcore > LOG         19.0     9.8   55       984.4  1001.7   125      0.0    331      0.5
 DEBUG maws2iotcore > PTU         19.0    10.3    20.2     9.8     8.8    13.0   55      50      99      984.4   983.8   986.7  1001.7  1001.1  1004.4       125       0     871      0.0     0.0     0.2
 DEBUG maws2iotcore > WIND         0.3    300
*/

#[derive(Debug, Serialize)]
pub struct MAWSWindMessage {
    ws_cur: f64, // WScur m/s 
    wd_cur: f64 // WDcur °C
}

#[derive(Debug, Serialize)]
pub struct MAWSLogMessage {
    ta60s_avg: f64, // TA60sAvg °C
    dp60s_avg: f64, // DP60sAvg °C
    rh60s_avg: f64, // RH60sAvg %
    pa60s_avg: f64, // PA60sAvg hPa
    qff60s_avg: f64, // QFF60sAvg hPa
    sr60s_avg: f64, // SR60sAvg W/m2
    pr60s_sum: f64, // PR60sSum mm
    wd2min_avg: f64, // WD2minAvg °C
    ws2min_avg: f64 // WS2minAvg m/s
}

#[derive(Debug, Serialize)]
pub struct MAWSPtuMessage {
    ta60s_avg: f64, // TA60sAvg °C
    ta24h_min: f64, // TA24hMin °C
    ta24h_max: f64, // TA24hMax °C
    dp60s_avg: f64, // DP60sAvg °C
    dp24h_min: f64, // DP24hMin °C
    dp24h_max: f64, // DP24hMax °C
    rh60s_avg: f64, // RH60sAvg %
    rh24h_min: f64, // RH24hMin %
    rh24h_max: f64, // RH24hMax %
    pa60s_avg: f64, // PA60sAvg hPa
    pa24h_min: f64, // PA24hMin hPa
    pa24h_max: f64, // PA24hMax hPa
    qff60s_avg: f64, // QFF60sAvg hPa
    qff24h_min: f64, // QFF24hMin hPa
    qff24h_max: f64, // QFF24hMax hPa
    sr60s_avg: f64, // SR60sAvg W/m2
    sr24h_min: f64, // SR24hMin W/m2
    sr24h_max: f64, // SR24hMax W/m2
    pr60s_avg: f64, // PR60sAvg mm
    pr24h_min: f64, // PR24hMin mm
    pr24h_max: f64 // PR24hMax mm
}

#[derive(Debug, Serialize)]
pub enum MAWSMessageKind {
    WIND(MAWSWindMessage),
    LOG(MAWSLogMessage),
    PTU(MAWSPtuMessage),
    UNKNOWN
}

impl MAWSMessageKind {
    pub fn parse(utf_string: String) -> MAWSMessageKind {
        let string_splitted = utf_string.split("\t").into_iter().map(|x| x.trim()).collect::<Vec<&str>>();
        //debug!("Splitted line: {:?}", string_splitted);

        let message: MAWSMessageKind;
        if utf_string.starts_with("WIND") {
            message = MAWSMessageKind::WIND(MAWSWindMessage{
                ws_cur: string_splitted[1].parse().unwrap(),
                wd_cur: string_splitted[2].parse().unwrap()
            });
        } else if utf_string.starts_with("LOG") {
            message = MAWSMessageKind::LOG(MAWSLogMessage{
                ta60s_avg: string_splitted[1].parse().unwrap(),
                dp60s_avg: string_splitted[2].parse().unwrap(),
                rh60s_avg: string_splitted[3].parse().unwrap(),
                pa60s_avg: string_splitted[4].parse().unwrap(),
                qff60s_avg: string_splitted[5].parse().unwrap(),
                sr60s_avg: string_splitted[6].parse().unwrap(),
                pr60s_sum: string_splitted[7].parse().unwrap(),
                wd2min_avg: string_splitted[8].parse().unwrap(),
                ws2min_avg: string_splitted[9].parse().unwrap(),
            })
        } else if utf_string.starts_with("PTU") {
            message = MAWSMessageKind::PTU(MAWSPtuMessage {
                ta60s_avg: string_splitted[1].parse().unwrap(),
                ta24h_min: string_splitted[2].parse().unwrap(),
                ta24h_max: string_splitted[3].parse().unwrap(),
                dp60s_avg: string_splitted[4].parse().unwrap(),
                dp24h_min: string_splitted[5].parse().unwrap(),
                dp24h_max: string_splitted[6].parse().unwrap(),
                rh60s_avg: string_splitted[7].parse().unwrap(),
                rh24h_min: string_splitted[8].parse().unwrap(),
                rh24h_max: string_splitted[9].parse().unwrap(),
                pa60s_avg: string_splitted[10].parse().unwrap(),
                pa24h_min: string_splitted[11].parse().unwrap(),
                pa24h_max: string_splitted[12].parse().unwrap(),
                qff60s_avg: string_splitted[13].parse().unwrap(),
                qff24h_min: string_splitted[14].parse().unwrap(),
                qff24h_max: string_splitted[15].parse().unwrap(),
                sr60s_avg: string_splitted[16].parse().unwrap(),
                sr24h_min: string_splitted[17].parse().unwrap(),
                sr24h_max: string_splitted[18].parse().unwrap(),
                pr60s_avg: string_splitted[19].parse().unwrap(),
                pr24h_min: string_splitted[20].parse().unwrap(),
                pr24h_max: string_splitted[21].parse().unwrap()    
            })
        } else {
            message = MAWSMessageKind::UNKNOWN;
        }

        message
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

// eof