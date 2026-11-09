#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacDetails {
    pub prefix: String,
    pub address_type: &'static str,
    pub manufacturer: Option<&'static str>,
}

pub fn describe(mac: &str) -> Option<MacDetails> {
    let bytes = parse(mac)?;
    let prefix = format!("{:02X}:{:02X}:{:02X}", bytes[0], bytes[1], bytes[2]);
    let multicast = bytes[0] & 1 != 0;
    let locally_administered = bytes[0] & 2 != 0;
    let address_type = if multicast {
        if bytes.iter().all(|byte| *byte == 0xff) {
            "Broadcast"
        } else {
            "Multicast"
        }
    } else if locally_administered {
        "Unicast locale (probabile MAC randomizzato)"
    } else {
        "Unicast universale"
    };
    let manufacturer = (!multicast && !locally_administered)
        .then(|| manufacturer(&prefix))
        .flatten();

    Some(MacDetails {
        prefix,
        address_type,
        manufacturer,
    })
}

fn parse(mac: &str) -> Option<[u8; 6]> {
    let bytes = mac.as_bytes();
    let valid_format = match bytes.len() {
        12 => bytes.iter().all(u8::is_ascii_hexdigit),
        17 => {
            let separator = bytes[2];
            matches!(separator, b':' | b'-')
                && (2..17).step_by(3).all(|index| bytes[index] == separator)
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| index % 3 == 2 || byte.is_ascii_hexdigit())
        }
        14 => {
            bytes[4] == b'.'
                && bytes[9] == b'.'
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| matches!(index, 4 | 9) || byte.is_ascii_hexdigit())
        }
        _ => false,
    };
    if !valid_format {
        return None;
    }
    let compact: String = mac
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | '.'))
        .collect();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    let mut bytes = [0; 6];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

fn manufacturer(prefix: &str) -> Option<&'static str> {
    const VENDORS: &[(&str, &[&str])] = &[
        (
            "Apple",
            &[
                "000393", "000A95", "000D93", "001124", "001451", "0016CB", "0017F2", "0019E3",
                "001B63", "001CB3", "001DC2", "001EC2", "001F5B", "0021E9", "002241", "002312",
                "002332", "002436", "002500", "002608", "286ABA", "3C0754", "3C22FB", "40A6D9",
                "5855CA", "600308", "78CA39", "80E650", "843835", "88665A", "8C8590", "9801A7",
                "A483E7", "ACBC32", "B8E856", "C82A14", "D0034B", "DC2B2A", "E0B52D", "F01898",
                "F45C89",
            ],
        ),
        ("Cisco", &["00000C", "001A2B", "001B0C", "0021A0", "0023EB"]),
        (
            "Samsung",
            &["000CE7", "001247", "001632", "0017C9", "001D25", "002454"],
        ),
        ("Intel", &["001B21", "001E64", "3C970E", "5C879C", "8086F2"]),
        ("Dell", &["001422", "001AA0", "14FEAF", "B083FE"]),
        ("HP / HPE", &["001A4B", "00215A", "3C4A92", "FC15B4"]),
        (
            "Huawei",
            &["001882", "002568", "048AD2", "CC96A0", "E0247F"],
        ),
        (
            "TP-Link",
            &["14CC20", "50C7BF", "60E327", "C46E1F", "F4EC38"],
        ),
        (
            "Ubiquiti",
            &["0418D6", "24A43C", "687251", "802AA8", "F09FC2"],
        ),
        ("ASUS", &["041E64", "08606E", "2C4D54", "F832E4"]),
        ("Google", &["3C5AB4", "546009", "F4F5D8"]),
        ("Amazon", &["0C47C9", "189B5B", "40B4CD", "A002DC"]),
        ("Raspberry Pi", &["B827EB", "DCA632", "E45F01"]),
        ("Lenovo", &["001E4F", "28D244", "54E1AD", "98FA9B"]),
        ("Xiaomi", &["0C1DAF", "286C07", "64B473", "F8A45F"]),
    ];
    let compact = prefix.replace(':', "");
    VENDORS
        .iter()
        .find(|(_, prefixes)| prefixes.contains(&compact.as_str()))
        .map(|(vendor, _)| *vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_vendor_and_address_type_from_common_mac_formats() {
        for mac in ["00:1A:2B:03:04:05", "00-1a-2b-03-04-05", "001a.2b03.0405"] {
            let details = describe(mac).unwrap();
            assert_eq!(details.prefix, "00:1A:2B");
            assert_eq!(details.address_type, "Unicast universale");
            assert_eq!(details.manufacturer, Some("Cisco"));
        }
    }

    #[test]
    fn recognizes_randomized_and_multicast_addresses_without_guessing_a_vendor() {
        let randomized = describe("02:1A:2B:03:04:05").unwrap();
        assert_eq!(
            randomized.address_type,
            "Unicast locale (probabile MAC randomizzato)"
        );
        assert_eq!(randomized.manufacturer, None);

        let multicast = describe("01:00:5E:00:00:01").unwrap();
        assert_eq!(multicast.address_type, "Multicast");
        assert_eq!(multicast.manufacturer, None);
        assert_eq!(
            describe("FF:FF:FF:FF:FF:FF").unwrap().address_type,
            "Broadcast"
        );
    }

    #[test]
    fn rejects_invalid_mac_addresses() {
        for mac in ["not-a-mac", "00:11:22", "00:11:22:33:44:GG", ""] {
            assert_eq!(describe(mac), None);
        }
    }
}
