use crate::{
    discovery,
    model::{Map, Status},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Write},
    path::Path,
};

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub fn validate(map: &Map) -> Result<()> {
    ensure!(
        map.version == 1,
        "Versione mappa non supportata: {}",
        map.version
    );
    map.settings.validate()?;
    discovery::networks(&map.settings.networks)?;
    ensure!(map.events.len() <= 10_000, "Troppi eventi");
    let mut ids = HashSet::new();
    for device in &map.devices {
        ensure!(
            device.id > 0 && ids.insert(device.id),
            "ID apparato duplicato o nullo"
        );
        ensure!(
            device
                .position
                .iter()
                .all(|p| p.is_finite() && p.abs() <= 1e8),
            "Coordinate non valide"
        );
        ensure!(
            !device.context.trim().is_empty(),
            "Contesto apparato mancante"
        );
        ensure!(
            device
                .ip
                .is_none_or(|ip| ip.octets()[0] > 0 && ip.octets()[0] < 224),
            "IPv4 apparato non unicast"
        );
    }
    ensure!(
        map.next_id > map.devices.iter().map(|d| d.id).max().unwrap_or(0) && map.next_id < u64::MAX,
        "Contatore ID non valido"
    );
    for link in &map.links {
        ensure!(
            link.from != link.to
                && ids.contains(&link.from)
                && ids.contains(&link.to)
                && ids.contains(&link.source),
            "Collegamento con riferimenti non validi"
        );
    }
    Ok(())
}

pub fn save(path: &Path, map: &Map) -> Result<()> {
    validate(map)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("Creazione file temporaneo")?;
    serde_json::to_writer_pretty(&mut temporary, map).context("Serializzazione mappa")?;
    temporary.flush()?;
    ensure!(
        temporary.as_file().metadata()?.len() <= MAX_FILE_BYTES,
        "Mappa oltre il limite di 64 MiB"
    );
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|e| e.error)
        .context("Sostituzione del file mappa")?;
    #[cfg(unix)]
    File::open(parent)?
        .sync_all()
        .context("Sincronizzazione cartella")?;
    Ok(())
}

pub fn load(path: &Path) -> Result<Map> {
    let file = File::open(path).context("Apertura mappa")?;
    ensure!(
        file.metadata()?.len() <= MAX_FILE_BYTES,
        "File oltre il limite di 64 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_FILE_BYTES,
        "File oltre il limite di 64 MiB"
    );
    let mut map: Map = serde_json::from_slice(&bytes).context("JSON mappa non valido")?;
    validate(&map)?;
    for device in &mut map.devices {
        device.status = Status::Unknown;
        device.failures = 0;
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Observation, Status};
    #[test]
    fn roundtrip_retains_metadata_but_not_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("map.json");
        let mut map = Map::default();
        map.merge(Observation {
            ip: Some(std::net::Ipv4Addr::LOCALHOST),
            context: "test".into(),
            group: "t".into(),
            mac: None,
            chassis: None,
            name: "host".into(),
            description: String::new(),
            method: "TCP".into(),
            responding: true,
        });
        map.devices[0].notes = "Nota".into();
        map.devices[0].position = [123.0, 42.0];
        save(&path, &map).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(
            (
                loaded.devices[0].notes.as_str(),
                loaded.devices[0].position,
                loaded.devices[0].status,
                loaded.devices[0].historical_status
            ),
            ("Nota", [123.0, 42.0], Status::Unknown, Status::Up)
        );
        let bytes = std::fs::read_to_string(path).unwrap();
        assert!(
            !bytes.contains("community")
                && !bytes.contains("\"failures\"")
                && !bytes.contains("\"status\"")
        );
    }
    #[test]
    fn failed_validation_does_not_replace_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("map.json");
        save(&path, &Map::default()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let bad = Map {
            version: 99,
            ..Map::default()
        };
        assert!(save(&path, &bad).is_err());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn failed_atomic_replacement_does_not_remove_destination_or_leave_temporary_files() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("existing-directory");
        std::fs::create_dir(&destination).unwrap();
        assert!(save(&destination, &Map::default()).is_err());
        assert!(destination.is_dir());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
