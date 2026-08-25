use super::*;

pub(super) fn load_source_graph(graph: ConfigSourceGraph) -> Result<LoadedConfig> {
    let (mut config, source_files, source_contents, processed) =
        decode::decode_source_graph(graph)?;
    validate_core::validate(&mut config)?;
    validate_runtime::validate(&mut config)?;
    validate_me::validate(&mut config)?;
    validate_server::validate(&mut config)?;
    validate_web::validate(&mut config)?;
    effective::apply(&mut config)?;
    Ok(LoadedConfig {
        config,
        source_files: source_files.into_iter().collect(),
        source_contents,
        rendered_hash: hash_rendered_snapshot(&processed),
    })
}
