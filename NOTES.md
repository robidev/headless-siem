change: siemctl make --full the default, so siemctl searches by default return the raw record, and returning just the index is a switch by adding --index-record
discussion: consider merging sources.toml and normalized.toml
feature: ensure retention for 0 days works to remove everything(raw logs and indexes)
bug: properly check whats going on with indexed, and why it does not exit
feature: siemctl allows to stop after a certain amount of hits with --limit
feature: normalized: allows a timerange to be provided for normalisaztion(cmdline flag) so that only logs within a timerange are normalised
feature: siemctl: allow grouping output on multiple fields. for example --group src_ip will display a unique src_ip per line, and a count per line (only possible on indexed fields). but also multiple fields by --group src_ip,dst_ip, so that unique source+destination ip combinations are possible to search 
feature: siemctl: --render flag, to decide what fields to show as output, and what format (json, tabs with headers on/off...), default is everything in json
