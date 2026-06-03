package main

import "path/filepath"

// resolveEBCDIC determines whether to decode this job and with which code page /
// carriage-control mode. Order: queue defaults (glob) -> auto-detect + global
// default -> off.
func resolveEBCDIC(j *job, raw []byte) (page, carriage string, on bool) {
	if !cfg.EBCDIC.Enabled {
		return "", "", false
	}
	for pattern, qd := range cfg.LPD.QueueDefaults {
		if ok, _ := filepath.Match(pattern, j.Queue); ok {
			if qd.EBCDIC || qd.CodePage != "" {
				page = orElse(qd.CodePage, cfg.EBCDIC.DefaultCodePage)
				carriage = orElse(qd.CarriageControl, cfg.EBCDIC.CarriageControl)
				return page, resolveCarriage(carriage, j), true
			}
		}
	}
	if cfg.EBCDIC.AutoDetect && looksEBCDIC(raw) {
		return cfg.EBCDIC.DefaultCodePage, resolveCarriage(cfg.EBCDIC.CarriageControl, j), true
	}
	return "", "", false
}

// resolveCarriage lets the LPD control-file hint upgrade "auto"/"" to "asa".
func resolveCarriage(mode string, j *job) string {
	if (mode == "" || mode == "auto") && j.carriageHint != "" {
		return j.carriageHint
	}
	if mode == "" {
		return "auto"
	}
	return mode
}
